#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import concurrent.futures
import contextlib
import copy
import functools
import json
import threading


class AgentSession:
    """
    Agent = ChatAPI + trajectory, the agentic loop is ported from onPanda's startAgenticLoop.

    trajectory = {"messages": [...], "tools": [...], "tool_configs": [...]} is pure data like the dialog of .panda.json.
    "tools" and "tool_configs" are optional, so it also works as a plain multi-round chat.
    - tool_configs are MCP servers by HTTP {"type": "mcp", "server_url": ...}
        or by stdio {"type": "mcp", "command": ..., "args": [...], "env": {...}},
        with optional "require_approval" ("always" | "never"), "tool_name_format" (e.g. "{server_label}__{name}")
        and "ignore_instructions"
    - Without "tools", all tools of tool_configs are written to trajectory["tools"],
        and the MCP instructions are prepended as system messages like onPanda.
        Otherwise tool calls are matched to the MCP tools by tool name.
    - tool_name_to_call is {tool name: callable(tool_call) -> content of the tool message} of the caller's own tools,
        which take priority over the MCP tools of the same name, so they can short-circuit MCP.
        self.tool_name_to_call holds them together with the MCP tools registered at init
    - self.tool_name_to_require_approval is {tool name: "always" | "never"}

    >>> with AgentSession(chat_api, trajectory) as agent:
    ...     trajectory = agent.run_agentic_loop()["trajectory"]
    """

    def __init__(self, chat_api, trajectory, tool_name_to_call=None):
        self.chat_api = chat_api
        self.trajectory = copy.deepcopy(trajectory)
        self.tool_name_to_call = {}
        self.tool_name_to_require_approval = {}
        self._mcp_holder = None
        if self.trajectory.get("tool_configs"):
            # The MCP SDK is async only, so MCP sessions live in the event loop of a background thread
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
            self._thread.start()
            self._closed = asyncio.Event()
            connected = concurrent.futures.Future()
            self._mcp_holder = asyncio.run_coroutine_threadsafe(
                self._hold_mcp_sessions(connected), self._loop
            )
            concurrent.futures.wait(
                [connected, self._mcp_holder],
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if self._mcp_holder.done():
                self.close()  # Raise the connection error
        # The given callables take priority over the MCP tools of the same name
        self.tool_name_to_call.update(tool_name_to_call or {})

    async def _hold_mcp_sessions(self, connected):
        # MCP contexts must be entered and exited in the same task, so this task holds them until close()
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        from mcp.client.streamable_http import streamable_http_client

        tools, instruction_messages = [], []
        async with contextlib.AsyncExitStack() as stack:
            for config in self.trajectory["tool_configs"]:
                if "command" in config:
                    stdio_keys = ["command", "args", "env", "cwd"]
                    transport = stdio_client(
                        StdioServerParameters(
                            **{key: config[key] for key in stdio_keys if key in config}
                        )
                    )
                else:
                    transport = streamable_http_client(config["server_url"])
                read, write, *_ = await stack.enter_async_context(transport)
                session = await stack.enter_async_context(ClientSession(read, write))
                instructions = (await session.initialize()).instructions
                if instructions and not config.get("ignore_instructions"):
                    instruction_messages.append(
                        {"role": "system", "content": instructions}
                    )
                # MCP results are read as the JSON of the MCP protocol, since the SDK renames
                # its attributes between versions, e.g. `inputSchema` is `input_schema` in mcp 2
                mcp_tools = (await session.list_tools()).model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )["tools"]
                for mcp_tool in mcp_tools:
                    name = config.get("tool_name_format", "{name}").format(
                        **dict(config, name=mcp_tool["name"])
                    )
                    assert (
                        name not in self.tool_name_to_call
                    ), f'Duplicated tool name "{name}", adjust `tool_name_format` of tool_configs to keep tool names unique'
                    self.tool_name_to_call[name] = functools.partial(
                        self._call_mcp_tool, session, mcp_tool["name"]
                    )
                    self.tool_name_to_require_approval[name] = config.get(
                        "require_approval", "never"
                    )
                    tools.append(
                        {
                            "type": "function",
                            "function": {
                                "name": name,
                                "description": mcp_tool.get("description", ""),
                                "parameters": mcp_tool["inputSchema"],
                            },
                        }
                    )
            if "tools" not in self.trajectory:
                self.trajectory["tools"] = tools
                self.trajectory["messages"][:0] = instruction_messages
            connected.set_result(None)
            await self._closed.wait()

    def _call_mcp_tool(self, session, name, tool_call):
        # Same as onPanda's callMcpTool and mcpToolResultToContent
        arguments = json.loads(tool_call["function"]["arguments"] or "{}")
        result = asyncio.run_coroutine_threadsafe(
            session.call_tool(name, arguments), self._loop
        ).result()
        result = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        content = []
        for item in result["content"]:
            if content:
                content.append({"type": "text", "text": "\n"})
            if item["type"] == "text":
                content.append({"type": "text", "text": item["text"]})
            elif item["type"] in ["image", "audio"]:
                chunk_type = item["type"] + "_url"
                url = f"data:{item['mimeType']};base64,{item['data']}"
                content.append({"type": chunk_type, chunk_type: {"url": url}})
            else:
                data = item["resource"] if item["type"] == "resource" else item
                text = json.dumps(data, ensure_ascii=False, indent=2)
                content.append({"type": "text", "text": text})
        if not content and "structuredContent" in result:
            return json.dumps(result["structuredContent"], ensure_ascii=False, indent=2)
        return content or ""

    @property
    def pending_tool_calls(self):
        """Tool calls of the final message that wait for tool messages, same as onPanda's getFinishReason"""
        message = self.trajectory["messages"][-1]
        if message.get("finish_reason", "tool_calls") == "tool_calls":
            return message.get("tool_calls") or []
        return []

    def call_tool(self, tool_call):
        """Call the tool by self.tool_name_to_call, returns the tool message"""
        function = tool_call["function"]
        call = self.tool_name_to_call[function["name"]]
        try:
            content = call(tool_call)
        except Exception as error:
            # Tool errors are returned to the model like onPanda
            content = f"<|tool_call_error_start|>\nTool call error:\n{error!r}\n<|tool_call_error_end|>"
        return dict(
            role="tool",
            content=content,
            tool_call_id=tool_call["id"],
            name=function["name"],
        )

    def run_agentic_loop(
        self,
        new_messages=None,
        auto_approve_run_num=0,
        max_turns=0,
        continue_final_message=False,
    ):
        """
        Request the model and call its tool calls in turn, until the model stops calling tools.
        Returns dict(trajectory, new_message_count) like ChatAPI's return_traj.

        The loop pauses and returns with self.pending_tool_calls, when a tool call has no callable in self.tool_name_to_call,
        or requires approval beyond auto_approve_run_num. Then continue by one of:
        - new_messages=[{"role": "tool", "content": ...}, None, ...]: one for each pending tool call in order,
            tool_call_id and name are completed automatically, and None is called by self.tool_name_to_call
        - auto_approve_run_num=1: approve to call the pending tool calls
        A run that can not make any progress is an AssertionError.

        - new_messages: messages appended before the loop, e.g. the user message of a new round
        - auto_approve_run_num: how many rounds of tool calls requiring approval can be called, like onPanda's autoApproveRunNum
        - max_turns: RuntimeError when the loop needs more than max_turns requests, 0 for no limit
        - continue_final_message: the first request continues the final assistant message, see ChatAPI
        """
        messages = self.trajectory["messages"]
        if new_messages:
            tool_calls = self.pending_tool_calls
            tool_message_count = sum(
                message is None or message["role"] == "tool" for message in new_messages
            )
            assert tool_message_count == len(
                tool_calls
            ), f"{tool_message_count} tool messages of new_messages mismatch {len(tool_calls)} pending tool calls"
            tool_calls = iter(tool_calls)
            for message in new_messages:
                if message is None:
                    message = self.call_tool(next(tool_calls))
                elif message["role"] == "tool":
                    tool_call = next(tool_calls)
                    message = dict(
                        message,
                        tool_call_id=tool_call["id"],
                        name=tool_call["function"]["name"],
                    )
                messages.append(message)
        old_message_count = len(messages) - bool(continue_final_message)
        chat_kwargs = {"continue_final_message": True} if continue_final_message else {}
        turn = 0
        while True:
            tool_calls = self.pending_tool_calls
            if tool_calls:
                names = [tool_call["function"]["name"] for tool_call in tool_calls]
                need_approval = any(
                    self.tool_name_to_require_approval.get(name) == "always"
                    for name in names
                )
                if not all(name in self.tool_name_to_call for name in names) or (
                    need_approval and not auto_approve_run_num
                ):
                    # Pause for the caller to provide or approve the tool calls
                    assert (
                        turn or new_messages
                    ), f"No progress: tool calls {names} have no callable or require approval"
                    break
                auto_approve_run_num -= need_approval
                messages += [self.call_tool(tool_call) for tool_call in tool_calls]
            if max_turns and turn == max_turns:
                raise RuntimeError(f"The agentic loop needs more than {max_turns=}")
            messages = self.trajectory["messages"] = self.chat_api(
                self.trajectory, return_traj=True, **chat_kwargs
            )["trajectory"]["messages"]
            chat_kwargs = {}  # Only the first request continues the final message
            turn += 1
            if not self.pending_tool_calls:
                break
        loop_result = dict(
            trajectory=self.trajectory,
            new_message_count=len(messages) - old_message_count,
        )
        return loop_result

    def close(self):
        if self._mcp_holder:
            self._loop.call_soon_threadsafe(self._closed.set)
            concurrent.futures.wait([self._mcp_holder])
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join()
            self._loop.close()
            self._mcp_holder.result()  # Raise the error of MCP sessions if any

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


if __name__ == "__main__":
    from boxx import tree
    from mxlm.api_protocols import example_chat_api, example_trajectory, mcp_trajectory

    chat_api = example_chat_api("openai_chat")
    with AgentSession(chat_api, mcp_trajectory) as mcp_agent:
        mcp_loop_result = mcp_agent.run_agentic_loop()
        print("mcp_loop_result")
        tree(mcp_loop_result)
    # %%
    # Pause at tool calls without callable, then provide tool messages, and None is called by tool_name_to_call
    agent = AgentSession(chat_api, example_trajectory)
    agent.run_agentic_loop()
    agent.tool_name_to_call["get_weather"] = lambda tool_call: tree(tool_call) or "21°C"
    new_messages = [None] * (len(agent.pending_tool_calls) - 1)
    new_messages.append({"role": "tool", "content": "15°C"})
    loop_result = agent.run_agentic_loop(new_messages)
    tree(loop_result)
