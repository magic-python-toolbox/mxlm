# `mxlm`: Language Model Utils

## ▮ Features
- [chat_api](mxlm/chat_api.py): A simple object-oriented wrapper for the OpenAI chat API.
    - Supports caching chat requests to avoid starting over in case of errors.
    - Supports [api_protocols](mxlm/api_protocols) `"openai_responses" | "anthropic_messages" | "gemini_generate_content"`, and trajectory rollout by `return_traj=True`.
- [agent_session](mxlm/agent_session.py): `AgentSession(chat_api, trajectory)` runs the agentic loop over a pure-data trajectory with MCP tools (HTTP and stdio), approval and external tool results.

## ▮ Usage
```bash
pip install mxlm
```

The `__main__` section at the bottom of the source code provides usage instructions and example code.
