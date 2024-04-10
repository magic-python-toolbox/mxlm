# `mxlm`: Language Model Utils

## ▮ Features
- [chat_api](mxlm/chat_api.py): A simple object-oriented wrapper for the OpenAI chat completions API.
- [`.chat.md` format](mxlm/chatmd_utils.py): 
    - A multi-turn dialogue format based on markdown, capable of converting to and from OpenAI messages JSON.
    - Modify and annotate multi-turn dialogue data using your favorite editor.
    - Maintain MD format, what you see is what you get while editing.
```markdown
<!--<|BOT|>--><hr></hr><hr></hr> Here you can put the `tag`, must be one line. Could be str or JSON.
## system
You are a helpful assistant.

<!--<|BOT|>--><hr></hr><hr></hr>
## user  
Summarize the content in this url: 
https://XXX.html

<!--<|BOT|>--><hr></hr><hr></hr> {"url":"XXX.html", "title":"XXX"}
## system
Text from url https://XXX.html: ...

<!--<|BOT|>--><hr></hr><hr></hr>
## comment
Multi-line comments.  
Visible to humans but invisible to models.
```
## ▮ Usage
```bash
pip install mxlm
```

The `__main__` section at the bottom of the source code provides usage instructions and example code.
