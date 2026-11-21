# PrivEscAgent

Domain-specialized privilege-escalation agent with deterministic enumeration,
category matching, strategy selection, and step planning. Its structured
knowledge base is under `knowledge/`.

## Running

The use case is registered with the bundled hackingBuddyGPT runtime through
the bridge in `wintermute/src/hackingBuddyGPT/usecases/privesc/privescagent.py`.
From this artifact root (keep this directory named `privescagent`, lowercase):

```bash
pip install -r wintermute-requirements.txt   # from the artifact root
PYTHONPATH=wintermute/src python -m hackingBuddyGPT.cli.wintermute PrivEscAgent \
    --conn.host 127.0.0.1 --conn.port 2222 --conn.username lowpriv --conn.password lowpriv \
    --llm.api_key "$OPENAI_API_KEY" --max_turns 20
```

`--help` lists all registered use cases; `PrivEscAgent` adds the
domain-specialized phases on top of the stock `LinuxPrivesc`.


