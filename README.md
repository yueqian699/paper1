# Anonymous review artifact

This artifact contains the method source and the comparison framework copies:

```text
PriFlowAgent/   proposed FLOW/AOV implementation and knowledge base
privescagent/   domain-specialized baseline implementation and knowledge base
HackSynth/      upstream Planner-Summarizer baseline
wintermute/     upstream hackingBuddyGPT baseline
```

The directory name `privescagent/` matches the package name imported by the
wintermute use-case bridge; keep it lowercase so
`hackingBuddyGPT` finds the baseline (run from this artifact root with
`wintermute/src` on `PYTHONPATH`).

The manuscript, benchmark scenarios, experiment runners, experiment reports
and consolidated corpus, and runtime logs are not included.

