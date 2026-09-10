# Contributing

[AGENTS.md](AGENTS.md) is the contributor guide. It applies to people, not
just agents: scope rules, code style, and the hostile-input discipline all
come from there, and [SPEC.md](SPEC.md) is the behavior contract.

Development happens in the Nix shell:

```sh
nix develop
just test
just fmt-check && just lint
```

Run `just` with no arguments to list every recipe. The formatting and lint
gates must pass before every commit. Reference the GitHub issue a change
relates to in its commit message; keep source comments about the code, not
the tracker.

[Test requirements](SPEC.md#9-acceptance-criteria) define what CI runs.
