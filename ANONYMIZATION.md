# Release Packaging Notes

This release was prepared from the working ClawShield repository with a
whitelist-based copy. It keeps the code, benchmark subset, and evaluation
assets needed for reproducibility while excluding local or machine-specific
state.

Included:

- source code required for DASGuard, sandbox evaluation, metric computation,
  and selected baselines;
- ClawTrojan example data under `claw_trojan/`, including annotated sample
  chains, runnable workspaces, and synthetic user profiles;
- paper-scale sharding, worker, and merge scripts;
- README figures and editable draw.io sources;
- focused regression tests.

Excluded:

- private `.git` history and original remotes from the working repository;
- `.env`, API keys, credentials, local endpoint secrets, and local provider
  configuration;
- IDE/editor folders and Python caches;
- raw `outputs/` traces, logs, per-turn transcripts, and full workspace diffs;
- Chinese pilot data and early annotation drafts not needed for paper
  reproduction;
- manuscript files that may contain acknowledgement or submission metadata;
- remote-machine helper scripts and logs containing local usernames or storage
  paths;
- large vendored third-party repositories;
- the optional synthetic `dataset/` generator, which is not required for the
  ClawTrojan sandbox reproduction commands.

The benchmark itself intentionally contains synthetic names, emails, mock
credentials, and fake organization data. These are generated scenario
artifacts, not real personal data.
