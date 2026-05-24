# Anonymous Release Notes

This package was created from the working ClawShield repository with a
whitelist-based copy.

Included:

- source code required for DASGuard, sandbox evaluation, metric computation, and
  selected baselines;
- reduced English ClawTrojan example data under `claw_trojan/`, with three
  annotated sample chains per available outcome category;
- paper-scale sharding, worker, and merge scripts;
- focused regression tests.

Excluded:

- `.git` history and original remotes;
- `.env`, API keys, credentials, local endpoint secrets, and local provider
  configuration;
- IDE/editor folders and Python caches;
- raw `outputs/` traces, logs, per-turn transcripts, and full workspace diffs;
- Chinese pilot data and early annotation drafts not needed for paper
  reproduction;
- manuscript files that may contain author or acknowledgement metadata;
- remote-machine helper scripts and logs containing local usernames or storage
  paths;
- large vendored third-party repositories.
- the optional synthetic `dataset/` generator, which is not required for the
  ClawTrojan sandbox reproduction commands.

The benchmark itself intentionally contains synthetic names, emails, mock
credentials, and fake organization data. These are generated scenario artifacts,
not real personal data.
