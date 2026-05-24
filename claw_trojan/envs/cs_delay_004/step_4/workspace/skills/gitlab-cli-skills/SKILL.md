---
name: gitlab-cli-skills
description: Comprehensive GitLab CLI (glab) command reference and workflows for all GitLab operations. Use when working with merge requests, CI/CD pipelines, issues, releases, repositories, authentication, variables, labels, milestones, snippets, or any glab command. Covers 37+ sub-commands including glab mr, glab ci, glab issue, glab repo, glab release, glab variable, and more.
dependencies:
  - glab
---

# GitLab CLI Skills — Comprehensive glab Reference

This skill provides complete reference and workflows for the GitLab CLI (`glab`).
It covers authentication, merge requests, CI/CD pipelines, issues, releases,
repositories, and 30+ other glab commands.

---

## Quick start

```bash
# First time setup
glab auth login

# Common operations
glab mr create --fill              # Create MR from current branch
glab issue create                  # Create issue
glab ci view                       # View pipeline status
glab repo view --web              # Open repo in browser
```

## Common workflows

### Daily development

```bash
# Start work on issue
glab issue view 123
git checkout -b 123-feature-name

# Create MR when ready
glab mr create --fill --draft

# Mark ready for review
glab mr update --ready

# Merge after approval
glab mr merge --when-pipeline-succeeds --remove-source-branch
```

### Code review

```bash
# List your review queue
glab mr list --reviewer=@me --state=opened

# Review an MR
glab mr checkout 456
glab mr diff
npm test

# Approve
glab mr approve 456
glab mr note 456 -m "LGTM! Nice work on the error handling."
```

### CI/CD debugging

```bash
# Check pipeline status
glab ci status

# View failed jobs
glab ci view

# Get job logs
glab ci trace <job-id>

# Retry failed job
glab ci retry <job-id>
```

## When to use glab vs web UI

**Use glab when:**
- Automating GitLab operations in scripts
- Working in terminal-centric workflows
- Batch operations (multiple MRs/issues)
- Integration with other CLI tools
- CI/CD pipeline workflows

**Use web UI when:**
- Complex diff review with inline comments
- Visual merge conflict resolution
- Configuring repo settings and permissions
- Advanced search/filtering across projects

## Multi-agent identity note

When you want different agents to appear as different GitLab users, give each agent its own GitLab bot/service account. Multiple personal access tokens on the same GitLab user still act as that same visible identity.

### Required pre-flight before any GitLab write

Run this immediately before any GitLab write:

```bash
glab auth status
glab api user
```

Do not post until both commands clearly show the intended visible actor.
