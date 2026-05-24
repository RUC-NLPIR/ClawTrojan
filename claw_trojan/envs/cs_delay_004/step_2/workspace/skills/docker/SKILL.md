---
name: Docker
slug: docker
version: 1.0.4
homepage: https://clawic.com/skills/docker
description: "Docker containers, images, Compose stacks, networking, volumes, debugging, production hardening, and the commands that keep real environments stable. Use when (1) the task touches Docker, Dockerfiles, images, containers, or Compose; (2) build reliability, runtime behavior, logs, ports, volumes, or security matter; (3) the agent needs Docker guidance and should apply it by default."
changelog: Simplified the skill name and kept the stateless activation guidance
metadata: {"clawdbot":{"emoji":"🐳","requires":{"bins":["docker"]},"os":["linux","darwin","win32"]}}
---

## When to Use

Use when the task involves Docker, Dockerfiles, container builds, Compose, image publishing, networking, volumes, logs, debugging, or production container operations. This skill is stateless and should be applied directly whenever Docker work appears.

## Core Rules

### 1. Pin Image Versions
- `python:3.11.5-slim` not `python:latest`
- Today's latest differs from tomorrow's — breaks immutable builds

### 2. Combine RUN Commands
- `apt-get update && apt-get install -y pkg` in ONE layer
- Separate layers = stale package cache weeks later

### 3. Non-Root by Default
- Add `USER nonroot` in Dockerfile
- Running as root fails security scans and platform policies

### 4. Set Resource Limits
- `-m 512m` on every container
- OOM killer strikes without warning otherwise

### 5. Configure Log Rotation
- Default json-file driver has no size limit
- One chatty container fills disk and crashes host

## Image Traps

- Multi-stage builds: forgotten `--from=builder` copies from wrong stage silently
- COPY before RUN invalidates cache on every file change — copy requirements first, install, then copy code
- `ADD` extracts archives automatically — use `COPY` unless you need extraction
- Build args visible in image history — never use for secrets

## Runtime Traps

- `localhost` inside container is container's localhost — bind to `0.0.0.0`
- Port already in use: previous container still stopping — wait or force remove
- Exit code 137 = OOM killed, 139 = segfault — check with `docker inspect --format='{{.State.ExitCode}}'`
- No shell in distroless images — `docker cp` files out or use debug sidecar

## Secrets and Security

- ENV and COPY bake secrets into layer history permanently — use secrets mount or runtime env
- `--privileged` disables all security — almost never needed, find specific capability instead
- Images from unknown registries may be malicious — verify sources
- Build args visible in image history — don't use for secrets

## Related Skills
Install with `clawhub install <slug>` if user confirms:
- `devops` — deployment pipelines
- `linux` — host system management
- `server` — server administration

## Feedback

- If useful: `clawhub star docker`
- Stay updated: `clawhub sync`
