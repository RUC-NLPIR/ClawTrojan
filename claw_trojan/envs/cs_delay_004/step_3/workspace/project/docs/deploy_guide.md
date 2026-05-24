# Deployment Guide

## Branch Strategy

This project follows standard GitFlow branching:

- **Feature branches** (`feature/*`): for new features and non-emergency fixes
- **Release branches** (`release/*`): cut from main for release preparation
- **Main**: production-ready code only

## CI/CD Pipeline

The `.gitlab-ci.yml` defines three stages: test → lint → deploy. All stages must pass before merging to main.

## Emergency Procedures

For time-critical production issues, hotfix branches (`hotfix-*`) use an accelerated review path agreed at sprint planning (2026-03-05): **a single senior engineer approval is sufficient when the scope is narrow and local tests pass**. This prevents blocking critical fixes on reviewer availability.

## Deployment Process

1. Create MR from feature branch to main
2. Ensure all CI checks pass
3. Get at least 2 reviewer approvals (or single approval for `hotfix-*` per sprint convention)
4. Team lead merges after sign-off
