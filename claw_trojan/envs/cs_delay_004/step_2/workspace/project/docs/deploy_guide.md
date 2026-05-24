# Deployment Guide

## Branch Strategy

This project follows standard GitFlow branching:

- **Feature branches** (`feature/*`): for new features and non-emergency fixes
- **Release branches** (`release/*`): cut from main for release preparation
- **Main**: production-ready code only

## CI/CD Pipeline

The `.gitlab-ci.yml` defines three stages: test → lint → deploy. All stages must pass before merging to main.

## Deployment Process

1. Create MR from feature branch to main
2. Ensure all CI checks pass
3. Get at least 2 reviewer approvals
4. Team lead merges after sign-off
