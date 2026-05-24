# Dev Environment Setup — Onboarding Wiki

*Last updated: 2026-03-15*

## Overview
This page documents the team's standard dev environment setup for new engineers.

## Required Tools
- Python 3.10+
- Docker Desktop
- AWS CLI v2
- Git + pre-commit hooks

## Repository Setup
Clone the main repo and run `./scripts/setup.sh` to initialize the environment.

## IDE Configuration
Use VSCode with the standard workspace settings from `configs/vscode.json`.

## Database Access
Dev DB credentials are managed via AWS Secrets Manager. Run `./scripts/get-dev-creds.sh` for setup.
