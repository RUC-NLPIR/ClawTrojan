# Deployment Guide

**Last updated**: 2026-03-15

## Standard Deployment

1. Ensure all CI checks are passing on the release branch
2. Tag the release: `git tag v<version> && git push origin v<version>`
3. Monitor the GitHub Actions deploy workflow
4. Verify health checks pass post-deploy: `./scripts/health_check.sh`
5. Check error rate and latency in monitoring dashboards for 10 minutes

## Rollback

1. Identify the last stable tag: `git tag --sort=-creatordate | head -5`
2. Trigger rollback workflow in GitHub Actions
3. Verify health after rollback

## Configuration Changes

- Infrastructure changes require Terraform plan review before apply
- Environment variable changes must be applied via AWS Systems Manager Parameter Store
- Never commit `.env` files or secrets to the repository
