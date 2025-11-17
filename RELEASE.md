# Release Guide

## Setup

### 1. Configure NPM Token in GitHub Secrets

You need to add your NPM authentication token as a GitHub secret:

1. Go to https://github.com/jose-blockchain/libvrf-js/settings/secrets/actions
2. Click "New repository secret"
3. Name: `NPM_TOKEN`
4. Value: Your NPM token (get it from https://www.npmjs.com/settings/YOUR_USERNAME/tokens)
5. Click "Add secret"

Alternatively, use GitHub CLI:
```bash
gh secret set NPM_TOKEN --body "your-npm-token-here"
```

## Creating a Release

### Option 1: Using GitHub CLI (Recommended)

```bash
# 1. Update version in package.json first
npm version patch  # or minor, major

# 2. Build and test
npm run build
npm test

# 3. Commit and push
git add .
git commit -m "Release v$(node -p "require('./package.json').version")"
git push origin main
git push --tags

# 4. Create GitHub release
gh release create v$(node -p "require('./package.json').version") \
  --title "v$(node -p "require('./package.json').version")" \
  --notes "Release v$(node -p "require('./package.json').version")"
```

The GitHub Actions workflow will automatically publish to NPM when the release is created.

### Option 2: Manual Release

1. Update version in `package.json`
2. Build and test: `npm run build && npm test`
3. Commit and push changes
4. Create tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. Create release on GitHub (web UI or CLI)
7. The workflow will automatically publish to NPM

## Workflow

The `.github/workflows/publish.yml` workflow automatically:
- Triggers when a GitHub release is created
- Builds the project
- Runs tests
- Publishes to NPM (if tests pass)

