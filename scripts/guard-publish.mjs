#!/usr/bin/env node
// Releases are published by .github/workflows/release.yml after the full test
// matrix passes. Block accidental publishes from a developer machine.
if (!process.env.GITHUB_ACTIONS && !process.env.VELA_ALLOW_LOCAL_PUBLISH) {
  console.error(
    'Refusing to publish outside CI. Tag a release instead:\n' +
      '  git tag vX.Y.Z && git push origin vX.Y.Z\n' +
      'Emergency override: VELA_ALLOW_LOCAL_PUBLISH=1 npm publish',
  );
  process.exit(1);
}
