import { defineConfig } from 'tsup';

// @noble/* packages are ESM-only. Bundle them into the CommonJS outputs so
// `require('vela-privacy')` works on every supported Node version (Node 22+),
// including 22.0-22.11, which lack require(esm).
const NOBLE = [/^@noble\//];

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    dts: true,
    clean: true,
    sourcemap: true,
    treeshake: true,
    splitting: false,
    outDir: 'dist',
  },
  {
    entry: ['src/index.ts'],
    format: ['cjs'],
    noExternal: NOBLE,
    dts: true,
    clean: false,
    sourcemap: true,
    treeshake: true,
    splitting: false,
    outDir: 'dist',
  },
  {
    entry: {
      'bin/vela-cli': 'bin/vela-cli.ts',
    },
    format: ['cjs'],
    noExternal: NOBLE,
    clean: false,
    sourcemap: false,
    outDir: 'dist',
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
]);
