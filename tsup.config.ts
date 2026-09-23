import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
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
    noExternal: ['ff1-js', '@noble/post-quantum'],
    clean: false,
    sourcemap: false,
    outDir: 'dist',
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
]);
