import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import dts from 'rollup-plugin-dts';

const external = [
  'chalk',
  'commander',
  'cookie-parser',
  'express',
  'ioredis',
  'pg',
  'crypto',
  'path',
  'fs',
  'util',
];

const sharedPlugins = [
  resolve({
    preferBuiltins: true,
  }),
  commonjs(),
  json(),
];

export default [
  // Main library build - ESM
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.mjs',
      format: 'esm',
      sourcemap: true,
    },
    external,
    plugins: [
      ...sharedPlugins,
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false,
        outDir: 'dist',
      }),
    ],
  },
  // Main library build - CJS
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.cjs',
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
    },
    external,
    plugins: [
      ...sharedPlugins,
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false,
        outDir: 'dist',
      }),
    ],
  },
  // CLI build - ESM
  {
    input: 'src/cli/index.ts',
    output: {
      file: 'dist/cli/index.mjs',
      format: 'esm',
      sourcemap: true,
    },
    external,
    plugins: [
      ...sharedPlugins,
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false,
        outDir: 'dist',
      }),
    ],
  },
  // CLI build - CJS
  {
    input: 'src/cli/index.ts',
    output: {
      file: 'dist/cli/index.cjs',
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
    },
    external,
    plugins: [
      ...sharedPlugins,
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
        declarationMap: false,
        outDir: 'dist',
      }),
    ],
  },
  // Type definitions for main library
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.d.ts',
      format: 'esm',
    },
    external,
    plugins: [dts()],
  },
  // Type definitions for CLI
  {
    input: 'src/cli/index.ts',
    output: {
      file: 'dist/cli/index.d.ts',
      format: 'esm',
    },
    external,
    plugins: [dts()],
  },
];
