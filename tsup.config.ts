// tsup.config.ts
// import * as path from 'node:path'
import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  tsconfig: '../../tsconfig.tsup.json',
  dts: true,
  target: ["es2022"],
  platform: 'neutral',
  cjsInterop: true,
  experimentalDts: false,
  keepNames: true,
  //external: ['whatwg-fetch', 'crypto', 'node:crypto' ,'stream', 'whatwg-url'],
  // onSuccess: "tsc -p ../../../../tsconfig.build.json --emitDeclarationOnly",
  shims: true,
  sourcemap: true,
  splitting: false,
  outDir: 'dist',
  clean: true,
  skipNodeModulesBundle: true
})
