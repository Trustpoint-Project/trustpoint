import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import * as esbuild from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const watch = process.argv.includes('--watch');

const srcFile = path.join(__dirname, 'src', 'app', 'workflow_editor_page.js');
const outFile = path.join(__dirname, '..', '..', 'static', 'js', 'workflows2', 'editor_bundle.js');

await mkdir(path.dirname(outFile), { recursive: true });

const buildOptions = {
  entryPoints: [srcFile],
  bundle: true,
  outfile: outFile,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  sourcemap: watch,
  minify: !watch,
  legalComments: 'none',
  logLevel: 'info',
};

if (watch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('[workflows2] watching src/app/workflow_editor_page.js');
} else {
  await esbuild.build(buildOptions);
  console.log('[workflows2] built ../../static/js/workflows2/editor_bundle.js');
}