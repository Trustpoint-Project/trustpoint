import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import * as esbuild from 'esbuild';

import { bundledNotices } from './notices.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const watch = process.argv.includes('--watch');
const check = process.argv.includes('--check');
if (watch && check) throw new Error('--watch and --check cannot be combined');

const srcFile = path.join(__dirname, 'src', 'workflow_editor', 'index.js');
const outFile = path.join(__dirname, '..', '..', 'static', 'js', 'workflows2', 'editor_bundle.js');

await mkdir(path.dirname(outFile), { recursive: true });

const noticesFile = outFile + '.NOTICES.txt';
const noticePlugin = {
  name: 'third-party-notices',
  setup(build) {
    build.onEnd(async result => {
      if (result.errors.length) return;
      const notices = await bundledNotices(result.metafile, __dirname);
      if (check) {
        // Compare in memory so CI cannot accidentally repair stale artifacts.
        for (const file of result.outputFiles) {
          if (!(await readFile(file.path)).equals(file.contents)) {
            throw new Error(`Stale frontend artifact: ${file.path}; run npm run build`);
          }
        }
        if (await readFile(noticesFile, 'utf8') !== notices) {
          throw new Error('Stale workflow editor notices; run npm run build');
        }
      } else {
        await writeFile(noticesFile, notices);
      }
    });
  },
};

const buildOptions = {
  absWorkingDir: __dirname,
  metafile: true,
  write: !check,
  plugins: [noticePlugin],
  entryPoints: [srcFile],
  bundle: true,
  outfile: outFile,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  sourcemap: watch,
  minify: !watch,
  legalComments: 'eof',
  banner: { js: '/*! Third-party license texts: editor_bundle.js.NOTICES.txt */' },
  logLevel: 'info',
};

if (watch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log('[workflows2] watching src/workflow_editor/index.js');
} else {
  await esbuild.build(buildOptions);
  console.log('[workflows2] built ../../static/js/workflows2/editor_bundle.js');
}
