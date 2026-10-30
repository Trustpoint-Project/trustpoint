// Copyright (c) 2026 The Trustpoint Project Authors
// SPDX-License-Identifier: MIT

import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

// Inspect the actual esbuild inputs, including transitive dependencies. Fail the
// build rather than silently distributing a dependency without its license.
export async function bundledNotices(metafile, workingDirectory) {
  const packages = new Map();
  for (const input of Object.keys(metafile.inputs)) {
    const absolute = path.resolve(workingDirectory, input);
    if (!absolute.includes(`${path.sep}node_modules${path.sep}`)) continue;
    let directory = path.dirname(absolute);
    while (directory !== path.dirname(directory)) {
      let metadata;
      try {
        metadata = JSON.parse(await readFile(path.join(directory, 'package.json'), 'utf8'));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        directory = path.dirname(directory);
        continue;
      }
      if (!metadata.name || !metadata.version) {
        directory = path.dirname(directory);
        continue;
      }
      const id = `${metadata.name}@${metadata.version}`;
      if (!packages.has(id)) {
        const files = (await readdir(directory))
          .filter(name => /^(licen[cs]e|copying|notice)(\.|$)/i.test(name)).sort();
        if (!files.some(name => /^(licen[cs]e|copying)(\.|$)/i.test(name))) {
          throw new Error(`Missing license text for bundled dependency ${id}`);
        }
        const texts = await Promise.all(files.map(async name =>
          `${name}\n${await readFile(path.join(directory, name), 'utf8')}`));
        packages.set(id, `${id}\nLicense: ${metadata.license ?? 'See license text'}\n\n${texts.join('\n')}`);
      }
      break;
    }
  }
  if (packages.size === 0) throw new Error('No bundled dependency licenses found');
  return 'Third-party notices for the Trustpoint workflow editor\n'
    + 'Generated from actual esbuild inputs; do not edit by hand.\n\n'
    + [...packages.keys()].sort().map(id => `${'='.repeat(72)}\n${packages.get(id)}`).join('\n\n') + '\n';
}
