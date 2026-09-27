#!/usr/bin/env node
/**
 * AuthShield 360 / Cornell Deep — build a clean, upload-ready repository copy.
 *
 *   node scripts/build-upload-bundle.js [targetDir]
 *
 * Copies every tracked project file into a flat, self-contained folder that can be
 * dragged straight into GitHub (web upload). Excludes dependencies, runtime
 * artifacts, and nested packaging output so the bundle stays small and tidy.
 * Never overwrites a target that already holds files unless --force is passed.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const force = args.includes('--force');
const target = path.resolve(args.find((a) => !a.startsWith('--')) || 'upload-bundle');

const INCLUDE_FILES = [
  '.gitignore',
  'AGENTS.md',
  'LICENSE.md',
  'README.md',
  'demo.mp4',
  'package.json',
  'package-lock.json',
];
const INCLUDE_DIRS = ['.github', 'backend', 'docs', 'frontend', 'presentation', 'scripts'];

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'data', 'logs', 'dist', 'coverage', 'GitHub',
  'demo-render', '.cache', '.vscode', '.idea', '.tmp-rec-profile',
]);

const skip = (name) => name === 'Thumbs.db' || name === '.DS_Store' || name.startsWith('.tmp');

function copyInto(srcDir, outDir, stats) {
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || skip(entry.name)) continue;
      copyInto(path.join(srcDir, entry.name), path.join(outDir, entry.name), stats);
    } else if (entry.isFile()) {
      if (skip(entry.name) || entry.name === '.DS_Store') continue;
      const to = path.join(outDir, entry.name);
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.copyFileSync(path.join(srcDir, entry.name), to);
      stats.files.push(path.relative(target, to).replace(/\\/g, '/'));
      stats.bytes += fs.statSync(to).size;
    }
  }
}

if (fs.existsSync(target) && fs.readdirSync(target).length && !force) {
  console.error(`target not empty: ${target}\nre-run with --force to replace its contents`);
  process.exit(1);
}
fs.rmSync(target, { recursive: true, force: true });
fs.mkdirSync(target, { recursive: true });

const stats = { files: [], bytes: 0 };
for (const f of INCLUDE_FILES) {
  const from = path.join(ROOT, f);
  if (!fs.existsSync(from)) { console.warn(`skip (missing) ${f}`); continue; }
  fs.copyFileSync(from, path.join(target, f));
  stats.files.push(f);
  stats.bytes += fs.statSync(from).size;
}
for (const d of INCLUDE_DIRS) {
  const from = path.join(ROOT, d);
  if (!fs.existsSync(from)) { console.warn(`skip (missing) ${d}/`); continue; }
  copyInto(from, path.join(target, d), stats);
}
stats.files.sort();

const required = ['.github/workflows/tests.yml', '.github/workflows/pages.yml',
  'README.md', 'package.json', 'docs/technical/Technical_Report_AR.md',
  'docs/technical/Presentation_Deck.pptx', 'presentation/index.html', 'demo.mp4'];
const missing = required.filter((f) => !stats.files.includes(f));
if (missing.length) {
  console.error('bundle incomplete, missing:\n  ' + missing.join('\n  '));
  process.exit(1);
}

// manifest stays outside the bundle so the repository itself carries no clutter
const manifest = path.join(ROOT, 'dist', 'upload-bundle-files.txt');
fs.mkdirSync(path.dirname(manifest), { recursive: true });
fs.writeFileSync(manifest, stats.files.join('\n') + '\n', 'utf8');
console.log(`bundle: ${target}`);
console.log(`files: ${stats.files.length}   size: ${(stats.bytes / 1048576).toFixed(1)} MB`);
console.log(`manifest: ${path.relative(ROOT, manifest)}`);
console.log(`workflows: ${stats.files.filter((f) => f.startsWith('.github/')).length}   docs: ${stats.files.filter((f) => f.startsWith('docs/')).length}`);
