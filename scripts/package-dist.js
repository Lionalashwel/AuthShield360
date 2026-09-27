/**
 * AuthShield 360 — ZIP packaging for delivery.
 *
 * Builds dist/AuthShield360-v2.zip from the repository, excluding
 * node_modules, .git, data/, logs/, tmp dirs and editor/tool droppings.
 *
 * Usage: node scripts/package-dist.js
 */
import { readdirSync, statSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, sep } from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = process.cwd();
const OUT = join('dist', 'AuthShield360-v2.zip');
const EXCLUDE_DIRS = new Set(['node_modules', '.git', 'data', 'logs', 'dist', 'GitHub', 'demo-render', '.tmp-rec-profile', 'coverage']);
const EXCLUDE_FILES = new Set(['.DS_Store', 'Thumbs.db']);
const EXCLUDE_PREFIX = ['.tmp', '.cache'];

const collect = (dir) => {
    const out = [];
    for (const name of readdirSync(dir)) {
        const abs = join(dir, name);
        const rel = abs.slice(ROOT.length + 1).split(sep).join('/');
        const st = statSync(abs);
        if (st.isDirectory()) {
            if (EXCLUDE_DIRS.has(name) || EXCLUDE_PREFIX.some((p) => rel.startsWith(p))) continue;
            out.push(...collect(abs));
        } else {
            if (EXCLUDE_FILES.has(name.toLowerCase())) continue;
            if (EXCLUDE_PREFIX.some((p) => name.startsWith(p))) continue;
            out.push(rel);
        }
    }
    return out;
};

const files = collect(ROOT);
console.log(`packing ${files.length} files → ${OUT}`);
mkdirSync('dist', { recursive: true });
if (existsSync(OUT)) rmSync(OUT, { force: true });
writeFileSync('.tmp-manifest.txt', files.join('\n') + '\n');
try {
    execSync(`python scripts/_zippack.py .tmp-manifest.txt "${OUT}"`, { cwd: ROOT, stdio: 'inherit', shell: false });
} finally {
    rmSync('.tmp-manifest.txt', { force: true });
}
const size = statSync(OUT).size;
console.log(`done: ${OUT} (${(size / 1024 / 1024).toFixed(1)} MB)`);