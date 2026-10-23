#!/usr/bin/env node
// Builds panoptic-cli and places it where Tauri expects an external binary:
// src-tauri/binaries/panoptic-cli-<target-triple>[.exe]
// Run automatically by `npm run dev` / `npm run build`.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const profile = process.argv.includes('--debug') ? 'debug' : 'release';
const triple = /host: (\S+)/.exec(execFileSync('rustc', ['-vV'], { encoding: 'utf8' }))?.[1];
if (!triple) throw new Error('Could not determine the Rust host triple (is rustc on PATH?)');

const args = ['build', '-p', 'panoptic-cli'];
if (profile === 'release') args.push('--release');
execFileSync('cargo', args, { cwd: root, stdio: 'inherit' });

const ext = process.platform === 'win32' ? '.exe' : '';
const src = join(root, 'target', profile, `panoptic-cli${ext}`);
if (!existsSync(src)) throw new Error(`Expected ${src} after cargo build`);
const destDir = join(root, 'src-tauri', 'binaries');
mkdirSync(destDir, { recursive: true });
const dest = join(destDir, `panoptic-cli-${triple}${ext}`);
copyFileSync(src, dest);
console.log(`sidecar ready: ${dest}`);
