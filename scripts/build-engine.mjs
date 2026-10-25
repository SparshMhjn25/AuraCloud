import { mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
const ext = process.platform === 'win32' ? '.exe' : '';
const output = join('bin', `aura-engine${ext}`);
mkdirSync(dirname(output), { recursive: true });
const result = spawnSync('go', ['build', '-o', output, './cmd/aura-engine'], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
