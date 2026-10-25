import { spawn, type ChildProcess } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';

const base = process.env.AURA_ENGINE_URL ?? 'http://127.0.0.1:9091';
let child: ChildProcess | undefined;
const token = randomBytes(32).toString('hex');
type EngineFetchInit = Omit<RequestInit, 'body'> & {
  body?: RequestInit['body'] | Uint8Array | null;
};
export async function startEngine() {
  const defaultBinary = process.platform === 'win32' ? './bin/aura-engine.exe' : './bin/aura-engine';
  const binary = process.env.AURA_ENGINE_BIN ?? defaultBinary;
  child = spawn(binary, [], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, AURA_ENGINE_TOKEN: token } });
  child.stdout?.on('data', (b) => process.stdout.write(`[aura-engine] ${b}`));
  child.stderr?.on('data', (b) => process.stderr.write(`[aura-engine] ${b}`));
  child.on('exit', (code, signal) => console.error(`[aura-engine] exited code=${code} signal=${signal}`));
  for (let i = 0; i < 60; i++) {
    if (child.exitCode !== null) throw new Error(`aura-engine exited with ${child.exitCode}`);
    try { const r = await engineFetch('/health', { signal: AbortSignal.timeout(1000) }); if (r.ok) return; } catch {}
    await delay(500);
  }
  stopEngine(); throw new Error('aura-engine did not become healthy within 30 seconds');
}
export function engineFetch(path: string, init: EngineFetchInit = {}) {
  const headers = new Headers(init.headers);
  headers.set('authorization', `Bearer ${token}`);
  const { body, ...options } = init;
  // Copy Node Buffer/typed-array payloads into an ArrayBuffer-backed view. This
  // is accepted by the DOM fetch BodyInit types even when Buffer uses
  // ArrayBufferLike (which may include SharedArrayBuffer).
  const fetchBody = body instanceof Uint8Array ? new Uint8Array(body) : body;
  return fetch(`${base}${path}`, { ...options, headers, body: fetchBody });
}
export function stopEngine() { if (child && child.exitCode === null) child.kill('SIGTERM'); }
export async function shutdownEngine() {
  if (!child || child.exitCode !== null) return;
  const proc = child;
  proc.kill('SIGTERM');
  await Promise.race([new Promise<void>((resolve) => proc.once('exit', () => resolve())), delay(5000)]);
  if (proc.exitCode === null) proc.kill('SIGKILL');
}
