import { setTimeout as delay } from 'node:timers/promises';
import { db, statements } from './db.js';
import { engineFetch } from './processManager.js';

const concurrency = 3;
let stopped = false;
async function transfer(job: any) {
  const claimed = statements.claim.run(new Date().toISOString(), job.id);
  if (!claimed.changes) return;
  try {
    const response = await engineFetch('/engine/peers/replicate', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ cid: job.chunk_cid, peer: job.peer_ip }), signal: AbortSignal.timeout(100_000),
    });
    if (!response.ok) throw new Error(await response.text());
    statements.done.run(new Date().toISOString(), job.id);
  } catch (error) {
    statements.fail.run(new Date().toISOString(), job.id);
    console.error(`[queue] job ${job.id} failed:`, error);
  }
}
async function tick() {
  const jobs = statements.pending.all() as any[];
  for (let i = 0; i < jobs.length; i += concurrency) {
    await Promise.all(jobs.slice(i, i + concurrency).map(transfer));
  }
}
export function startQueue() {
  statements.recover.run();
  void (async () => { while (!stopped) { try { await tick(); } catch (e) { console.error('[queue] poll failed:', e); } await delay(2000); } })();
}
export function stopQueue() { stopped = true; }
export function enqueueFile(fileId: string, cids: string[], peers: string[]) {
  const tx = db.transaction(() => { for (const peer of peers) for (const cid of cids) statements.enqueue.run(cid, fileId, peer); }); tx();
}
