import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { basename } from 'node:path';
import { readFile } from 'node:fs/promises';
import { db, statements } from './db.js';
import { engineFetch, engineToken, startEngine, shutdownEngine } from './processManager.js';
import { enqueueFile, startQueue, stopQueue } from './queue.js';
import { readChunk, readEncryptedChunk, saveReplicatedChunk, sliceChunkStream, storeChunk } from './chunks.js';

const app = Fastify({ logger: true, bodyLimit: 64 * 1024 * 1024 });
app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
await app.register(multipart, { limits: { fileSize: 20 * 1024 * 1024 * 1024, files: 1 } });
const chunkBytes = 2 * 1024 * 1024;
app.get('/api/v1/node/status', async () => {
  const engine: any = await engineFetch('/engine/status').then(r => r.ok ? r.json() : Promise.reject(new Error('engine unavailable')));
  const mesh = engine.mesh ?? {};
  return { hostname:mesh.hostname, tailscale_ips:mesh.tailscale_ips ?? [], status:mesh.status ?? 'offline',
    mesh_enabled:mesh.mesh_enabled ?? false, state_dir:mesh.state_dir };
});
app.get('/api/v1/health', async () => ({status:'online', system:'AuraCloud Hybrid'}));
app.get('/api/v1/sync/status', async () => {
  const [engine, queue] = await Promise.all([
    engineFetch('/engine/status').then(r => r.ok ? r.json() : Promise.reject(new Error('engine unavailable'))),
    Promise.resolve(statements.stats.all()),
  ]);
  const counts = queue as Array<{status:string;count:number}>;
  return { mesh_enabled:true, peers_online:((engine as any).onlinePeers ?? []).length,
    pending_chunks:counts.filter(x => ['PENDING','FAILED','IN_PROGRESS'].includes(x.status)).reduce((a,x) => a+x.count,0) };
});
app.get('/', async (_request, reply) => reply.type('text/html').send(await readFile('web/index.html')));
app.get('/api/v1/files', async () => statements.listFiles.all());
app.post('/api/v1/files/upload', async (request, reply) => {
  const part = await request.file();
  if (!part) return reply.code(400).send({ error: 'multipart file field is required' });
  const id = randomUUID(); const cids: string[] = []; const chunkRows: Array<[string, number, string, string, number]> = [];
  let size = 0; let index = 0;
  for await (const block of sliceChunkStream(part.file, chunkBytes)) {
    const saved = await storeChunk(block);
    cids.push(saved.cid); chunkRows.push([id,index++,saved.cid,saved.nonce_hex,block.length]); size += block.length;
  }
  if (part.file.truncated) return reply.code(413).send({ error: 'upload exceeds configured limit' });
  if (!size) return reply.code(400).send({ error: 'empty files are not supported' });
  const peers: string[] = await engineFetch('/engine/status').then(r => r.json()).then((x: any) => x.onlinePeers ?? []).catch(() => []);
  const tx = db.transaction(() => {
    statements.insertFile.run(id, basename(part.filename), size, part.mimetype || 'application/octet-stream', cids.length, new Date().toISOString());
    for (const row of chunkRows) statements.insertChunk.run(...row);
  }); tx();
  enqueueFile(id,cids,peers);
  return reply.code(201).send({ file_id:id,file_name:basename(part.filename),file_size:size,total_chunks:cids.length,status:'uploaded_and_encrypted' });
});
app.get('/api/v1/files/download/:id', async (request: any, reply) => {
  const file: any = statements.getFile.get(request.params.id);
  if (!file) return reply.code(404).send({ error:'file not found' });
  const chunks: any[] = statements.getChunks.all(file.id);
  reply.header('content-type',file.mime_type).header('content-disposition',`attachment; filename="${encodeURIComponent(file.file_name)}"`);
  reply.hijack();
  for (const row of chunks) {
    try {
      const plain = await readChunk(row.cid);
      if (!reply.raw.write(plain)) await new Promise<void>(resolve => reply.raw.once('drain', resolve));
    } catch (error) {
      reply.raw.destroy(error instanceof Error ? error : new Error(String(error)));
      return reply;
    }
  }
  reply.raw.end();
  return reply;
});
app.delete('/api/v1/files/delete/:id', async (request: any, reply) => {
  const result = db.prepare('DELETE FROM files WHERE id=?').run(request.params.id);
  if (!result.changes) return reply.code(404).send({error:'file not found'});
  return {file_id:request.params.id,status:'deleted'};
});
app.post('/api/v1/engine/chunks/store', async (request, reply) => {
  const raw = request.body as Buffer;
  if (!Buffer.isBuffer(raw)) return reply.code(415).send({ error:'send application/octet-stream' });
  try { return reply.code(201).send(await storeChunk(raw)); }
  catch (error) { return reply.code(400).send({error: error instanceof Error ? error.message : String(error)}); }
});
app.post('/api/v1/engine/peers/replicate', async (request, reply) => {
  const { cid, peer } = request.body as {cid?:string;peer?:string};
  if (!cid || !peer) return reply.code(400).send({error:'cid and peer are required'});
  let encrypted: Buffer;
  try { encrypted = await readEncryptedChunk(cid); }
  catch (error) { return reply.code(404).send({error:error instanceof Error ? error.message : String(error)}); }
  const result = await engineFetch('/proxy/send-to-peer', { method:'POST', headers:{
    'content-type':'application/octet-stream', 'x-auracloud-cid':cid, 'x-auracloud-peer':peer,
  }, body:encrypted });
  return reply.code(result.status).send(await result.text());
});
app.post('/internal/chunks/receive', {
  preHandler: async (request, reply) => {
    const provided = request.headers.authorization ?? '';
    const expected = `Bearer ${engineToken}`;
    if (provided.length !== expected.length || !timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
      return reply.code(401).send({error:'unauthorized'});
    }
  },
}, async (request, reply) => {
  const cid = request.headers['x-auracloud-cid'];
  const encrypted = request.body;
  if (typeof cid !== 'string' || !Buffer.isBuffer(encrypted)) return reply.code(400).send({error:'cid and raw encrypted chunk are required'});
  try { await saveReplicatedChunk(cid, encrypted); return reply.code(201).send({status:'stored',cid}); }
  catch (error) { return reply.code(400).send({error:error instanceof Error ? error.message : String(error)}); }
});
const stop = async () => { stopQueue(); await app.close(); await shutdownEngine(); db.close(); };
process.once('SIGINT', () => void stop()); process.once('SIGTERM', () => void stop());
await app.listen({ host: process.env.HOST ?? '127.0.0.1', port: Number(process.env.PORT ?? 3000) });
// Start Node's receiver before Go opens the tsnet listener so peer arrivals
// can always be forwarded to a live internal endpoint.
await startEngine();
startQueue();
