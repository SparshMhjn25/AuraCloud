import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const CHUNK_SIZE = 2 * 1024 * 1024;
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const KEY_SIZE = 32;
const chunkDir = path.join(process.env.AURA_DATA_DIR ?? '.auracloud_data', 'chunks');

await mkdir(chunkDir, { recursive: true });
const masterKey = await loadOrCreateKey();

export interface StoredChunk {
  cid: string;
  nonce_hex: string;
  size: number;
}

export function sliceChunks(input: Buffer, chunkSize = CHUNK_SIZE): Buffer[] {
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < input.length; offset += chunkSize) {
    chunks.push(input.subarray(offset, Math.min(offset + chunkSize, input.length)));
  }
  return chunks;
}

export async function* sliceChunkStream(
  source: AsyncIterable<Uint8Array>,
  chunkSize = CHUNK_SIZE,
): AsyncGenerator<Buffer> {
  let pending = Buffer.alloc(0);
  for await (const incoming of source) {
    const data = Buffer.isBuffer(incoming) ? incoming : Buffer.from(incoming);
    let offset = 0;
    if (pending.length > 0) {
      const needed = chunkSize - pending.length;
      if (data.length < needed) {
        pending = Buffer.concat([pending, data]);
        continue;
      }
      yield Buffer.concat([pending, data.subarray(0, needed)]);
      pending = Buffer.alloc(0);
      offset = needed;
    }
    while (offset + chunkSize <= data.length) {
      yield data.subarray(offset, offset + chunkSize);
      offset += chunkSize;
    }
    if (offset < data.length) pending = Buffer.from(data.subarray(offset));
  }
  if (pending.length > 0) yield pending;
}

export async function storeChunk(plain: Buffer): Promise<StoredChunk> {
  if (plain.length === 0 || plain.length > CHUNK_SIZE) throw new Error('chunk size must be between 1 byte and 2 MiB');
  const cid = createHash('sha256').update(plain).digest('hex');
  const nonce = randomBytes(NONCE_SIZE);
  const cipher = createCipheriv('aes-256-gcm', masterKey, nonce);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  await writeFile(chunkPath(cid), Buffer.concat([nonce, encrypted]), { mode: 0o600 });
  return { cid, nonce_hex: nonce.toString('hex'), size: plain.length };
}

export async function readChunk(cid: string): Promise<Buffer> {
  assertCID(cid);
  const stored = await readFile(chunkPath(cid));
  if (stored.length < NONCE_SIZE + TAG_SIZE) throw new Error(`encrypted chunk ${cid} is truncated`);
  const nonce = stored.subarray(0, NONCE_SIZE);
  const tag = stored.subarray(stored.length - TAG_SIZE);
  const ciphertext = stored.subarray(NONCE_SIZE, stored.length - TAG_SIZE);
  const decipher = createDecipheriv('aes-256-gcm', masterKey, nonce);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const actualCID = createHash('sha256').update(plain).digest('hex');
  if (actualCID !== cid) throw new Error(`chunk CID integrity check failed for ${cid}`);
  return plain;
}

export async function readEncryptedChunk(cid: string): Promise<Buffer> {
  assertCID(cid);
  return readFile(chunkPath(cid));
}

export async function saveReplicatedChunk(cid: string, encrypted: Buffer): Promise<void> {
  assertCID(cid);
  if (encrypted.length < NONCE_SIZE + TAG_SIZE || encrypted.length > CHUNK_SIZE + NONCE_SIZE + TAG_SIZE) {
    throw new Error('invalid encrypted chunk size');
  }
  await writeFile(chunkPath(cid), encrypted, { mode: 0o600 });
}

async function loadOrCreateKey(): Promise<Buffer> {
  const configured = process.env.AURA_MASTER_KEY;
  if (configured?.trim()) {
    const normalizedValue = configured.trim();
    const normalized = normalizedValue.startsWith('0x') ? normalizedValue.slice(2) : normalizedValue;
    if (/^[0-9a-f]{64}$/i.test(normalized)) return Buffer.from(normalized, 'hex');
    return createHash('sha256').update(configured).digest();
  }

  const keyPath = path.join(chunkDir, 'master.key');
  try {
    const encoded = (await readFile(keyPath, 'utf8')).trim();
    if (!/^[0-9a-f]{64}$/i.test(encoded)) throw new Error('master.key must contain a 32-byte hexadecimal key');
    return Buffer.from(encoded, 'hex');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const key = randomBytes(KEY_SIZE);
  try {
    const file = await open(keyPath, 'wx', 0o600);
    try { await file.writeFile(`${key.toString('hex')}\n`, 'utf8'); }
    finally { await file.close(); }
    return key;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    const encoded = (await readFile(keyPath, 'utf8')).trim();
    if (!/^[0-9a-f]{64}$/i.test(encoded)) throw new Error('master.key must contain a 32-byte hexadecimal key');
    return Buffer.from(encoded, 'hex');
  }
}

function chunkPath(cid: string): string { return path.join(chunkDir, `${cid}.chunk`); }
function assertCID(cid: string): void {
  if (!/^[0-9a-f]{64}$/i.test(cid)) throw new Error('invalid chunk CID');
}
