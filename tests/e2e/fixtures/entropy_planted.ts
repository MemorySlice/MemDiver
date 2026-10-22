import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * A low-entropy, heap-like RAW dump with high-entropy keys planted at known
 * offsets, generated at spec time (12 MiB is too large to commit).
 *
 * The filler is what a heap mostly looks like to a 32-byte entropy window:
 * zero pages, arrays of small little-endian ints, ASCII words and user-space
 * pointers (0x00007f3a5cXXXXXX). Every 32-byte window of it stays well below
 * the 4.5 bits/byte default threshold, so any region the entropy view reports
 * must be a planted key -- a false positive on the filler fails the spec.
 *
 * The size is deliberately ABOVE the 8 MiB `FULL_RESOLUTION_AUTO_BYTES`, so
 * the Workspace's first (auto) request comes back sampled and the progressive
 * follow-up (`resolution=full`) has to replace it.
 *
 * Deterministic (seeded PRNG): the same bytes on every run, so a pass or a
 * failure is a property of the code, not of the dice.
 */

export interface PlantedKey {
  offset: number;
  length: number;
}

export interface PlantedDump {
  path: string;
  size: number;
  keys: PlantedKey[];
}

const PAGE = 4096;
const MIB = 1024 * 1024;
export const PLANTED_DUMP_SIZE = 12 * MIB;

/** One 32-byte key and one 64-byte key, far apart and off page boundaries. */
export const PLANTED_KEYS: PlantedKey[] = [
  { offset: 3 * MIB + 0x1230, length: 32 },
  { offset: 9 * MIB + 0x2340, length: 64 },
];

const WORDS = ["heap", "node", "data", "next", "prev", "size", "free", "used"];

/** mulberry32: a tiny seeded PRNG, uniform uint32 per call. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}

function fillSmallInts(page: Buffer, rand: () => number): void {
  for (let i = 0; i < PAGE; i += 4) page.writeUInt32LE(rand() % 8, i);
}

function fillAscii(page: Buffer, rand: () => number): void {
  let i = 0;
  while (i < PAGE) {
    const word = `${WORDS[rand() % WORDS.length]} `;
    i += page.write(word, i, "latin1");
  }
}

function fillPointers(page: Buffer, rand: () => number): void {
  // 0x00007f3a5c______ little-endian: 3 varying low bytes, 5 fixed high bytes.
  for (let i = 0; i < PAGE; i += 8) {
    const low = rand() & 0xfff0; // 16-byte aligned, a narrow arena
    page.writeUInt32LE(((0x5c << 24) | (0x10 << 16) | low) >>> 0, i);
    page.writeUInt32LE(0x00007f3a, i + 4);
  }
}

/** One filler page: zero / small ints / ASCII words / pointers. */
function fillerPage(rand: () => number): Buffer {
  const page = Buffer.alloc(PAGE);
  const kind = rand() % 10;
  if (kind < 4) return page; // zero page
  if (kind < 6) fillSmallInts(page, rand);
  else if (kind < 8) fillAscii(page, rand);
  else fillPointers(page, rand);
  return page;
}

function keyBytes(length: number, rand: () => number): Buffer {
  const key = Buffer.alloc(length);
  for (let i = 0; i < length; i++) key[i] = rand() & 0xff;
  return key;
}

/** Write the dump (idempotent: same path, same bytes) and describe it. */
export function generatePlantedHeapDump(): PlantedDump {
  const dir = path.join(os.tmpdir(), "memdiver-e2e-entropy-planted");
  mkdirSync(dir, { recursive: true });
  const dumpPath = path.join(dir, "planted_heap.bin");

  const fillerRand = seededRandom(0x5eed1234);
  const pages: Buffer[] = [];
  for (let p = 0; p < PLANTED_DUMP_SIZE / PAGE; p++) pages.push(fillerPage(fillerRand));
  const blob = Buffer.concat(pages);

  const keyRand = seededRandom(0xc0ffee42);
  for (const key of PLANTED_KEYS) keyBytes(key.length, keyRand).copy(blob, key.offset);

  writeFileSync(dumpPath, blob);
  return { path: dumpPath, size: blob.length, keys: PLANTED_KEYS };
}
