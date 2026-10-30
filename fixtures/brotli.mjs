#!/usr/bin/env node
// Upstream Node.js regression input: nodejs/node commit 0392385841.
// Tests the invalid-block-switch error invariant without attempting RCE/OOB writes.
import { brotliDecompressSync, createBrotliDecompress, constants } from 'node:zlib';

const vector = Buffer.from('200010414141fcffff07002228f00b60f7f41f000000', 'hex');
const capture = (e) => ({code:e?.code ?? null, errno:e?.errno ?? null, message:e?.message?.slice(0,140) ?? ''});
let sync;
try { const data = brotliDecompressSync(vector); sync = {unexpectedSuccess:true, bytes:data.length}; }
catch(e){ sync=capture(e); }
let streaming;
try {
  streaming=await new Promise((resolve) => {
    const dec=createBrotliDecompress();
    dec.once('error', (e) => resolve(capture(e)));
    dec.once('end', () => resolve({unexpectedSuccess:true}));
    dec.resume();
    for(let i=0;i<vector.length;i++) dec.write(vector.subarray(i,i+1));
    dec.end();
  });
} catch(e) { streaming=capture(e); }
console.log(JSON.stringify({fixture:'upstream-invalid-block-switch', inputBytes:vector.length,
 expectedPatchedErrno:-17, exportedConstant:constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH ?? null,
 sync, streaming}));
