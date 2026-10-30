import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {readFileSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createZipMismatch} from '../fixtures/zip-fixture.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));

test('all October CVEs are covered, no active fixture is silently skipped',()=>{
 const proc=spawnSync(process.execPath,[join(root,'probe.mjs'),'--json','--skip-snapshot'],{
   encoding:'utf8',timeout:28000,maxBuffer:2*1024*1024});
 assert.ok([0,2].includes(proc.status), proc.stderr||'runner returned invalid exit status');
 const report=JSON.parse(proc.stdout);
 const ids=new Set(report.checks.map(x=>x.cve));
 assert.equal(ids.size,10);
 for(const id of ['CVE-2026-111497','CVE-2026-105481','CVE-2026-106070']) assert.ok(ids.has(id));
 const affected=report.checks.filter(x=>['CVE-2026-111497','CVE-2026-105481'].includes(x.cve));
 if([22,24,26].includes(Number(process.versions.node.split('.')[0]))) {
   assert.equal(affected.length,3);
   assert.ok(affected.every(x=>!['not-run','not-applicable'].includes(x.outcome)));
 }
 if(process.versions.node.startsWith('26.')) {
   assert.ok(!['not-run','not-applicable'].includes(report.checks.find(x=>x.cve==='CVE-2026-106070').outcome));
 }
});

test('ZIP fixture contains distinct decoy and actual data, with conflicting CRC',()=>{
 const dir=mkdtempSync(join(tmpdir(),'zip-fixture-test-'));
 try {
   const f=join(dir,'archive.zip');
   const info=createZipMismatch(f);
   const buf=readFileSync(f);
   const start=info.decoy.length;
   assert.equal(info.decoy.length,info.payload.length);
   assert.equal(buf.subarray(0,start).toString(),info.decoy);
   assert.equal(buf.readUInt32LE(start),0x04034b50);
   assert.equal(buf.readUInt32LE(buf.length-22),0x06054b50);
   assert.ok(buf.includes(Buffer.from(info.payload)));
   const central=buf.lastIndexOf(Buffer.from('PK\x01\x02','binary'));
   assert.ok(central>start);
   assert.notEqual(buf.readUInt32LE(start+14),buf.readUInt32LE(central+16));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
