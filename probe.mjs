#!/usr/bin/env node
/**
 * Node.js October 21 2026 security release: safe, local differential probes.
 * No production targets, external DNS, destructive filesystem operations,
 * malformed native decoder input, or malicious archive payloads.
 *
 * Usage: node probe.mjs [--json] [--scan-root=/absolute/path] [--skip-snapshot]
 * Exit codes: 0 = no vulnerable behaviors observed, 2 = vulnerable behavior
 * observed, 1 = harness failure. An exit 0 is NOT an application security attestation.
 */
import { createSocket } from 'node:dgram';
import { promises as dns } from 'node:dns';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, extname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { checkServerIdentity } = require('node:tls');
const flags = new Set(process.argv.slice(2));
const json = flags.has('--json');
const skipSnapshot = flags.has('--skip-snapshot');
const scanRootArg = [...flags].find(s => s.startsWith('--scan-root='));
const major = +process.versions.node.split('.')[0];
const version = process.versions.node;
const minimums = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
const affected = {
  'CVE-2026-105482': [22, 24, 26],
  'CVE-2026-105483': [24, 26],
  'CVE-2026-106069': [22, 24, 26],
  'CVE-2026-111497': [22, 24, 26],
  'CVE-2026-105481': [22, 24, 26],
  'CVE-2026-106072': [22, 24, 26],
  'CVE-2026-106074': [22, 24, 26],
  'CVE-2026-106070': [26],
  'CVE-2026-106071': [26],
  'CVE-2026-106073': [22, 24, 26],
};

function compare(a, b) {
  const left = a.split('.').map(Number), right = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return Math.sign(left[i] - right[i]);
  return 0;
}
function versionAssessment(cve) {
  if (!(major in minimums)) return 'unassessed-runtime-line';
  if (!affected[cve].includes(major)) return 'not-affected-per-advisory';
  return compare(version, minimums[major]) >= 0 ? 'fixed-release-or-newer' : 'older-than-security-release';
}
const checks = [];
function record(cve, probe, outcome, evidence) {
  checks.push({cve, probe, outcome, evidence, runtimeAssessment: versionAssessment(cve)});
}
function child(args, options = {}) {
  return spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024, ...options });
}
const fixture=(name)=>fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
function runFixture(name, args=[]) {
  const p=child([fixture(name), ...args], {timeout: 8500});
  const output=parseChildJson(p);
  return {output, status:p.status, signal:p.signal, stderr:p.stderr?.trim().slice(0,200)};
}

function decodeQName(buf) {
  const labels = [];
  let pos = 12;
  while (pos < buf.length) {
    const len = buf[pos++];
    if (len === 0) break;
    if (len > 63 || pos + len > buf.length) return null;
    labels.push(buf.subarray(pos, pos + len).toString('ascii'));
    pos += len;
  }
  if (pos + 4 > buf.length) return null;
  return { name: labels.join('.'), end: pos + 4 };
}
async function dnsProbe() {
  const cve = 'CVE-2026-105482';
  if (!affected[cve].includes(major)) return record(cve, 'loopback-dns', 'not-applicable', 'Release line not covered');
  const server = createSocket('udp4');
  const queries = [];
  server.on('message', (packet, peer) => {
    const q = decodeQName(packet);
    if (!q) return;
    queries.push(q.name);
    const header = Buffer.alloc(12);
    packet.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2); // standard no-error answer
    header.writeUInt16BE(1, 4); // one question
    header.writeUInt16BE(1, 6); // one answer
    const answer = Buffer.from([0xc0,0x0c, 0,1, 0,1, 0,0,0,5, 0,4, 127,0,0,42]);
    server.send(Buffer.concat([header, packet.subarray(12, q.end), answer]), peer.port, peer.address);
  });
  try {
    await new Promise((ok, fail) => {
      server.once('error', fail);
      server.bind(0, '127.0.0.1', ok);
    });
    const resolver = new dns.Resolver();
    resolver.setServers([`127.0.0.1:${server.address().port}`]);
    const hostile = 'attacker.invalid\0.trusted.invalid';
    let response, error;
    try { response = await resolver.resolve4(hostile); }
    catch (e) { error = e.code || e.message; }
    if (queries.includes('attacker.invalid') && response?.includes('127.0.0.42')) {
      record(cve, 'loopback-dns', 'vulnerable-behavior', 'dns.resolve4 truncated an allowed-suffix string at NUL and queried attacker.invalid');
    } else if (queries.length === 0 && error) {
      record(cve, 'loopback-dns', 'rejected', `Invalid hostname rejected before DNS query (${error})`);
    } else {
      record(cve, 'loopback-dns', 'inconclusive', JSON.stringify({queries, response, error}));
    }
  } catch (e) {
    record(cve, 'loopback-dns', 'inconclusive', String(e));
  } finally {
    await new Promise(resolveClose => server.close(resolveClose));
  }
}
function tlsProbe(cve, host, san) {
  if (!affected[cve].includes(major)) return record(cve, 'tls.checkServerIdentity', 'not-applicable', 'Release line not covered');
  const cert = { subjectaltname: san, subject: {} };
  const canonical = checkServerIdentity('127.0.0.1', { subjectaltname: 'DNS:127.0.0.1', subject: {} });
  if (!canonical || canonical.code !== 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return record(cve, 'tls.checkServerIdentity', 'inconclusive', 'Control failed: canonical IP with DNS-only SAN was not rejected');
  }
  try {
    const error = checkServerIdentity(host, cert);
    record(cve, 'tls.checkServerIdentity', error === undefined ? 'vulnerable-behavior' : 'rejected',
      error === undefined ? `Accepted certificate SAN ${san} for noncanonical host ${host}` :
        `Rejected certificate SAN ${san} for ${host}: ${error.code || error.message}`);
  } catch (e) {
    record(cve, 'tls.checkServerIdentity', 'inconclusive', `Unexpected exception: ${e}`);
  }
}
function parseChildJson(r) {
  if (r.error || r.signal || r.status !== 0) return { failure: `status=${r.status}; signal=${r.signal}; ${r.error?.message || r.stderr?.trim() || ''}` };
  try { return JSON.parse(r.stdout.trim()); }
  catch { return {failure: `Invalid child output: ${r.stdout.slice(0,250)}`}; }
}
function permissionProbe(dir, cve, kind) {
  if (!affected[cve].includes(major)) return record(cve, 'permission-sentinel', 'not-applicable', 'Release line not covered');
  const secret = join(dir, 'confidential');
  const permitted = join(dir, 'confidential.allowed');
  writeFileSync(secret, 'PRIVATE_SENTINEL_ONLY\n');
  writeFileSync(permitted, 'PUBLIC_SENTINEL_ONLY\n');
  const code = kind === 'realpath'
    ? `const fs=require('node:fs'); const p=process.argv[1]; let result;try{result={kind:'returned',value:fs.realpathSync(p)}}catch(e){result={kind:'threw',code:e.code}}console.log(JSON.stringify({allowed:process.permission.has('fs.read',p),...result}))`
    : `const fs=require('node:fs'); const p=process.argv[1]; let result;try{result={kind:'returned',value:fs.readFileSync(p,'utf8')}}catch(e){result={kind:'threw',code:e.code}}console.log(JSON.stringify({allowed:process.permission.has('fs.read',p),...result}))`;
  const grant = kind === 'realpath' ? permitted : `${secret}.*`;
  const r = child(['--permission', `--allow-fs-read=${grant}`, '-e', code, secret]);
  const result = parseChildJson(r);
  if (result.failure) return record(cve, `permission-${kind}`, 'inconclusive', result.failure);
  if (kind === 'realpath') {
    if (result.allowed === false && result.kind === 'returned') {
      record(cve, 'permission-realpath', 'vulnerable-behavior', 'realpathSync returned a disallowed sentinel path');
    } else if (result.allowed === false && result.code === 'ERR_ACCESS_DENIED') {
      record(cve, 'permission-realpath', 'rejected', 'realpathSync denied disallowed sentinel path');
    } else record(cve, 'permission-realpath', 'inconclusive', JSON.stringify(result));
  } else {
    if (result.allowed === true && result.value?.includes('PRIVATE_SENTINEL_ONLY')) {
      record(cve, 'permission-wildcard', 'vulnerable-behavior', 'Wildcard confidential.* unexpectedly granted confidential');
    } else if (result.allowed === false && result.code === 'ERR_ACCESS_DENIED') {
      record(cve, 'permission-wildcard', 'rejected', 'Wildcard correctly denied path shorter than grant');
    } else record(cve, 'permission-wildcard', 'inconclusive', JSON.stringify(result));
  }
}
function snapshotProbe(dir) {
  const cve = 'CVE-2026-106074';
  if (!affected[cve].includes(major)) return record(cve, 'snapshot-entropy', 'not-applicable', 'Release line not covered');
  if (skipSnapshot) return record(cve, 'snapshot-entropy', 'not-run', 'Skipped by --skip-snapshot');
  const source = join(dir, 'snapshot.cjs'), blob = join(dir, 'snapshot.blob');
  writeFileSync(source, `const c=require('node:crypto');
c.randomUUID(); c.randomInt(1000000000);
require('node:v8').startupSnapshot.setDeserializeMainFunction(() => {
 const c=require('node:crypto');
 console.log(JSON.stringify({uuid:c.randomUUID(),integer:c.randomInt(1000000000)}));
});\n`);
  const built = child([`--snapshot-blob=${blob}`, '--build-snapshot', source], {cwd: dir});
  if (built.status !== 0) return record(cve, 'snapshot-entropy', 'inconclusive', `Snapshot build failed: ${built.stderr.trim().slice(0,300)}`);
  const first = parseChildJson(child([`--snapshot-blob=${blob}`], {cwd: dir}));
  const second = parseChildJson(child([`--snapshot-blob=${blob}`], {cwd: dir}));
  if (first.failure || second.failure || !first.uuid || !second.uuid) {
    return record(cve, 'snapshot-entropy', 'inconclusive', JSON.stringify({first, second}));
  }
  if (first.uuid === second.uuid && first.integer === second.integer) {
    record(cve, 'snapshot-entropy', 'vulnerable-behavior', 'Two separately started processes generated identical cached UUID and randomInt');
  } else if (first.uuid !== second.uuid && first.integer !== second.integer) {
    record(cve, 'snapshot-entropy', 'rejected', 'Two processes returned distinct first UUIDs and randomInt values');
  } else {
    record(cve, 'snapshot-entropy', 'inconclusive', 'Only one entropy stream was duplicated; check snapshot implementation');
  }
}
function brotliProbe() {
  const cve='CVE-2026-111497';
  if (!affected[cve].includes(major)) return record(cve,'brotli-invalid-block-switch','not-applicable','Release line not covered');
  const {output,status,signal,stderr}=runFixture('brotli.mjs');
  if(output.failure) return record(cve,'brotli-invalid-block-switch','inconclusive',JSON.stringify({status,signal,stderr,failure:output.failure}));
  const {sync,streaming,exportedConstant}=output;
  const evidence=JSON.stringify({sync,streaming,exportedConstant,
    caveat:'Upstream 22-byte decoder invariant test; does not demonstrate arbitrary OOB writes or RCE'});
  const patched=x=>x?.errno===-17 && x?.code==='ERR__ERROR_FORMAT_BLOCK_SWITCH';
  if(patched(sync)&&patched(streaming)&&exportedConstant===-17) return record(cve,'brotli-invalid-block-switch','rejected',evidence);
  if(sync?.errno===-9&&streaming?.errno===-9) return record(cve,'brotli-invalid-block-switch','vulnerable-behavior',evidence);
  return record(cve,'brotli-invalid-block-switch','inconclusive',evidence);
}
function httpProbe() {
  const cve='CVE-2026-105481';
  if(!affected[cve].includes(major)) return record(cve,'http-agent-reuse','not-applicable','Release line not covered');
  for(const mode of ['free','queued']) {
    const {output,status,signal,stderr}=runFixture('http.mjs',mode==='queued'?['--queued']:[]);
    const probe=`http-agent-${mode}-socket`;
    if(output.failure) {record(cve,probe,'inconclusive',JSON.stringify({status,signal,stderr,failure:output.failure}));continue;}
    const evidence=JSON.stringify({mode,workerWrote:output.workerWrote,
      queuedBeforeReuse:output.queuedBeforeReuse,reusedSocket:output.reusedSocket,first:output.first,second:output.second});
    if(!output.workerWrote || !output.queuedBeforeReuse || output.first?.body!=='/request1') {
      record(cve,probe,'inconclusive',evidence);
    } else if(output.second?.poisoned===true) {
      record(cve,probe,'vulnerable-behavior',evidence);
    } else if(output.second?.body==='/request2' && output.second?.poisoned===false) {
      record(cve,probe,'rejected',evidence);
    } else {
      record(cve,probe,'inconclusive',evidence);
    }
  }
}
function zipProbe(dir) {
  const cve='CVE-2026-106070';
  if(!affected[cve].includes(major)) return record(cve,'zip-header-cache','not-applicable','Only Node 26 affected per advisory');
  const {output,status,signal,stderr}=runFixture('zip.mjs',[join(dir,'mismatched.zip')]);
  if(output.failure || output.supported!==true) return record(cve,'zip-header-cache','inconclusive',JSON.stringify({status,signal,stderr,output}));
  const ops=output.operations;
  const rejection=x=>x?.error==='ERR_ZIP_INVALID_ARCHIVE';
  const paths=['contentAfterModifiedFirst','contentAfterModifiedSecond','directFirst','directSecond',
    'compact','asyncFirst','asyncSecond','asyncIterator','asyncStream','asyncCompact'];
  const leaked=paths.filter(k=>ops[k]?.returned===true && ops[k]?.content?.includes('SCANNER-SEES-BENIGN!!'));
  const failed=paths.filter(k=>!rejection(ops[k]));
  const evidence=JSON.stringify({fixture:output.fixture,operations:ops,leaked,nonRejecting:failed,
    caveat:'Only built-in node:zlib.ZipFile is tested; not third-party ZIP readers'});
  if(leaked.length) return record(cve,'zip-header-cache','vulnerable-behavior',evidence);
  if(failed.length===0) return record(cve,'zip-header-cache','rejected',evidence);
  return record(cve,'zip-header-cache','inconclusive',evidence);
}
const patterns = {
  'CVE-2026-105482': [/\bdns\.(?:promises\.)?(?:resolve\w*|reverse)\b/, /\b(?:resolve4|resolve6|resolveMx|reverse)\s*\(/],
  'CVE-2026-105483': [/checkServerIdentity|servername|rejectUnauthorized/],
  'CVE-2026-106069': [/checkServerIdentity|servername|rejectUnauthorized/],
  'CVE-2026-111497': [/\b(?:brotliDecompress(?:Sync)?|createBrotliDecompress|BrotliDecompress)\b/, /\bContent-Encoding\b|\bbr\b/],
  'CVE-2026-105481': [/\b(?:https?\.Agent|keepAlive|setGlobalDispatcher|undici|fetch\s*\()/],
  'CVE-2026-106072': [/checkServerIdentity|servername|rejectUnauthorized/],
  'CVE-2026-106074': [/\b(?:randomUUIDv7|randomUUID|randomInt|createObjectURL|build-snapshot|useSnapshot)\b/],
  'CVE-2026-106070': [/\bZipFile\b|\.compact\s*\(/],
  'CVE-2026-106071': [/allow-fs-read|allow-fs-write|\-\-permission/],
  'CVE-2026-106073': [/realpathSync|\-\-permission/],
};
function scanSource(root) {
  const skip = new Set(['.git','node_modules','.next','.nuxt','.turbo','dist','build','coverage','.output','.cache','.pnpm-store']);
  const allowed = new Set(['.js','.mjs','.cjs','.jsx','.ts','.tsx','.json','.yaml','.yml','.sh','.mts','.cts']);
  const matches = {};
  let filesScanned = 0, truncated = false;
  const stack = [resolve(root)];
  while (stack.length && filesScanned < 20000) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, {withFileTypes: true}); }
    catch { continue; }
    for (const item of entries) {
      if (item.isSymbolicLink() || item.name.startsWith('.env')) continue;
      const file = join(dir, item.name);
      if (item.isDirectory()) { if (!skip.has(item.name)) stack.push(file); continue; }
      if (!item.isFile() || !(allowed.has(extname(item.name)) || /^(Dockerfile|Containerfile)(\..*)?$/.test(item.name))) continue;
      try { if (statSync(file).size > 500000) continue; }
      catch { continue; }
      filesScanned++;
      const lines = readFileSync(file, 'utf8').split(/\r?\n/);
      for (let i=0; i<lines.length; i++) for (const [cve, tests] of Object.entries(patterns)) {
        if (tests.some(re => re.test(lines[i])) && (matches[cve]?.length || 0) < 20) {
          (matches[cve] ||= []).push(`${file}:${i+1}`);
        }
      }
    }
  }
  truncated = stack.length > 0;
  return {root: resolve(root), filesScanned, truncated, matches,
    warning: 'Keyword hits are review hints, NOT proof of application exposure. No hits are NOT proof of safety; dependencies, dynamic imports and built artifacts are omitted.'};
}
async function main() {
  await dnsProbe();
  tlsProbe('CVE-2026-105483', '１２７.0.0.1', 'DNS:127.0.0.1');
  tlsProbe('CVE-2026-106069', '0127.0.0.1', 'IP Address:87.0.0.1');
  tlsProbe('CVE-2026-106072', '0177.0.0.1', 'DNS:127.0.0.1');
  const dir = mkdtempSync(join(tmpdir(), 'node-2026-cve-'));
  try {
    permissionProbe(dir, 'CVE-2026-106071', 'wildcard');
    permissionProbe(dir, 'CVE-2026-106073', 'realpath');
    snapshotProbe(dir);
    brotliProbe();
    httpProbe();
    zipProbe(dir);
  } finally { rmSync(dir, {recursive:true,force:true}); }
  const sourceScan = scanRootArg ? scanSource(scanRootArg.split('=').slice(1).join('=')) : null;
  const summary = {node:version, execPath:process.execPath, platform:process.platform, arch:process.arch,
    advisory:'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    patchBaseline:minimums[major] || null,
    versionStatus:minimums[major] ? (compare(version,minimums[major]) >= 0 ? 'meets-october-security-baseline' : 'below-october-security-baseline') : 'unassessed-runtime-line',
    checks, sourceScan,
    caveat:'Run on isolated test binaries. Pass/fail is scoped to these probes, not an app security attestation; version is the primary runtime remediation signal.'};
  if (json) console.log(JSON.stringify(summary,null,2));
  else {
    console.log(`Node ${version} (${process.platform}/${process.arch}), security baseline ${summary.patchBaseline || 'unsupported line'}: ${summary.versionStatus}`);
    for (const {cve,probe,outcome,evidence} of checks) console.log(`${outcome.padEnd(20)} ${cve} ${probe}: ${typeof evidence === 'string' ? evidence : JSON.stringify(evidence)}`);
    if (sourceScan) { console.log(`\nSource review hints (${sourceScan.filesScanned} files):`); for (const [cve,loc] of Object.entries(sourceScan.matches)) console.log(`${cve}: ${loc.slice(0,5).join(', ')}${loc.length>5?' ...':''}`); }
    console.log('\nA rejected probe is not proof a different Node build is patched; confirm version and application exposure.');
  }
  if (checks.some(c=>c.outcome === 'vulnerable-behavior')) process.exitCode=2;
}
main().catch(e=> { console.error(e); process.exitCode=1; });
