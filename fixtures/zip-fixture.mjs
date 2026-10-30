#!/usr/bin/env node
// Generates a fully local ZIP fixture derived from the upstream regression
// nodejs/node commit 745ad77156. No external packages or untrusted files.
import { crc32 } from 'node:zlib';
import { writeFileSync } from 'node:fs';

export function createZipMismatch(path) {
  const decoy=Buffer.from('SCANNER-SEES-BENIGN!!');
  const payload=Buffer.from('UNZIP-SEES-PAYLOAD!!!');
  const name=Buffer.from('entry.txt');
  if (decoy.length !== payload.length) throw Error('fixture contents must have equal length');
  // Local header CRC describes the actual content. Central directory CRC is
  // deliberately inconsistent and describes the initial decoy prefix instead.
  const local=Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50,0);
  local.writeUInt16LE(20,4);                    // needed version
  local.writeUInt16LE(0,6);                     // flags
  local.writeUInt16LE(0,8);                     // STORE
  local.writeUInt32LE(crc32(payload)>>>0,14);
  local.writeUInt32LE(payload.length,18);
  local.writeUInt32LE(payload.length,22);
  local.writeUInt16LE(name.length,26);

  const central=Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50,0);
  central.writeUInt16LE(20,4);                   // made by
  central.writeUInt16LE(20,6);                   // needed version
  central.writeUInt16LE(0,10);                   // STORE
  central.writeUInt32LE(crc32(decoy)>>>0,16);    // inconsistent CRC (key to repro)
  central.writeUInt32LE(payload.length,20);
  central.writeUInt32LE(payload.length,24);
  central.writeUInt16LE(name.length,28);
  central.writeUInt32LE(decoy.length,42);        // local header starts after prefix

  const centralPos=decoy.length+local.length+name.length+payload.length;
  const eocd=Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50,0);
  eocd.writeUInt16LE(1,8); eocd.writeUInt16LE(1,10);
  eocd.writeUInt32LE(central.length+name.length,12);
  eocd.writeUInt32LE(centralPos,16);
  writeFileSync(path, Buffer.concat([decoy,local,name,payload,central,name,eocd]));
  return {file:path,entry:'entry.txt',decoy:decoy.toString(),payload:payload.toString(),bytes:centralPos+central.length+name.length+eocd.length};
}
