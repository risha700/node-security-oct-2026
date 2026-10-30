#!/usr/bin/env node
import {ZipFile} from 'node:zlib';
import {createZipMismatch} from './zip-fixture.mjs';
import {resolve} from 'node:path';

if (typeof ZipFile?.openSync !== 'function') {
 console.log(JSON.stringify({supported:false, reason:'node:zlib.ZipFile unavailable in this runtime'}));
 process.exit(0);
}
const fixture = createZipMismatch(resolve(process.argv[2]));
const out={supported:true, fixture:{...fixture,file:'<temporary fixture>'}, operations:{}};
const resultValue=val=>({returned:true,content:Buffer.isBuffer(val)||val instanceof Uint8Array?Buffer.from(val).toString('utf8'):String(val)});
const capture=fn=>{try{return resultValue(fn());}catch(e){return {error:e.code??e.name,message:e.message?.slice(0,120)}}};
const captureAsync=async fn=>{try{return resultValue(await fn());}catch(e){return {error:e.code??e.name,message:e.message?.slice(0,120)}}};
// If validation fails, *every* subsequent content access must fail.
for(const path of ['after-modified','direct','compact']){
  const zip=ZipFile.openSync(fixture.file);
  try {
    const entry=zip.getSync(fixture.entry);
    if(path==='after-modified'){
      out.operations.modified=capture(()=>entry.modified instanceof Date);
      out.operations.contentAfterModifiedFirst=capture(()=>entry.contentSync());
      out.operations.contentAfterModifiedSecond=capture(()=>entry.contentSync());
    }else if(path==='direct'){
      out.operations.directFirst=capture(()=>entry.contentSync());
      out.operations.directSecond=capture(()=>entry.contentSync());
    }else{
      out.operations.compact=capture(()=>zip.compactSync());
    }
  }finally{zip.closeSync();}
}
// Exercise async reads/iterators and compaction as well; all paths must reject.
{
 const zip=await ZipFile.open(fixture.file);
 try{
   const entry=await zip.get(fixture.entry);
   out.operations.asyncModified=capture(()=>entry.modified instanceof Date);
   out.operations.asyncFirst=await captureAsync(()=>entry.content());
   out.operations.asyncSecond=await captureAsync(()=>entry.content());
   out.operations.asyncIterator=await captureAsync(async()=>{
     const chunks=[];
     for await(const chunk of entry.contentIterator()) chunks.push(chunk);
     return Buffer.concat(chunks);
   });
   out.operations.asyncStream=await captureAsync(async()=>{
     const chunks=[];
     for await(const chunk of await zip.stream(fixture.entry)) chunks.push(chunk);
     return Buffer.concat(chunks);
   });
 }finally{await zip.close();}
}
{
 const zip=await ZipFile.open(fixture.file);
 try{
   out.operations.asyncCompact=await captureAsync(async()=>{
     const chunks=[];
     for await(const chunk of zip.compact()) chunks.push(chunk);
     return Buffer.concat(chunks);
   });
 }finally{await zip.close();}
}
console.log(JSON.stringify(out));
