#!/usr/bin/env node
// Node.js regression scenario from 0683ee5f7d, adapted to a worker-thread
// loopback server. The worker writes unexpected bytes while the test thread
// blocks, so the Agent cannot poll for data between the write and socket reuse.
import http from 'node:http';
import { Worker } from 'node:worker_threads';

const mode=process.argv.includes('--queued')?'queued':'free';
const state=new Int32Array(new SharedArrayBuffer(4));
const peer=new Worker(new URL('./http-peer.mjs',import.meta.url),{workerData:{shared:state.buffer}});
const ready=await new Promise((resolve,reject)=>{
  peer.once('message',m=>resolve(m)); peer.once('error',reject);
});
const agent=new http.Agent({keepAlive:true,maxSockets:1});
const endpoint={host:'127.0.0.1',port:ready.port,agent};
const results={fixture:'loopback-unsolicited-response',mode,workerWrote:false,queuedBeforeReuse:false,
 reusedSocket:null,second:{},first:{}};
const response=(req,cb)=>{
 req.once('response',res=>{
  let body='';res.setEncoding('utf8');
  res.on('data',chunk=>body+=chunk);
  res.once('end',()=>cb(null,{status:res.statusCode,body,poisoned:res.headers['x-poisoned']==='true'}));
 });
 req.once('error',err=>cb({code:err.code,message:err.message}));
};
const poison=()=>{
  Atomics.store(state,0,0);
  peer.postMessage({op:'poison'});
  const waited=Atomics.wait(state,0,0,2000);
  results.workerWrote=Atomics.load(state,0)===1;
  results.queuedBeforeReuse=waited==='ok'&&results.workerWrote;
  return results.workerWrote;
};
try {
 await new Promise((resolve)=>{
   let done=false;
   const finish=out=>{if(done)return;done=true;results.second=out;resolve();};
   const req1=http.request({...endpoint,path:'/request1'});
   if(mode==='free'){
     response(req1,(e,v)=>{results.first=e||v;});
     req1.on('close',()=>process.nextTick(()=>{
       const name=agent.getName(endpoint);
       const freeSocket=agent.freeSockets[name]?.[0];
       if(!freeSocket){finish({inconclusive:'first socket not in agent free pool'});return;}
       if(!poison()){finish({inconclusive:'worker failed to write bytes before reuse'});return;}
       // Same turn: no event loop polling between unexpected bytes and reuse.
       const req2=http.request({...endpoint,path:'/request2'});
       req2.once('socket',()=>{results.reusedSocket=req2.reusedSocket;});
       response(req2,(e,v)=>{results.reusedSocket=req2.reusedSocket;finish(e?{error:e}:v);});
       req2.end();
     }));
     req1.end();
   } else {
     response(req1,(e,v)=>{
       results.first=e||v;
       // The queued request will be assigned to this socket on next tick.
       if(!poison()) finish({inconclusive:'worker failed to write bytes before queued reuse'});
     });
     req1.end();
     const req2=http.request({...endpoint,path:'/request2'});
     response(req2,(e,v)=>{results.reusedSocket=req2.reusedSocket;finish(e?{error:e}:v);});
     req2.end();
   }
   setTimeout(()=>finish({inconclusive:'HTTP fixture timed out'}),4500).unref();
 });
} finally {
 agent.destroy(); peer.postMessage({op:'stop'});
}
console.log(JSON.stringify(results));
