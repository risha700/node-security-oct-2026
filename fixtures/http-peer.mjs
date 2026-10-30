#!/usr/bin/env node
// Deliberately unsolicited response is sent only over a loopback socket.
import http from 'node:http';
import { parentPort, workerData } from 'node:worker_threads';
const shared=new Int32Array(workerData.shared);
const sockets=new Set();
let firstSocket;
const server=http.createServer((req,res)=>{
  firstSocket ??= req.socket;
  res.setHeader('X-Local-Fixture','yes');
  res.end(req.url);
});
server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
server.listen(0,'127.0.0.1',()=>parentPort.postMessage({port:server.address().port}));
parentPort.on('message', msg=>{
  if(msg.op==='poison'){
    if(!firstSocket||firstSocket.destroyed){Atomics.store(shared,0,-1);Atomics.notify(shared,0);return;}
    // The newline-terminated HTTP message is not linked to any request.
    firstSocket.write('HTTP/1.1 200 OK\r\nX-Poisoned: true\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n',()=>{
      Atomics.store(shared,0,1);
      Atomics.notify(shared,0);
    });
  }
  if(msg.op==='stop'){
    for(const socket of sockets) socket.destroy();
    server.close(()=>process.exit(0));
  }
});
