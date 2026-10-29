"""Hosted-only actual Node/FD routing; fake SDK registry, no model/auth/network.

This does not execute native Pi, a C bootstrap, Docker or a provider. It tests the
fixed extension's tool transport with two real owned seqpacket connections.
"""
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=r'''
import extension from './runtime/pi/extension.mjs';
import {deepStrictEqual} from 'node:assert';
import {TOOLS} from './runtime/claude/mcp-tools.mjs';
const tools=new Map(),events=new Map();
extension({registerTool:t=>tools.set(t.name,t),registerCommand:()=>{},on:(n,f)=>events.set(n,f)});
const gh=await tools.get('gh').execute('tool',{id:'stable-forge',argv:['pr','view','1']});
if(gh.isError)throw Error('unexpected-gh-error');
const peer=await tools.get('uas_peer').execute('tool',{id:'stable-peer',kind:'message',run_id:'run',generation:1,payload:{}});
if(peer.isError)throw Error('unexpected-peer-error');
const run=await tools.get('uas_run').execute('tool',{id:'stable-run',kind:'run-propose',payload:{}});
if(run.isError)throw Error('unexpected-run-error');
deepStrictEqual(tools.get('uas_review').parameters,TOOLS.find(x=>x.name==='uas_review').inputSchema);
const submission={id:'stable-submit',kind:'submit-for-review',run_id:'run',generation:1,
  payload:{target:{head_sha:'a'.repeat(40)},evidence:['evidence:test']},observation_id:'observation'};
const submitted=await tools.get('uas_review').execute('tool',submission);
if(submitted.isError)throw Error('unexpected-submission-error');
const review={id:'stable-review',kind:'review-result',run_id:'run',generation:1,
  payload:{verdict:'pass',evidence:['evidence:test']}};
const deniedReview=await tools.get('uas_review').execute('tool',review);
if(!deniedReview.isError)throw Error('Hub-review-denial-hidden');
for(const invalid of [null,[],{...review,kind:'approve-merge'},{...review,actor_id:'forged'},
    {...review,id:'bad id'},{...review,generation:true},{...review,payload:[]},
    {...review,observation_id:'bad id'},{...review,payload:{oversize:'x'.repeat(65536)}}]){
  let rejected=false;try{await tools.get('uas_review').execute('tool',invalid);}catch{rejected=true;}
  if(!rejected)throw Error('invalid-review-crossed-boundary');
}

let denied=false;
try{await tools.get('gh').execute('large',{id:'oversize',argv:['pr','comment','1','--body-file','-'],body:'x'.repeat(65536)});}catch{denied=true;}
if(!denied)throw Error('oversize-accepted');
events.get('session_shutdown')();
console.log('direct-pi-routing-ok');
'''
SHIM='import os,sys,fcntl; a=fcntl.fcntl(int(sys.argv[1]),fcntl.F_DUPFD_CLOEXEC,10); b=fcntl.fcntl(int(sys.argv[2]),fcntl.F_DUPFD_CLOEXEC,10); os.dup2(a,3); os.dup2(b,4); os.close(a); os.close(b); [os.close(fd) for fd in (int(sys.argv[1]),int(sys.argv[2])) if fd not in (3,4)]; os.set_inheritable(3,True); os.set_inheritable(4,True); os.set_blocking(3,False); os.set_blocking(4,False); os.execve(sys.argv[3],[sys.argv[3],"--input-type=module","-e",sys.argv[4]],{"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","UAS_PI_NATIVE":"1","UAS_PI_PEER_FD":"3","UAS_PI_FORGE_FD":"4"})'

class NativePiForgeTransportTests(unittest.TestCase):
    def test_native_extension_routes_forge_only_to_private_fd4(self):
        node=shutil.which('node');self.assertIsNotNone(node,'hosted Node required')
        peer,peer_child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        forge,forge_child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        peer.settimeout(2);forge.settimeout(2);process=None
        try:
            process=subprocess.Popen([sys.executable,'-c',SHIM,str(peer_child.fileno()),str(forge_child.fileno()),node,SCRIPT],
                pass_fds=(peer_child.fileno(),forge_child.fileno()),cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            peer_child.close();forge_child.close()
            frame=json.loads(forge.recv(65537))
            self.assertEqual(frame['envelope'],{'id':'stable-forge','kind':'forge-read','argv':['pr','view','1']})
            self.assertEqual(select.select([peer],[],[],0)[0],[],'Forge cannot arrive at Hub')
            forge.sendall(json.dumps({'request_id':frame['request_id'],'ok':True,'receipt':{'observation':{'completeness':'complete'}}}).encode())
            packet=json.loads(peer.recv(65537));self.assertEqual(packet['envelope']['id'],'stable-peer')
            self.assertEqual(select.select([forge],[],[],0)[0],[],'peer traffic cannot arrive at Forge')
            peer.sendall(json.dumps({'request_id':packet['request_id'],'ok':True,'receipt':{}}).encode())
            run=json.loads(peer.recv(65537));self.assertEqual(run['envelope'],{'id':'stable-run','kind':'run-propose','payload':{}})
            self.assertEqual(select.select([forge],[],[],0)[0],[],'Run proposal must stay on Hub channel')
            peer.sendall(json.dumps({'request_id':run['request_id'],'ok':True,'receipt':{}}).encode())
            submit=json.loads(forge.recv(65537))
            self.assertEqual(submit['envelope'],{'id':'stable-submit','kind':'submit-for-review','run_id':'run','generation':1,
                'payload':{'target':{'head_sha':'a'*40},'evidence':['evidence:test']},'observation_id':'observation'})
            self.assertEqual(select.select([peer],[],[],0)[0],[],'review submission uses trusted host')
            forge.sendall(json.dumps({'request_id':submit['request_id'],'ok':True,'receipt':{'stage':'REVIEWING'}}).encode())
            review=json.loads(forge.recv(65537));self.assertEqual(review['envelope'],{'id':'stable-review','kind':'review-result',
                'run_id':'run','generation':1,'payload':{'verdict':'pass','evidence':['evidence:test']}})
            self.assertEqual(select.select([peer],[],[],0)[0],[],'review verdict uses trusted host')
            forge.sendall(json.dumps({'request_id':review['request_id'],'ok':False,'error':'REVIEWER_NOT_INDEPENDENT'}).encode())
            stdout,stderr=process.communicate(timeout=3)
            self.assertEqual(process.returncode,0,stderr.decode());self.assertEqual(stdout,b'direct-pi-routing-ok\n')
            # Oversize failed before either record; shutdown closed both FDs.
            self.assertEqual(peer.recv(65537),b'');self.assertEqual(forge.recv(65537),b'')
        finally:
            peer.close();peer_child.close();forge.close();forge_child.close()
            if process is not None:
                if process.poll() is None:process.kill();process.wait(timeout=2)
                for stream in (process.stdout,process.stderr):
                    if stream is not None:stream.close()

    def test_native_mode_missing_fd_selection_never_falls_back_to_hub(self):
        node=shutil.which('node');self.assertIsNotNone(node)
        script="import extension from './runtime/pi/extension.mjs'; let registered=false; try{extension({registerTool:()=>{registered=true;},registerCommand:()=>{},on:()=>{}});process.exit(2);}catch{if(registered)process.exit(3);}"
        result=subprocess.run([node,'--input-type=module','-e',script],cwd=ROOT,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','UAS_PI_NATIVE':'1','UAS_PI_PEER_FD':'3'},
            capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr.decode())
