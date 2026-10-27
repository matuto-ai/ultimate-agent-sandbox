"""Hosted account-free real Node/seqpacket transport, not native Claude evidence.

No SDK, model, npm/network, credentials or C bootstrap exec. Fixed /opt native
payload paths are deliberately not redirected to test executables.
"""
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

class NativeClaudeTransportTests(unittest.TestCase):
    def test_real_stdio_activation_request_reply_and_cleanup(self):
        node=shutil.which('node')
        self.assertIsNotNone(node,'hosted Node runtime is required, not a skipped test')
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        parent.settimeout(2)
        # Fixed FD3 handoff in an owned child. No preexec callback in a threaded
        # test runner; the shim execs only the selected local Node and fixed file.
        shim='import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3); os.close(fd) if fd!=3 else None; os.set_inheritable(3,True); os.set_blocking(3,False); os.execve(sys.argv[2],[sys.argv[2],sys.argv[3]],{"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})'
        process=None; buffer=bytearray(); deadline=time.monotonic()+7
        try:
            process=subprocess.Popen([sys.executable,'-c',shim,str(child.fileno()),node,
                str(ROOT/'runtime/claude/mcp-server.mjs')],pass_fds=(child.fileno(),),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT)
            child.close()
            os.set_blocking(process.stdin.fileno(),False)
            def send(value):
                wire=(json.dumps(value)+'\n').encode(); offset=0
                while offset<len(wire):
                    remaining=deadline-time.monotonic(); self.assertGreater(remaining,0)
                    _,writable,_=select.select([],[process.stdin],[],remaining)
                    self.assertTrue(writable,'bounded MCP input deadline')
                    try: count=os.write(process.stdin.fileno(),wire[offset:])
                    except BlockingIOError: continue
                    self.assertGreater(count,0); offset+=count
            def reply():
                nonlocal buffer
                while b'\n' not in buffer:
                    wait=min(2,deadline-time.monotonic()); self.assertGreater(wait,0)
                    ready,_,_=select.select([process.stdout],[],[],wait)
                    self.assertTrue(ready,'bounded MCP response deadline')
                    chunk=os.read(process.stdout.fileno(),262144)
                    self.assertTrue(chunk,'MCP process exited before response'); buffer.extend(chunk)
                    self.assertLessEqual(len(buffer),1114112)
                row,_,buffer=buffer.partition(b'\n'); return json.loads(row)
            send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'controlled-test','version':'1'}}})
            self.assertEqual(reply()['result']['protocolVersion'],'2025-11-25')
            send({'jsonrpc':'2.0','method':'notifications/initialized'})
            send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            self.assertEqual({x['name'] for x in reply()['result']['tools']},{'uas_peer','uas_review','gh'})
            payload={'id':'peer-operation','run_id':'run','generation':1,'kind':'message','payload':{}}
            request={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'uas_peer','arguments':payload}}
            send(request); self.assertIn('error',reply())
            self.assertEqual(select.select([parent],[],[],0)[0],[],'pre-admission call must not reach owner')
            parent.sendall(b'UAS-HELPER-ACTIVE-1\n')
            # An explicit pre-admission refusal is known-no-effect, not an
            # uncertain request. Retry only those refusals with stable op ID.
            frame=None
            for attempt in range(20):
                request['id']=4+attempt; send(request)
                readable,_,_=select.select([parent,process.stdout],[],[],min(2,deadline-time.monotonic()))
                self.assertTrue(readable)
                if parent in readable:
                    frame=json.loads(parent.recv(65537)); break
                refused=reply()
                self.assertEqual(refused.get('error',{}).get('message'),'native helper not admitted')
                self.assertEqual(select.select([parent],[],[],0)[0],[])
                time.sleep(.01)
            self.assertIsNotNone(frame,'bounded helper activation wait')
            self.assertEqual(set(frame),{'request_id','envelope'})
            self.assertEqual(frame['envelope'],payload); self.assertEqual(len(frame['request_id']),32)
            parent.sendall(json.dumps({'request_id':frame['request_id'],'ok':True,'receipt':{'stored':'controlled'}}).encode())
            result=reply()['result']; self.assertFalse(result['isError'])
            self.assertEqual(json.loads(result['content'][0]['text'])['receipt'],{'stored':'controlled'})
            # Oversized writes fail before even the first channel packet.
            send({'jsonrpc':'2.0','id':100,'method':'tools/call','params':{'name':'gh','arguments':{
                'id':'large','argv':['pr','comment','1','--body-file','-'],'body':'x'*65536}}})
            self.assertIn('error',reply()); self.assertEqual(select.select([parent],[],[],0)[0],[])
            process.stdin.close(); process.wait(timeout=min(2,max(.001,deadline-time.monotonic())))
            self.assertEqual(parent.recv(1),b'','stdio EOF must close the inherited channel')
        finally:
            child.close(); parent.close()
            if process is not None:
                if process.poll() is None: process.kill(); process.wait(timeout=2)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream is not None: stream.close()

    def test_wrong_or_extra_activation_record_closes_without_effect(self):
        node=shutil.which('node'); self.assertIsNotNone(node)
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET); parent.settimeout(2)
        shim='import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3); os.close(fd) if fd!=3 else None; os.set_inheritable(3,True); os.set_blocking(3,False); os.execve(sys.argv[2],[sys.argv[2],sys.argv[3]],{"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})'
        process=None
        try:
            process=subprocess.Popen([sys.executable,'-c',shim,str(child.fileno()),node,
                str(ROOT/'runtime/claude/mcp-server.mjs')],pass_fds=(child.fileno(),),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT)
            child.close(); parent.sendall(b'UAS-HELPER-ACTIVE-1\nextra')
            process.wait(timeout=2)
            self.assertEqual(process.returncode,1)
            self.assertEqual(parent.recv(65537),b'','malformed activation cannot emit a request')
        finally:
            child.close(); parent.close()
            if process is not None:
                if process.poll() is None: process.kill(); process.wait(timeout=2)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream is not None: stream.close()
