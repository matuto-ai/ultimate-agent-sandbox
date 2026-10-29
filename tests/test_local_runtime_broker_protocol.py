"""Real Broker/client wire compatibility on deterministic queue/kernel doubles.

Replay server-generated packets through the actual client; compare every client
packet with the server's consumed transcript. No sockets, threads, subprocesses,
credentials or provider calls. Idle time is simulated by one-second timeouts.
"""
from collections import deque
from dataclasses import asdict
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from uas import forge_read_service as wire
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas import local_native_run_session as runtime


IDLE=object()


class Record:
    def __init__(self,data,credentials):
        self.data=data;self.credentials=credentials;self.pidfd=42
    def __enter__(self):return self
    def __exit__(self,*_):return False


class KernelOrigin:
    def __init__(self,record):
        self.credentials=record.credentials;self.pidfd=record.pidfd;self.closed=False
    def require(self,record):
        if self.closed or record.credentials!=self.credentials:
            raise AssertionError('test kernel identity mismatch')
    def close(self):self.closed=True


class QueueChannel:
    def __init__(self,packets,credentials):
        self.pending=deque(packets);self.credentials=credentials
        self.sent=[];self.received=[];self.timeouts=[];self.idle_seconds=0;self.closed=False
    def settimeout(self,value):self.timeout=value;self.timeouts.append(value)
    def send(self,raw):self.sent.append(raw);return len(raw)
    def receive(self):
        value=self.pending.popleft()
        if value is IDLE:
            if self.timeout!=1:raise AssertionError('idle wait reused finite bootstrap/request timeout')
            self.idle_seconds+=1;raise socket.timeout()
        self.received.append(value)
        return Record(value,self.credentials)
    def close(self):self.closed=True


class LocalRuntimeBrokerProtocolTests(unittest.TestCase):
    def test_one_real_hello_then_two_real_operations_across_long_idle(self):
        binding=ForgeBinding('alpha','project','owner/repo')
        scope={**asdict(binding),'room_instance':'instance'}
        nonce,first,second='a'*32,'b'*32,'c'*32
        hello=wire._json({'kind':'READ_BROKER_HELLO','nonce':nonce,'binding':scope}).encode()
        requests=[wire.request_json({'request_id':identifier,'room_id':'alpha',
                    'room_instance':'instance','denial':code}).encode()
                  for identifier,code in ((first,'FORBIDDEN'),(second,'ROOM_NOT_RUNNING'))]
        server=QueueChannel([hello]+[IDLE]*50+[requests[0]]+[IDLE]*50+[requests[1]],(100,165533,165533))
        def no_provider(_actor):raise AssertionError('denial must not contact a provider')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with ForgeAudit(root/'audit.db','deployment') as audit:
                broker=ExternalReadBroker(binding,'instance',audit,no_provider,root/'results')
                # Both protocol implementations below are real. Only transport
                # and unavailable kernel-origin observations are substituted.
                with patch.object(wire,'enable'),patch.object(wire,'HeldOrigin',KernelOrigin),\
                     patch.object(wire,'receive',side_effect=lambda channel:channel.receive()),\
                     patch.object(wire,'alive',side_effect=lambda _fd:bool(server.pending)):
                    wire.serve(server,broker,supervisor_uid=165533,supervisor_gid=165533)
                with sqlite3.connect(root/'audit.db') as database:
                    self.assertEqual(database.execute('SELECT count(*) FROM read_starts').fetchone()[0],2)
            self.assertEqual(server.idle_seconds,100)
            self.assertEqual(server.timeouts.count(45),3)  # bootstrap + two requests, not idle
            self.assertTrue(server.closed)
            client_channel=QueueChannel(server.sent,(200,165534,165534))
            identities=[SimpleNamespace(hex=value) for value in (nonce,first,second)]
            owner=object.__new__(runtime.LocalNativeRunSession)
            owner.plan=SimpleNamespace(room={'id':'alpha','project':{'id':'project','repository':'owner/repo'}})
            owner.resources={'instance':'instance'};owner.supervisor=SimpleNamespace(room_id='alpha')
            owner._thread=threading.get_ident();owner._broker_attempted=False
            owner._broker=owner._git_broker=None;owner.broker_fd=7;owner.git_fd=None
            with patch.object(wire,'enable'),patch.object(wire,'HeldOrigin',KernelOrigin),\
                 patch.object(wire,'receive',side_effect=lambda channel:channel.receive()),\
                 patch.object(wire.uuid,'uuid4',side_effect=identities),\
                 patch.object(runtime.os,'dup',return_value=8),\
                 patch.object(runtime.socket,'socket',return_value=client_channel) as channel_factory,\
                 patch.object(owner,'current'):
                # Invoke the actual persistent owner method, not a fake client.
                # current()'s host/kernel checks are outside this wire test.
                client,git=owner.clients()
                self.assertIs(type(client),wire.ReadBrokerClient);self.assertIsNone(git)
                self.assertEqual(len(client_channel.sent),1)  # startup, before any Run operation
                client.denied('FORBIDDEN')
                self.assertFalse(client.closed)
                second_client,git=owner.clients()
                self.assertIs(second_client,client);channel_factory.assert_called_once()
                second_client.denied('ROOM_NOT_RUNNING')
                self.assertEqual(client_channel.sent,server.received)
                self.assertEqual(sum(json.loads(packet).get('kind')=='READ_BROKER_HELLO'
                                     for packet in client_channel.sent),1)
                self.assertFalse(client_channel.pending)
                owner.close()
            self.assertTrue(client_channel.closed)
