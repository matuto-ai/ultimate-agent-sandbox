"""Bounded Git protocol-v0 advertised source identities, never local claims.

The external SSH owner supplies these bytes before forwarding them.  No ref,
packfile, path or command from a Workstation enters this parser.  An advertised
SHA plus a separately hash-verified commit supplies an anchor; an arbitrary
local SHA or editable cherry-pick trailer does not.
"""
import re

_OID = re.compile(rb'[0-9a-f]{40}\Z')
_REF = re.compile(rb'(?:HEAD|refs/[A-Za-z0-9_./+@{}^~-]{1,1000})\Z')


class AdvertisedRefs:
    def __init__(self):
        self.buffer = bytearray()
        self.bytes_seen = 0
        self.oids = set()
        self.refs = set()
        self.complete = False
        self.valid = True

    def feed(self, block):
        if self.complete or not self.valid: return
        if type(block) is not bytes:
            self.valid = False; return
        self.bytes_seen += len(block)
        # Only retain the bounded advertisement, never the subsequent pack.
        self.buffer.extend(block[:65537 - len(self.buffer)])
        while len(self.buffer) >= 4 and self.valid and not self.complete:
            header = bytes(self.buffer[:4])
            if not re.fullmatch(rb'[0-9a-fA-F]{4}', header):
                self.valid = False; break
            size = int(header, 16)
            if size == 0:
                del self.buffer[:4]
                self.complete = True
                break
            if not 4 < size <= 65520:
                self.valid = False; break
            if len(self.buffer) < size: break
            payload = bytes(self.buffer[4:size]); del self.buffer[:size]
            # Protocol-v1 advert prefix is supported; protocol-v2 must not be
            # negotiated because the fixed external SSH omits GIT_PROTOCOL.
            if payload == b'version 1\n' and not self.refs: continue
            first, separator, capabilities = payload.partition(b'\0')
            if separator and self.refs:
                self.valid = False; break
            line = first.rstrip(b'\n')
            if line.endswith(b'\r') or line.count(b' ') != 1:
                self.valid = False; break
            oid, ref = line.split(b' ', 1)
            if oid == b'0' * 40 and ref == b'capabilities^{}' and not self.refs:
                self.refs.add(ref); continue
            if (not _OID.fullmatch(oid) or oid == b'0' * 40 or not _REF.fullmatch(ref)
                    or b'..' in ref or b'//' in ref or ref.startswith(b'refs/.')
                    or ref in self.refs or len(self.refs) >= 2048):
                self.valid = False; break
            self.refs.add(ref); self.oids.add(oid.decode('ascii'))
        if not self.complete and (self.bytes_seen > 65536 or len(self.buffer) > 65536):
            self.valid = False
        if self.complete or not self.valid:
            self.buffer.clear()

    def result(self, *, transport_succeeded):
        if transport_succeeded is not True or not self.complete or not self.valid:
            return ()
        return tuple(sorted(self.oids))
