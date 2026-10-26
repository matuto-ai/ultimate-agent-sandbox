// A test instrumentation guard, NOT an OS security boundary.
// Loaded before the libraries: accidental known Node network paths fail closed.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
export const networkAttempts = [];
const deny = (...args) => {
  networkAttempts.push('network API invoked');
  throw new Error('Network is forbidden in this account-free native fixture');
};
globalThis.fetch = deny;
http.request = http.get = https.request = https.get = deny;
net.connect = net.createConnection = tls.connect = deny;
net.Socket.prototype.connect = deny;
syncBuiltinESMExports();
