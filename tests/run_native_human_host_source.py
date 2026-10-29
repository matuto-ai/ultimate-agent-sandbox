#!/usr/bin/env python3
"""Finite source-only consumed native human hosting checks, never native/runtime qualification.

The guard is installed before importing either repository test module. Every
attempt is recorded, including a call caught by code under test; zero attempts
is mandatory. This is an accidental-effect guard, not an adversarial sandbox.
No discovery, subprocess test launcher, compiler, SDK process or socket is used.
"""
import _socket
import _thread
import _ctypes
import ctypes
import importlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import unittest
from unittest import mock  # Load unittest's standard-library dependencies first.


TEST_CLASSES = (
    ('test_native_human_launch_source','NativeHumanLaunchSourceTests'),
    ('test_native_human_host_source','NativeHumanConsumedSourceTests'),
    ('test_native_human_host_source','NativeHumanRunCompositionSourceTests'),
    ('test_native_human_host_source','NativeHumanRootSourceTests'),
    ('test_native_human_host_source','NativeHumanEntrySourceTests'),
    ('test_native_human_host_source','NativeHumanHostedSelectionSourceTests'),
    ('test_native_human_host_source','NativeHumanAuditObservationSourceTests'),
    ('test_native_qualification_execute','NativeQualificationExecuteTests'),
    ('test_staged_source_closure','StagedSourceClosureTests'),
)

ATTEMPTS = []
CURRENT_TEST = '<repository-import>'


class ProhibitedEffect(AssertionError):
    pass


def _guard(name):
    def denied(*_args, **_kwargs):
        # Do not log arguments: a failed test may have supplied sensitive data.
        ATTEMPTS.append((CURRENT_TEST, name))
        raise ProhibitedEffect('source-only guard prohibited ' + name)
    return denied


def _guard_attributes(owner, label, names):
    for name in names:
        if hasattr(owner, name):
            setattr(owner, name, _guard(label + '.' + name))


def install_guards():
    # Standard-library ctypes is initialized above; no repository has been
    # imported. Cover retained loaders/symbol paths as well as public factories.
    # The audit hook cannot be removed by a test that catches our exception.
    def native_audit(event, _arguments):
        if event.startswith('ctypes.'):
            _guard('audit:' + event)()
    sys.addaudithook(native_audit)
    _guard_attributes(ctypes.LibraryLoader, 'ctypes.LibraryLoader', ('LoadLibrary', '__getattr__'))
    _guard_attributes(ctypes.CDLL, 'ctypes.CDLL', ('__getattr__', '__getitem__'))
    _guard_attributes(ctypes, 'ctypes', (
        'CDLL', 'PyDLL', 'WinDLL', 'OleDLL', 'CFUNCTYPE', 'PYFUNCTYPE', 'WINFUNCTYPE',
        'cast', 'string_at', 'wstring_at', 'memoryview_at', 'memmove', 'memset', 'resize'))
    _guard_attributes(_ctypes, '_ctypes', (
        'dlopen', 'dlsym', 'call_function', 'call_cdeclfunction', 'CFuncPtr'))
    _guard_attributes(subprocess, 'subprocess', (
        'Popen', 'run', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput'))
    _guard_attributes(os, 'os', (
        'fork', 'forkpty', 'posix_spawn', 'posix_spawnp', 'system', 'popen',
        'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe',
        'kill', 'killpg', 'pidfd_open', 'wait', 'waitpid', 'waitid', 'wait3', 'wait4',
        'chmod', 'fchmod', 'lchmod', 'chown', 'fchown', 'lchown', 'umask',
        'setuid', 'seteuid', 'setreuid', 'setresuid', 'setgid', 'setegid',
        'setregid', 'setresgid', 'setgroups', 'chroot', 'unshare', 'setns', 'mknod', 'mkfifo'))
    _guard_attributes(threading.Thread, 'threading.Thread', ('start',))
    _guard_attributes(threading, 'threading', ('_start_new_thread', '_start_joinable_thread'))
    _guard_attributes(_thread, '_thread', ('start_new_thread', 'start_new', 'start_joinable_thread'))
    # Guard retained Python socket-class aliases as well as all public factories.
    _guard_attributes(socket.socket, 'socket.socket', (
        '__init__', 'connect', 'connect_ex', 'bind', 'listen', 'accept', '_accept',
        'send', 'sendall', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg',
        'recv_into', 'recvfrom_into', 'recvmsg_into', 'shutdown'))
    _guard_attributes(socket, 'socket', (
        'socket', 'SocketType', 'socketpair', 'create_connection', 'create_server', 'fromfd', 'fromshare',
        'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr', 'getnameinfo'))
    _guard_attributes(_socket, '_socket', ('socket', 'socketpair', 'getaddrinfo'))
    _guard_attributes(ssl, 'ssl', ('SSLSocket', 'wrap_socket'))
    _guard_attributes(ssl.SSLContext, 'ssl.SSLContext', (
        'wrap_socket', 'wrap_bio', 'load_cert_chain', 'load_verify_locations',
        'load_default_certs', 'set_default_verify_paths'))
    _guard_attributes(ssl, 'ssl', (
        'SSLContext', 'SSLObject', 'create_default_context', '_create_unverified_context',
        '_create_default_https_context', '_create_stdlib_context'))


class GuardedResult(unittest.TextTestResult):
    def startTest(self, test):
        global CURRENT_TEST
        CURRENT_TEST = test.id()
        self.guard_start = len(ATTEMPTS)
        super().startTest(test)

    def stopTest(self, test):
        global CURRENT_TEST
        if len(ATTEMPTS) != self.guard_start and not any(
                failed is test for failed, _ in self.failures + self.errors):
            try:
                raise ProhibitedEffect('test caught a prohibited effect; zero attempts required')
            except ProhibitedEffect:
                self.addFailure(test, sys.exc_info())
        super().stopTest(test)
        CURRENT_TEST = '<between-tests>'


def main():
    if len(sys.argv) != 1:
        raise SystemExit('This runner accepts no selectors; its finite test inventory is source-pinned.')
    sys.dont_write_bytecode = True
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root), str(root / 'tests')]
    install_guards()
    suite = unittest.TestSuite()
    try:
        for module_name, class_name in TEST_CLASSES:
            module = importlib.import_module(module_name)
            test_class = getattr(module, class_name)
            if not isinstance(test_class, type) or not issubclass(test_class, unittest.TestCase):
                raise TypeError('explicit source test class unavailable: ' + class_name)
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
        if ATTEMPTS:
            raise ProhibitedEffect('a repository import caught a prohibited effect')
        result = unittest.TextTestRunner(verbosity=2, resultclass=GuardedResult).run(suite)
        return 0 if result.wasSuccessful() and not ATTEMPTS else 1
    finally:
        print('Source-only prohibited effect attempts:', len(ATTEMPTS), file=sys.stderr)
        for test_id, operation in ATTEMPTS:
            print('  ' + test_id + ': ' + operation, file=sys.stderr)


if __name__ == '__main__':
    raise SystemExit(main())
