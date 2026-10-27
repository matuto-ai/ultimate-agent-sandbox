"""Pure command schemas and mocked lifecycle; never execute native payloads."""
from copy import deepcopy
import hashlib
import struct
import unittest
from unittest.mock import Mock, patch

from uas.artifact_protocol import ArtifactError, profile_scope_digest
from uas.config import ConfigError
from uas.gate_repository import (compile_repository_config, command_request,
    command_correlation, command_observation, command_observations)
from uas import artifact_helper as helper

SCOPE = {'version': 1, 'evaluation_id': 'evaluation-a', 'room_id': 'alpha',
    'room_instance': 'instance-a', 'project_id': 'project-a', 'repository': 'org/repo',
    'run_id': 'run-a', 'generation': 1, 'participant_id': 'alice', 'policy_id': 'default',
    'policy_version': 1, 'policy_digest': 'a' * 64, 'gate_id': 'command', 'config_digest': 'b' * 64}
TARGET = {'target_id': 'c' * 32, 'head_sha': 'd' * 40, 'tree_sha': 'e' * 40,
    'manifest_sha256': 'f' * 64, 'source_digest': '1' * 64,
    'device': 1, 'inode': 2, 'entries': 1, 'expanded_bytes': 3,
    'work': {'device': 2, 'inode': 3, 'limit_bytes': 8 << 20}}
CONFIG = {'argv': ['/usr/bin/python3.13', '-m', 'unittest', 'test_example'], 'cwd': '.',
    'timeout_seconds': 5, 'process_limit': 8, 'memory_bytes': 128 << 20,
    'output_bytes': 65536, 'environment': {'LC_ALL': 'C'}, 'executable_sha256': 'a' * 64}


def observations(stdout=b'passed\n', stderr=b'', *, code=0, signal=0, timeout=False, limited=False):
    correlation = command_correlation(SCOPE, TARGET, CONFIG)
    packets = [b'CGS1' + bytes.fromhex(correlation)]
    for index, raw in enumerate((stdout, stderr)):
        tail = raw[-16384:]
        packets.append(struct.pack('!4sIQ32sII', b'CGR1', index, len(raw),
            hashlib.sha256(raw).digest(), len(tail), int(len(raw) > 16384)))
        for offset in range(0, len(tail), 8192):
            packets.append(struct.pack('!4sII', b'CGT1', index, offset) + tail[offset:offset + 8192])
    packets.append(struct.pack('!4siIIIQ32sIII', b'CGE1', -1 if code is None else code,
        signal, int(timeout), int(limited), 5000 if timeout else 12, bytes.fromhex(CONFIG['executable_sha256']), 1, int(timeout or limited), 1))
    packets.append(b'CGF1' + bytes.fromhex(correlation))
    return [command_observation(packet, correlation) for packet in packets]


class CommandSchemaTests(unittest.TestCase):
    def test_bounded_config_canonical_and_no_source_mutation(self):
        source = deepcopy(CONFIG)
        compiled = compile_repository_config('command', source, 'command')
        self.assertEqual(compiled['executables'], [])
        self.assertEqual(source, CONFIG)
        self.assertEqual(compile_repository_config('command', compiled, 'command'), compiled)

    def test_exact_argv_cwd_environment_and_limits_reject_unsafe_definitions(self):
        updates = [{'argv': '/bin/sh -c true'}, {'argv': ['/bin/sh', '-c', 'true']},
            {'argv': ['/usr/bin/bash', '-c', 'true']}, {'argv': ['/usr/bin/env', 'sh']},
            {'argv': ['/usr/bin/../bin/python3']}, {'argv': ['/usr/bin/python3', 'x\0y']},
            {'cwd': '../source'}, {'cwd': '/source'}, {'environment': {'LD_PRELOAD': '/x'}},
            {'environment': {'LC_ALL': 'other'}}, {'process_limit': True}, {'process_limit': 33},
            {'memory_bytes': 1}, {'output_bytes': 0}, {'timeout_seconds': 0}, {'timeout_seconds': 11},
            {'executable_sha256': 'not-a-digest'}, {'verdict': 'passed'}]
        for update in updates:
            with self.subTest(update=update), self.assertRaises(ConfigError):
                compile_repository_config('command', {**CONFIG, **update}, 'command')

    def test_executable_dependencies_are_pinned_bounded_and_non_shell(self):
        config = {**CONFIG, 'executables': [{'path': '/usr/bin/true', 'sha256': 'b' * 64}]}
        self.assertEqual(compile_repository_config('command', config, 'command')['executables'], config['executables'])
        for dependencies in ([{'path': '/usr/bin/sh', 'sha256': 'b' * 64}],
                [{'path': '/usr/bin/true', 'sha256': 'wrong'}], config['executables'] * 2):
            with self.assertRaises(ConfigError):
                compile_repository_config('command', {**CONFIG, 'executables': dependencies}, 'command')

    def test_request_binds_full_configuration_and_exact_target(self):
        packet = command_request(SCOPE, TARGET, CONFIG)
        self.assertEqual(packet[:4], b'CGQ1')
        self.assertEqual(struct.unpack('!IIIIIIII', packet[68:100]), (5, 4, 1, 1, 8, 128 << 20, 65536, 0))
        self.assertEqual(struct.unpack('!QQ', packet[124:140]), (TARGET['device'], TARGET['inode']))
        original = command_correlation(SCOPE, TARGET, CONFIG)
        self.assertNotEqual(original, command_correlation(SCOPE, {**TARGET, 'inode': 3}, CONFIG))
        self.assertNotEqual(original, command_correlation(SCOPE, TARGET, {**CONFIG, 'argv': [*CONFIG['argv'], '-v']}))
        self.assertNotEqual(profile_scope_digest('artifacts-v1-source', SCOPE, {key: value for key, value in TARGET.items() if key != 'work'}),
                            profile_scope_digest('command-v1-source', SCOPE, TARGET))

    def test_complete_success_keeps_hash_tail_and_raw_exit_without_verdict(self):
        facts, final = command_observations(observations(), SCOPE, TARGET, CONFIG)
        self.assertEqual(bytes.fromhex(facts['stdout']['tail_hex']), b'passed\n')
        self.assertEqual(facts['stderr']['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(facts['exit']['exit_code'], 0)
        self.assertTrue(facts['exit']['whole_tree_exited'])
        self.assertNotIn('verdict', facts)
        self.assertEqual(final['kind'], 'final')

    def test_failed_signal_timeout_and_bounded_tail_remain_facts(self):
        for args in ({'code': 1}, {'code': None, 'signal': 9, 'timeout': True},
                     {'stdout': b'x' * 65537, 'code': None, 'signal': 9, 'limited': True}):
            facts, _ = command_observations(observations(**args), SCOPE, TARGET, CONFIG)
            self.assertNotIn('ok', facts)
            self.assertLessEqual(len(bytes.fromhex(facts['stdout']['tail_hex'])), 16384)

    def test_malformed_reordered_forged_and_incomplete_observations_refuse(self):
        original = observations()
        variants = [original[:-1], [*original, original[-1]], [original[1], original[0], *original[2:]]]
        for mutate in ('hash', 'tree', 'digest', 'claim', 'tail', 'correlation'):
            altered = deepcopy(original)
            if mutate == 'hash': altered[1]['sha256'] = 'f' * 64
            if mutate == 'tree': altered[-2]['whole_tree_exited'] = False
            if mutate == 'digest': altered[-2]['executable_sha256'] = 'b' * 64
            if mutate == 'claim': altered[-2]['verdict'] = 'passed'
            if mutate == 'tail': altered[2]['offset'] = 8192
            if mutate == 'correlation': altered[-1]['correlation'] = 'c' * 64
            variants.append(altered)
        for records in variants:
            with self.assertRaises(ArtifactError):
                command_observations(records, SCOPE, TARGET, CONFIG)

    def test_unknown_profile_refused_before_any_boundary_effect(self):
        with self.assertRaises(ArtifactError):
            helper.GateWorkstation('alpha', 'instance-a', *[c * 64 for c in '123456'], 'hub', profile='generic-shell')

    def test_command_loss_cannot_cleanup_from_observer_exit(self):
        launch = object.__new__(helper.GateHelperLaunch)
        launch.workstation = helper.GateWorkstation('alpha', 'instance-a', *[c * 64 for c in '123456'], 'hub', profile='command-v1-source')
        launch.state, launch.origin, launch.journal, launch.incarnation = 'running', None, None, 'e' * 32
        launch.target_lease = Mock()
        launch._exit = Mock(return_value=True)
        result = launch.abort()
        self.assertFalse(result['cleanup'])
        self.assertEqual(result['launch_state'], 'unknown')
        launch._exit.assert_not_called()
        launch.target_lease.mark_exit_confirmed.assert_not_called()
        launch.target_lease.cleanup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
