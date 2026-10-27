"""Pure native frame validation; synthetic frames are NOT native qualification."""
from types import SimpleNamespace
import unittest
from uas.native_claude_runtime import NativeClaudeReceiver
from uas.claude_runtime import _ClaudeJournal, ClaudeUnavailable

class NativeClaudeFrameTests(unittest.TestCase):
    def receiver(self):
        r=NativeClaudeReceiver.__new__(NativeClaudeReceiver)
        r.root=SimpleNamespace(native_namespace_pid=37)
        r.session_id='11111111-1111-4111-8111-111111111111'
        r.native_spawned=False; r.ready=False; r.revision=0
        r.pending=None; r.ack=None; r.reply_id=None; r.reply=None
        return r
    def test_host_pid_is_not_native_authority(self):
        r=self.receiver()
        with self.assertRaises(ClaudeUnavailable): r._frame({'type':'native-spawned','native_pid':36,'session_id':r.session_id})
    def test_exact_ready_frame_stays_receiver_observation(self):
        r=self.receiver(); r._frame({'type':'native-spawned','native_pid':37,'session_id':r.session_id})
        r._frame({'type':'host-ready','native_pid':37,'session_id':r.session_id,'sdk_version':'0.3.310',
            'cli_version':'2.1.310','authority':'native-child-awaits-supervisor-admission','fresh_context':'exclusive-new-home-explicit-session-no-input'})
        self.assertTrue(r.ready); self.assertFalse(hasattr(r.root,'active'))
    def test_old_fixture_ready_not_native_proof(self):
        r=self.receiver(); r.native_spawned=True
        with self.assertRaises(ClaudeUnavailable): r._frame({'type':'host-ready','native_pid':37,'session_id':r.session_id,
            'sdk_version':'0.3.310','cli_version':'2.1.310','authority':'sdk-host-owned-fixture-only'})
    def test_uncorrelated_reply_rejected(self):
        r=self.receiver(); r.reply_id='one'
        with self.assertRaises(ClaudeUnavailable): r._frame({'type':'reply','id':'two','state':'safe'})
    def test_policy_fence_rejected(self):
        r=self.receiver()
        with self.assertRaises(ClaudeUnavailable): r._frame({'type':'native','fence':'needs-input','event':{}})
    def test_old_intent_and_receipt_algorithm_reused(self):
        self.assertTrue(issubclass(NativeClaudeReceiver,_ClaudeJournal))
        self.assertIs(NativeClaudeReceiver._unknown,_ClaudeJournal._unknown)
        self.assertIs(NativeClaudeReceiver._close_journal,_ClaudeJournal._close_journal)
