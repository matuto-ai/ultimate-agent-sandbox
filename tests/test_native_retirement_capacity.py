"""Conservative existing lifecycle projection includes native retirement fields."""
from copy import deepcopy
import unittest
from uas.context import MAX_CONTEXT_GENERATION
from uas.ledger import _json
from uas.run_control import reserve_run_control_capacity

class NativeRetirementCapacityTests(unittest.TestCase):
    def test_worst_bounded_retirement_pending_is_covered(self):
        wide='x'*256;maximum=MAX_CONTEXT_GENERATION
        targets=[{'participant_id':'seat-'+str(i),'actor_id':wide,'attachment_id':wide,
            'incarnation_id':wide,'scope':{'room_id':wide,'participant_id':'seat-'+str(i),
            'run_id':'run','generation':maximum,'context_generation':maximum}} for i in range(2)]
        pending={'operation_id':wide,'kind':'retire-completed','control_revision':maximum,
            'source_generation':maximum,'target_generation':maximum,'targets':targets,
            'completion_digest':'f'*64,'attention':'NATIVE_RECONCILIATION_REQUIRED'}
        state={'runs':{'run':{'control_pending':deepcopy(pending)}}}
        reserve_run_control_capacity(state)
        modeled=state['runs']['run']['control_pending']
        self.assertGreaterEqual(len(_json(modeled)),len(_json(pending)))
        for target in modeled['targets']:
            self.assertEqual(wide,target['actor_id']);self.assertEqual(wide,target['attachment_id'])
        self.assertEqual(maximum,modeled['control_revision'])
        self.assertEqual(64,len(modeled['completion_digest']))
