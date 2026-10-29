"""Cheap entrypoint contract tests; native operations are never executed."""
import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch
from uas import local_cli
from uas.__main__ import main

class LocalCLITests(unittest.TestCase):
    def test_dispatch_and_inspection(self):
        with patch('uas.local_cli.Installation') as installation, contextlib.redirect_stdout(io.StringIO()) as output:
            installation.return_value.status.return_value={'runtime':'not-observed'}
            self.assertEqual(main(['local','--root','/private/install','inspect']),0)
            self.assertEqual(json.loads(output.getvalue()),{'runtime':'not-observed'})
            installation.return_value.setup.assert_not_called()

    def test_selected_room_is_forwarded_once_no_unknown_retry(self):
        with patch('uas.local_cli.Installation'),patch('uas.local_cli.request',return_value={'outcome':'unknown'}) as request,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(local_cli.main(['--root','/private/install','start','--room','alpha']),3)
            self.assertEqual(request.call_count,1)
            self.assertEqual(request.call_args.args[1:],('start','alpha'))

    def test_stop_failed_return_is_not_success(self):
        failed={'infrastructure':{'phase':'stop_failed','leftovers':[{'kind':'authority'}],
                                  'observed':{'container':{'running':True}}}}
        self.assertFalse(local_cli.stopped_result(failed))
        with patch('uas.local_cli.Installation'),patch('uas.local_cli.request',return_value={'outcome':'observed','result':failed}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(local_cli.main(['--root','/private/install','stop','--room','alpha']),3)
        self.assertTrue(local_cli.stopped_result({'infrastructure':{'phase':'stopped','leftovers':[],
                                                                  'observed':{'container':{'running':False}}}}))

    def test_host_shutdown_rejects_stop_failed_even_when_services_close(self):
        controller=Mock();controller.native.stop.return_value={'infrastructure':{
            'phase':'stop_failed','leftovers':[{'kind':'container'}],
            'observed':{'container':{'running':True}}}}
        services=Mock();services.rooms=('alpha',);services.close.return_value=True
        with patch('uas.local_cli.host_lock',return_value=contextlib.nullcontext(12)), \
             patch('uas.local_services.LocalServices',return_value=services), \
             patch('uas.local_manager_owner.ManagerOwner'), \
             patch('uas.local_cli.LocalController',return_value=controller), \
             patch('uas.local_cli.serve'),patch('uas.local_cli.signal.signal'):
            with self.assertRaisesRegex(local_cli.LocalInstallationError,'LOCAL_HOST_SHUTDOWN_UNCONFIRMED'):
                local_cli.run_host(Mock(bootstrap=Mock(return_value=({}, {}, {'native':None}))))
        services.close.assert_called_once()

    def test_repeated_start_unknown_hub_receipt_remains_nonzero(self):
        receipt={'outcome':'observed','result':{'infrastructure':{'phase':'running','leftovers':[]},
                                              'services':{'hub':'unknown','runtime':'not-started'}}}
        with patch('uas.local_cli.Installation'),patch('uas.local_cli.request',return_value=receipt) as request,contextlib.redirect_stdout(io.StringIO()):
            for _ in range(2):
                self.assertEqual(local_cli.main(['--root','/private/install','start','--room','alpha']),3)
            self.assertEqual(request.call_count,2)  # Two explicit calls, no implicit retry.

    def test_errors_do_not_echo_private_details(self):
        with patch('uas.local_cli.Installation',side_effect=OSError('private-secret')),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(local_cli.main(['--root','/private/install','inspect']),3)
            self.assertNotIn('private-secret',output.getvalue())

if __name__=='__main__':unittest.main()
