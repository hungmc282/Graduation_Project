import functools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sv4_app_llm.services.enterprise as enterprise
from sv4_app_llm.storage import repository
from sv4_app_llm.service import inspect_sv1_dataset


class EnterpriseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db = Path(temp.name)/'store.sqlite3'
        changes = {name: functools.partial(getattr(repository,name),path=db)
                   for name in ('get_record','list_records','save_record','update_record')}
        patcher=patch.multiple(enterprise,**changes)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_asset_types_unknown_and_edit(self):
        for kind in ('database','workstation','server','web_server','cloud_resource'):
            record_id=enterprise.save_enterprise_asset(kind,kind,subnet='10.0.0.0/24',vlan='20')
            old=enterprise.get_record(record_id)['payload']['asset']['asset_id']
            enterprise.save_enterprise_asset('Updated',kind,record_id=record_id)
            self.assertEqual(enterprise.get_record(record_id)['payload']['asset']['asset_id'],old)
        workspace=enterprise.load_workspace()
        self.assertEqual(len(workspace['assets']),5)
        self.assertTrue(all(a['criticality'] is None for a in workspace['assets']))
        with self.assertRaises(ValueError):
            enterprise.save_enterprise_asset('bad','database',criticality=6)

    def test_connections_validate_endpoints_and_do_not_create_exploits(self):
        enterprise.save_enterprise_asset('Web','web_server')
        enterprise.save_enterprise_asset('DB','database')
        workspace=enterprise.load_workspace()
        a,b=workspace['assets']
        enterprise.save_declared_connection(a['asset_id'],b['asset_id'],True,'declared firewall')
        self.assertEqual(len(enterprise.load_workspace()['connections']),1)
        self.assertEqual(enterprise.load_workspace()['exploit_rules'],[])
        self.assertEqual(enterprise.load_workspace()['analysis_status'],'not_connected')
        with self.assertRaises(ValueError):
            enterprise.save_declared_connection('MISSING',b['asset_id'],True,'test')
        with self.assertRaises(ValueError):
            enterprise.save_declared_connection(a['asset_id'],b['asset_id'],True,' ')

    def test_import_snapshot_is_separate_and_deduplicated(self):
        enterprise.save_enterprise_asset('My database','database')
        dataset=inspect_sv1_dataset()['dataset']
        content=json.dumps(dataset).encode()
        record_id=enterprise.store_input_dataset(content)
        self.assertEqual(enterprise.store_input_dataset(content),record_id)
        self.assertEqual(len(enterprise.load_workspace(record_id)['assets']),4)
        self.assertEqual(len(enterprise.load_workspace()['assets']),1)
        self.assertEqual(enterprise.load_workspace(record_id)['dataset'],dataset)
        self.assertEqual(enterprise.load_workspace()['dataset'],None)
