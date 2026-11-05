import functools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sv4_app_llm.storage import repository
import sv4_app_llm.services.websites as websites
from sv4_app_llm.service import inspect_sv1_dataset


class WebsiteWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        db = Path(self.temp.name)/'history.sqlite3'
        patches = {name: functools.partial(getattr(repository, name), path=db)
                   for name in ('get_record', 'list_records', 'save_record', 'update_record')}
        self.patch = patch.multiple(websites, **patches)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def create(self, name='Cửa hàng', address='example.com'):
        return websites.save_website(name, address, websites.PURPOSES[1],
                                     'Chưa biết', None, '')

    def test_intake_unknown_and_duplicate(self):
        record_id = self.create()
        p = websites.get_website(record_id)['payload']
        self.assertEqual(p['address'], 'https://example.com')
        self.assertIsNone(p['asset_draft']['criticality'])
        self.assertIsNone(p['asset_draft']['internet_facing'])
        self.assertIsNone(p['sensitive_data'])
        self.assertEqual(p['assessment_status'], 'not_assessed')
        with self.assertRaises(ValueError): self.create()
        for url in ('https://user:pass@example.com', 'ftp://example.com', 'bad address'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                websites.normalize_website_url(url)

    def test_edit_keeps_id_and_rejects_changed_website(self):
        record_id = self.create()
        asset_id = websites.get_website(record_id)['payload']['asset_draft']['asset_id']
        websites.save_website('Tên mới', 'example.com', websites.PURPOSES[0],
                              websites.IMPACTS[1], False, 'Unknown', record_id)
        self.assertEqual(websites.get_website(record_id)['payload']['asset_draft']['asset_id'], asset_id)
        with self.assertRaises(ValueError):
            websites.save_website('Other', 'other.com', websites.PURPOSES[0],
                                  websites.IMPACTS[0], None, '', record_id)

    def test_evidence_and_status_do_not_create_assessment(self):
        record_id = self.create()
        other_id = self.create('Khác', 'other.com')
        dataset = inspect_sv1_dataset()['dataset']
        content = json.dumps(dataset).encode()
        with self.assertRaises(ValueError):
            websites.attach_website_dataset(record_id, content, 'WEB01', False)
        with self.assertRaises(ValueError):
            websites.attach_website_dataset(record_id, content, 'NOPE', True)
        websites.attach_website_dataset(record_id, content, 'WEB01', True)
        self.assertEqual(len(websites.website_evidence(record_id)), 1)
        self.assertEqual(websites.website_evidence(other_id), [])
        websites.set_action_status(record_id, 'evidence', 'Tôi đã xử lý', 'đã gửi')
        result = websites.action_status(record_id, 'evidence')
        self.assertEqual(result['verification'], 'not_verified')
        self.assertEqual(websites.get_website(record_id)['payload']['assessment_status'], 'not_assessed')
        with self.assertRaises(ValueError):
            websites.set_action_status(record_id, 'analysis', 'Tôi đã xử lý')
        self.assertNotIn('evidence', [s['id'] for s in websites.preparation_steps(record_id)])
        self.assertIn('Chưa có kết quả', websites.website_summary(record_id))
