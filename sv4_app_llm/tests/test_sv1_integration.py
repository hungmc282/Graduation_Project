import json
import unittest
from sv4_app_llm.service import inspect_sv1_dataset
from sv4_app_llm.adapters.sv1 import DatasetInputError


class SV1IntegrationTests(unittest.TestCase):
    def test_sample_and_upload_roundtrip(self):
        sample = inspect_sv1_dataset()
        self.assertEqual(sample['counts'], dict(assets=4, services=4, findings=4,
                                                connections=4, exploit_rules=0))
        self.assertEqual(inspect_sv1_dataset(json.dumps(sample['dataset']).encode()), sample)
        self.assertNotIn('risk_before', sample)

    def test_invalid_inputs_rejected(self):
        for payload in (b'{bad', b'[]', b'{"schema_version":"99"}'):
            with self.subTest(payload=payload), self.assertRaises(DatasetInputError):
                inspect_sv1_dataset(payload)

    def test_missing_asset_rejected_with_details(self):
        dataset = inspect_sv1_dataset()['dataset']
        dataset['findings'][0]['asset_id'] = 'MISSING'
        with self.assertRaises(DatasetInputError) as result:
            inspect_sv1_dataset(json.dumps(dataset).encode())
        self.assertTrue(result.exception.details)
