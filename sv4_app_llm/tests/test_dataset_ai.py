import unittest
from unittest.mock import patch
from sv4_app_llm.service import inspect_sv1_dataset, explain_sv1_dataset, save_dataset_explanation


class DatasetAITests(unittest.TestCase):
    def test_input_context_and_provenance(self):
        data = inspect_sv1_dataset()['dataset']
        with patch('sv4_app_llm.llm.dataset.ask_ollama', return_value=('Giải thích', 'mock')) as call:
            answer = explain_sv1_dataset(data, 'Dữ liệu thiếu gì?')
        context = call.call_args.args[1]
        self.assertEqual(context['input_dataset'], data)
        self.assertEqual(context['analysis_status'], 'not_connected')
        self.assertNotIn('reports', context)
        self.assertEqual(answer['scope'], 'input_only')
        changed = dict(data, dataset_id='another')
        with self.assertRaises(ValueError):
            save_dataset_explanation(changed, answer)
        with patch('sv4_app_llm.service.save_record', return_value='saved') as save:
            self.assertEqual(save_dataset_explanation(data, answer), 'saved')
        self.assertEqual(save.call_args.args[0], 'dataset_explanation')

    def test_reject_invalid_input_before_model(self):
        data = inspect_sv1_dataset()['dataset']
        with patch('sv4_app_llm.llm.dataset.ask_ollama') as call:
            with self.assertRaises(ValueError):
                explain_sv1_dataset(data, ' ')
            data['findings'][0]['asset_id'] = 'MISSING'
            with self.assertRaises(ValueError):
                explain_sv1_dataset(data, 'Explain')
            call.assert_not_called()
