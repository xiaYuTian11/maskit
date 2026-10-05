"""P6: real ingress evidence is neither a demo result nor process authentication."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'engine'))
import onboarding
import transparent as tr
import event_store as es
import panel
import ner_engine
from test_inspection_report import _ProxyHarness

PHONE = '1' + '3' + '0' + '0' * 8


class MarkerTests(unittest.TestCase):
    def test_ner_never_receives_marker(self):
        _, marker = onboarding.create('proxy', '', 'fp', 0)
        with tr.demo_store_scope(), mock.patch.object(tr, 'NER_ENABLED', True), \
                mock.patch.object(ner_engine, 'is_ner_available', return_value=True), \
                mock.patch.object(ner_engine, 'extract_entities', return_value=[]) as detect:
            tr._new_session('verify-ner')
            self.addCleanup(tr._drop, 'verify-ner')
            tr.mask('before ' + marker + ' after', 'verify-ner')
            self.assertTrue(detect.called)
            self.assertTrue(all(marker not in call.args[0] for call in detect.call_args_list))

    def test_marker_bypasses_rules_and_ner_but_neighbors_are_scanned(self):
        _, marker = onboarding.create('proxy', 'client', 'fp', 0, 'marker', now=100)
        with tr.demo_store_scope(), mock.patch.object(tr, 'NER_ENABLED', False), \
                mock.patch.object(tr, 'CUSTOM_WORDS', {marker: 'VERIFY', 'MASKIT': 'VERIFY'}):
            sid = 'onboarding-unit'
            tr._new_session(sid)
            self.addCleanup(tr._drop, sid)
            result = tr.mask(PHONE + ' ' + marker + ' ' + PHONE, sid)
            self.assertIn(marker, result)
            self.assertNotIn(PHONE, result)
            self.assertNotIn(marker, tr.sessions[sid]['fwd'])
            self.assertIn(hashlib.sha256(marker.encode()).hexdigest(),
                          tr.sessions[sid]['verification'])

    def test_all_log_modes_strip_markers_without_mutating_input(self):
        _, marker = onboarding.create('proxy', '', 'fp', 0, 'marker')
        record = {'type': 'MASK', 'dialog': marker, 'items': [{'label': 'TEST', 'original': marker}]}
        for mode in ('summary', 'trace', 'detailed'):
            with mock.patch.object(es, 'effective_log_mode', return_value=mode):
                self.assertNotIn(marker, json.dumps(es.project_event_for_log(record)))
        self.assertEqual(record['dialog'], marker)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record, self.marker = onboarding.create('proxy', 'client', 'fp', 10, 'marker', now=100)

    def row(self, **overrides):
        return dict(seq=11, ts=101, type='MASK', ingress='proxy', upstream='client', sid='s',
                    verification={hashlib.sha256(self.marker.encode()).hexdigest(): True}, **overrides)

    def test_matching_entry_is_observed_without_claiming_response_success(self):
        result = onboarding.advance(self.record, [self.row()], 'fp', now=102)
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['evidence']['seq'], 11)
        self.assertNotIn(self.marker, json.dumps(result))

    def test_wrong_ingress_client_demo_old_and_wrong_marker_do_not_verify(self):
        for changes in ({'ingress': 'ext'}, {'upstream': 'other'}, {'type': 'DEMO'},
                        {'ts': 99}, {'verification': {}}, {'seq': 10}):
            row = self.row()
            row.update(changes)
            result = onboarding.advance(dict(self.record), [row], 'fp', now=102)
            self.assertEqual(result['status'], 'pending', changes)

    def test_configuration_change_and_expiry_invalidate_evidence(self):
        observed = onboarding.advance(self.record, [self.row()], 'fp', now=102)
        self.assertEqual(onboarding.advance(observed, [], 'changed', now=103)['status'], 'stale')
        self.assertEqual(onboarding.advance(self.record, [], 'fp', now=1000)['status'], 'expired')

    def test_weak_mode_is_explicit_and_does_not_require_marker(self):
        record, marker = onboarding.create('ext', '', 'fp', 0, 'window', now=100)
        self.assertIsNone(marker)
        result = onboarding.advance(record, [{'seq': 1, 'ts': 101, 'type': 'MASK', 'ingress': 'ext'}], 'fp', now=102)
        self.assertEqual(result['mode'], 'window')
        self.assertEqual(result['status'], 'observed')


class PanelTests(unittest.TestCase):
    def test_disabling_extension_invalidates_fingerprint(self):
        self.assertNotEqual(panel._verification_fingerprint({'ext_bridge_enabled': True}),
                            panel._verification_fingerprint({'ext_bridge_enabled': False}))

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for obj, key, value in ((panel, 'DATA_ROOT', Path(tmp.name)),
                                (panel, 'load_config', lambda: {'upstreams': [{'name': 'client', 'port': 5800}]}),
                                (panel, 'fetch_events', mock.Mock(return_value=[]))):
            p = mock.patch.object(obj, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = panel.app.test_client()
        self.headers = {'X-Shield-Token': panel.API_TOKEN}

    def test_start_persists_only_digest_and_is_guarded(self):
        url = '/api/onboarding/verification'
        self.assertEqual(self.client.post(url, json={}).status_code, 403)
        response = self.client.post(url, json={'ingress': 'proxy', 'upstream': 'client'}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        saved = (panel.DATA_ROOT / 'onboarding-verification.json').read_text()
        self.assertNotIn(result['marker'], saved)
        self.assertEqual(self.client.get(url, headers=self.headers).get_json()['status'], 'pending')

    def test_preview_download_and_save_use_identical_bytes(self):
        with mock.patch.object(panel, '_diagnostics_payload', return_value={'schema': 2, 'generated_at': 1}):
            preview = self.client.post('/api/diagnostics/preview', headers=self.headers)
        self.assertEqual(preview.status_code, 200)
        data = preview.get_json()
        download = self.client.get('/api/diagnostics?preview_id=' + data['id'], headers=self.headers)
        self.assertEqual(download.data.decode(), data['body'])
        saved = self.client.post('/api/diagnostics/save', json={'preview_id': data['id']}, headers=self.headers).get_json()
        self.assertEqual(Path(saved['path']).read_bytes(), download.data)
        self.assertEqual(saved['size'], len(download.data))
        self.assertEqual(self.client.get('/api/diagnostics?preview_id=missing', headers=self.headers).status_code, 410)

    def test_diagnostics_strip_markers_even_in_nested_metadata(self):
        _, marker = onboarding.create('proxy', '', 'fp', 0, 'marker')
        payload = {'upstreams': [{'name': marker}], 'verification': {'private': True}, 'log_tail': [marker]}
        with mock.patch.object(panel, '_diagnostics_payload', return_value=payload):
            response = self.client.post('/api/diagnostics/preview', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(marker, response.get_json()['body'])
        self.assertNotIn('verification', json.loads(response.get_json()['body']))

    def test_extension_zero_hit_marker_still_produces_evidence(self):
        _, marker = onboarding.create('ext', '', 'fp', 0)
        with mock.patch.object(panel, '_ext_cfg', return_value={'ext_record_events': False}), \
                mock.patch.dict(panel._ext_cfg_state, {'ext_bridge_enabled': True}), \
                mock.patch.object(tr, '_maybe_reload'), mock.patch.object(tr, 'NER_ENABLED', False), \
                mock.patch.object(tr, 'enqueue_event') as emit, mock.patch.object(tr, '_log'):
            response = self.client.post('/api/ext/mask', json={'text': marker}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.addCleanup(tr._drop, response.get_json()['sid'])
        self.assertEqual(response.get_json()['masked_text'], marker)
        self.assertEqual(emit.call_args.args[0]['verification'], {onboarding.digest(marker): True})
        self.assertNotIn(marker, json.dumps(emit.call_args.args[0]))


class ProxyEvidenceTests(_ProxyHarness):
    def test_stdout_correlation_is_absent_from_diagnostics(self):
        _, marker = onboarding.create('proxy', '', 'fp', 0)
        tr._new_session('verify-stdout')
        tr.mask(marker, 'verify-stdout')
        with mock.patch.object(tr, '_log') as log:
            tr._emit('MASK', sid='verify-stdout')
        body = panel._diagnostic_body({'log_tail': [panel._scrub_text(log.call_args.args[0])]})
        self.assertNotIn(onboarding.digest(marker), body)

    def test_real_request_preserves_marker_and_emits_only_digest(self):
        _, marker = onboarding.create('proxy', '', 'fp', 0)
        flow = self._flow({'messages': [{'role': 'user', 'content': PHONE + ' ' + marker}]})
        with mock.patch.object(tr, 'NER_ENABLED', False), mock.patch.object(tr, 'write_runtime_metrics'), \
                mock.patch.object(tr, '_ENGINE_DEADLINE_S', 3):
            self._drive(flow)
        self.assertIsNone(flow.response)
        self.assertIn(marker.encode(), flow.request.content)
        self.assertNotIn(PHONE.encode(), flow.request.content)
        masks = [event for event in self.events if event['type'] == 'MASK']
        self.assertEqual(masks[0]['verification'], {onboarding.digest(marker): True})
        self.assertNotIn(marker, json.dumps(self.events))


if __name__ == '__main__':
    unittest.main()
