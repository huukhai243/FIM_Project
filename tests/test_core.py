import json, os, tempfile, time, unittest
from datetime import datetime
from pathlib import Path
from fim.core import FileState, compare_states, Change, scan_tree
from fim.rules import classify
from fim.database import FimDB
from fim import service

DAY = datetime(2026, 1, 5, 10, 0)     # trong giờ làm việc
NIGHT = datetime(2026, 1, 5, 2, 0)


def fs(path, sha='a', size=1, mode=0o644): return FileState(path, sha, size, 1, mode)


class CompareTest(unittest.TestCase):
    def test_created(self): self.assertEqual(compare_states({}, {'a': fs('a')})[0].event_type, 'CREATED')
    def test_deleted(self): self.assertEqual(compare_states({'a': fs('a')}, {})[0].event_type, 'DELETED')
    def test_modified(self): self.assertEqual(compare_states({'a': fs('a', 'x')}, {'a': fs('a', 'y')})[0].event_type, 'MODIFIED')
    def test_permission(self):
        self.assertEqual(compare_states({'a': fs('a', mode=0o644)}, {'a': fs('a', mode=0o600)})[0].event_type, 'PERMISSION_CHANGED')
    def test_modified_and_permission(self):
        self.assertEqual(compare_states({'a': fs('a', 'x')}, {'a': fs('a', 'y', mode=0o755)})[0].event_type,
                         'MODIFIED+PERMISSION_CHANGED')
    def test_moved(self):
        ch = compare_states({'a.txt': fs('a.txt', 'h')}, {'b.locked': fs('b.locked', 'h')})
        self.assertEqual([(c.event_type, c.old.path) for c in ch], [('MOVED', 'a.txt')])
    def test_empty_files_not_paired_as_move(self):
        ch = compare_states({'a': fs('a', 'e', size=0)}, {'b': fs('b', 'e', size=0)})
        self.assertEqual(sorted(c.event_type for c in ch), ['CREATED', 'DELETED'])


class RulesTest(unittest.TestCase):
    cfg = {'watch_paths': [{'path': '/r/etc', 'critical': True}, {'path': '/r/home'}],
           'sensitive_paths': ['*.conf'], 'executable_extensions': ['.sh'], 'check_unix_permissions': True}

    def mod(self, path, **kw): return Change(path, 'MODIFIED', fs(path), fs(path, 'b', **kw))

    def test_sensitive_critical_is_high(self):
        v = classify(self.mod('/r/etc/app.conf'), self.cfg, now=DAY)
        self.assertEqual((v.level, v.verdict), ('HIGH', 'SUSPICIOUS')); self.assertEqual(v.score, 7)

    def test_normal_user_edit_is_legitimate(self):
        v = classify(self.mod('/r/home/notes.txt'), self.cfg, now=DAY)
        self.assertEqual((v.level, v.verdict), ('LOW', 'LEGITIMATE'))

    def test_off_hours_raises_score(self):
        v = classify(self.mod('/r/home/notes.txt'), self.cfg, now=NIGHT)
        self.assertEqual(v.verdict, 'SUSPICIOUS'); self.assertIn('outside work hours', v.details)

    def test_allow_whitelist(self):
        allow = [{'pattern': '*.conf', 'events': 'MODIFIED'}]
        self.assertEqual(classify(self.mod('/r/etc/app.conf'), self.cfg, allow, now=DAY).verdict, 'LEGITIMATE')
        deleted = Change('/r/etc/app.conf', 'DELETED', fs('/r/etc/app.conf'), None)   # event khác => không được allow
        self.assertEqual(classify(deleted, self.cfg, allow, now=DAY).verdict, 'SUSPICIOUS')

    def test_whitelist_cannot_hide_log_truncation(self):
        allow = [{'pattern': '*.log', 'events': 'MODIFIED'}]
        append = Change('/r/home/app.log', 'MODIFIED', fs('/r/home/app.log', size=10), fs('/r/home/app.log', 'b', size=20))
        wipe = Change('/r/home/app.log', 'MODIFIED', fs('/r/home/app.log', size=10), fs('/r/home/app.log', 'b', size=0))
        self.assertEqual(classify(append, self.cfg, allow, now=DAY).verdict, 'LEGITIMATE')
        v = classify(wipe, self.cfg, allow, now=DAY)
        self.assertEqual(v.verdict, 'SUSPICIOUS'); self.assertIn('overridden', v.details)

    def test_ransomware_rename_and_mass_change(self):
        ch = Change('/r/home/doc.txt.locked', 'MOVED', fs('/r/home/doc.txt'), fs('/r/home/doc.txt.locked'))
        v = classify(ch, self.cfg, batch_size=50, now=DAY)
        self.assertEqual(v.level, 'HIGH')
        for r in ('ransomware-like extension', 'extension changed', 'mass change'): self.assertIn(r, v.details)

    def test_setuid_and_exec_bit(self):
        ch = Change('/r/home/x', 'PERMISSION_CHANGED', fs('/r/home/x', mode=0o644), fs('/r/home/x', mode=0o4755))
        v = classify(ch, self.cfg, now=DAY)
        self.assertIn('setuid', v.details); self.assertIn('execute permission added', v.details); self.assertEqual(v.level, 'HIGH')

    def test_hidden_file(self):
        v = classify(Change('/r/home/.backdoor', 'CREATED', None, fs('/r/home/.backdoor')), self.cfg, now=DAY)
        self.assertIn('hidden file', v.details)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        (self.root / 'sub').mkdir(); (self.root / '__pycache__').mkdir()
        (self.root / 'a.txt').write_text('A'); (self.root / 'sub' / 'b.tmp').write_text('B')
        (self.root / '__pycache__' / 'c.pyc').write_text('C')
    def tearDown(self): self.tmp.cleanup()

    def test_ignore_patterns(self):
        s, err = scan_tree([self.root.as_posix()], ['*.tmp', '__pycache__/'])
        self.assertEqual([k.rsplit('/', 1)[-1] for k in s], ['a.txt']); self.assertEqual(err, [])

    def test_missing_root_reported(self):
        s, err = scan_tree([(self.root / 'nope').as_posix()])
        self.assertEqual(s, {}); self.assertEqual(len(err), 1)

    def test_quick_scan_reuses_hash(self):
        s, _ = scan_tree([self.root.as_posix()], ['*.tmp', '__pycache__/'])
        key = next(iter(s)); fake = {key: FileState(key, 'cached', s[key].size, s[key].mtime_ns, s[key].mode)}
        self.assertEqual(scan_tree([self.root.as_posix()], ['*.tmp', '__pycache__/'], prev=fake)[0][key].sha256, 'cached')
        self.assertNotEqual(scan_tree([self.root.as_posix()], ['*.tmp', '__pycache__/'])[0][key].sha256, 'cached')


class _TempProject(unittest.TestCase):
    """Thư mục giám sát + config tạm."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); t = Path(self.tmp.name)
        (t / 'w' / 'etc').mkdir(parents=True); (t / 'w' / 'home').mkdir()
        (t / 'w' / 'etc' / 'app.conf').write_text('x=1'); (t / 'w' / 'home' / 'n.txt').write_text('hi')
        self.cfgp = t / 'c.json'
        self.cfgp.write_text(json.dumps({
            'watch_paths': [{'path': (t / 'w' / 'etc').as_posix(), 'critical': True}, (t / 'w' / 'home').as_posix()],
            'database': (t / 'fim.db').as_posix(), 'log_file': (t / 'fim.log').as_posix(),
            'whitelist': ['*.tmp'], 'allowed_changes': [{'pattern': '*.log', 'events': 'CREATED'}],
            'sensitive_paths': ['*.conf'], 'work_hours': [0, 24]}))
        self.t = t
    def tearDown(self):
        import logging
        for h in logging.getLogger('fim').handlers: h.close()
        logging.getLogger('fim').handlers.clear(); self.tmp.cleanup()


class ServiceTest(_TempProject):
    """Luồng init -> thay đổi -> scan -> accept."""
    def test_scan_requires_baseline(self):
        with self.assertRaises(service.FimError): service.scan_baseline(str(self.cfgp))

    def test_full_flow(self):
        service.initialize(str(self.cfgp))
        (self.t / 'w' / 'etc' / 'app.conf').write_text('x=2')
        (self.t / 'w' / 'home' / 'app.log').write_text('log')
        (self.t / 'w' / 'home' / 'junk.tmp').write_text('ignored')
        _, results, _ = service.scan_baseline(str(self.cfgp), record=True)
        got = {ch.path.rsplit('/', 1)[-1]: v.verdict for ch, v in results}
        self.assertEqual(got, {'app.conf': 'SUSPICIOUS', 'app.log': 'LEGITIMATE'})
        db = FimDB(self.t / 'fim.db')
        try: self.assertEqual(len(db.alerts('NEW')), 1)
        finally: db.close()
        # accept 1 file -> chỉ còn app.log; accept --all -> sạch
        service.accept(str(self.cfgp), str(self.t / 'w' / 'etc' / 'app.conf'))
        self.assertEqual([c.path.rsplit('/', 1)[-1] for c, _ in service.scan_baseline(str(self.cfgp))[1]], ['app.log'])
        service.accept(str(self.cfgp))
        self.assertEqual(service.scan_baseline(str(self.cfgp))[1], [])

    def test_process_once_and_ignore_added_later(self):
        service.initialize(str(self.cfgp))
        cfg = service.load_config(str(self.cfgp)); db = service.open_db(cfg); lg = service.logger_for(cfg['log_file'])
        try:
            (self.t / 'w' / 'home' / 'n.txt').write_text('changed!')
            self.assertEqual([c.event_type for c, _ in service.process_once(cfg, db, lg)], ['MODIFIED'])
            self.assertEqual(service.process_once(cfg, db, lg), [])
            db.whitelist_add('*.txt', 'ignore')       # thêm ignore sau => không được báo là DELETED
            self.assertEqual(service.process_once(cfg, db, lg), [])
        finally: db.close()


    def test_accept_moved_removes_old_path(self):
        service.initialize(str(self.cfgp))
        old, new = self.t / 'w' / 'home' / 'n.txt', self.t / 'w' / 'home' / 'n.txt.locked'
        old.rename(new)
        self.assertEqual([c.event_type for c, _ in service.scan_baseline(str(self.cfgp))[1]], ['MOVED'])
        service.accept(str(self.cfgp), [str(new), str(old)])
        self.assertEqual(service.scan_baseline(str(self.cfgp))[1], [])

    def test_failed_scan_does_not_stop_monitor(self):
        service.initialize(str(self.cfgp))
        cfg = service.load_config(str(self.cfgp)); db = service.open_db(cfg); lg = service.logger_for(cfg['log_file'])
        db.close()                                    # mọi truy vấn sau đây sẽ lỗi
        service._process_safely(cfg, db, lg)          # phải ghi log lỗi, không được ném ngoại lệ
        self.assertIn('Quét thất bại', (self.t / 'fim.log').read_text(encoding='utf-8'))

    def test_watch_path_without_path_key(self):
        self.cfgp.write_text(json.dumps({'watch_paths': [{'label': 'thiếu path'}]}))
        with self.assertRaises(service.FimError): service.load_config(str(self.cfgp))


class ScanDueTest(unittest.TestCase):
    """Điều kiện quét của monitor: debounce, và giới hạn chờ khi file bị ghi liên tục."""
    def test_waits_for_quiet_period(self):
        self.assertFalse(service.scan_due(now=10.3, dirty=True, first=10.0, last=10.0, debounce=0.5, max_wait=2.0))
        self.assertTrue(service.scan_due(now=10.6, dirty=True, first=10.0, last=10.0, debounce=0.5, max_wait=2.0))

    def test_busy_file_cannot_postpone_scan_forever(self):
        # sự kiện đến liên tục mỗi 0.2s (last luôn mới), nhưng sự kiện đầu tiên đã chờ 2.1s
        self.assertTrue(service.scan_due(now=12.1, dirty=True, first=10.0, last=12.0, debounce=0.5, max_wait=2.0))

    def test_nothing_to_do(self):
        self.assertFalse(service.scan_due(now=99.0, dirty=False, first=0.0, last=0.0, debounce=0.5, max_wait=2.0))


class DashboardTest(_TempProject):
    def client(self, with_token=True):
        try: from fim.dashboard import create_app
        except ImportError: self.skipTest('flask not installed')
        c = create_app(str(self.cfgp)).test_client()
        if with_token:
            with c.session_transaction() as s: s['csrf'] = 'test-token'
        return c

    def test_pages(self):
        service.initialize(str(self.cfgp))
        (self.t / 'w' / 'etc' / 'app.conf').write_text('x=3'); service.scan_baseline(str(self.cfgp), record=True)
        c = self.client()
        for url in ('/', '/events', '/events?verdict=SUSPICIOUS&q=app', '/alerts', '/alerts?status=ALL', '/whitelist', '/scope'):
            self.assertEqual(c.get(url).status_code, 200, url)
        self.assertIn('app.conf', c.get('/alerts').get_data(as_text=True))
        self.assertIn('name="csrf"', c.get('/alerts').get_data(as_text=True))
        tok = {'csrf': 'test-token'}
        self.assertEqual(c.post('/whitelist/add', data={'pattern': '*.bak', 'kind': 'ignore', **tok}).status_code, 302)
        self.assertIn('*.bak', c.get('/whitelist').get_data(as_text=True))
        c.post('/whitelist/add', data={'pattern': '*.x', 'kind': 'bogus', **tok})           # kind sai: báo lỗi, không 500
        self.assertNotIn('*.x', c.get('/whitelist').get_data(as_text=True))
        self.assertEqual(c.post('/alerts/1/accept', data=tok).status_code, 302)
        self.assertIn('Không có cảnh báo', c.get('/alerts').get_data(as_text=True))
        self.assertEqual(service.scan_baseline(str(self.cfgp))[1], [])

    def test_post_without_csrf_token_is_rejected(self):
        service.initialize(str(self.cfgp))
        (self.t / 'w' / 'etc' / 'app.conf').write_text('attacker was here')
        c = self.client(with_token=False)
        # mô phỏng trang web lạ gửi form tới dashboard: không biết token => không được thực hiện
        c.post('/baseline/accept', data={})
        c.post('/whitelist/add', data={'pattern': '*', 'kind': 'ignore', 'csrf': 'guess'})
        self.assertNotIn('<td class="path">*</td>', c.get('/whitelist').get_data(as_text=True))
        self.assertEqual([ch.event_type for ch, _ in service.scan_baseline(str(self.cfgp))[1]], ['MODIFIED'])

    def test_accept_moved_alert_from_dashboard(self):
        service.initialize(str(self.cfgp))
        (self.t / 'w' / 'home' / 'n.txt').rename(self.t / 'w' / 'home' / 'n.txt.locked')
        service.scan_baseline(str(self.cfgp), record=True)
        c = self.client()
        self.assertEqual(c.post('/alerts/1/accept', data={'csrf': 'test-token'}).status_code, 302)
        self.assertEqual(service.scan_baseline(str(self.cfgp))[1], [])     # không còn báo DELETED đường dẫn cũ


if __name__ == '__main__': unittest.main()
