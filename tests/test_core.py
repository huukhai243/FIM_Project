import json, os, tempfile, time, unittest
from datetime import datetime
from pathlib import Path
from fim.core import FileState, compare_states, Change, scan_tree, matches
from fim.rules import classify
from fim.database import FimDB
from fim import service

DAY = datetime(2026, 1, 5, 10, 0)     # trong giờ làm việc
NIGHT = datetime(2026, 1, 5, 2, 0)


def fs(path, sha='a', size=1, mode=0o644, mtime=1, uid=None, gid=None):
    return FileState(path, sha, size, mtime, mode, uid, gid)


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
    def test_owner_changed(self):
        ch = compare_states({'a': fs('a', uid=1000, gid=1000)}, {'a': fs('a', uid=0, gid=0)})
        self.assertEqual(ch[0].event_type, 'OWNER_CHANGED')
    def test_owner_unknown_in_old_baseline_is_not_reported(self):   # baseline tạo từ phiên bản chưa lưu uid/gid
        self.assertEqual(compare_states({'a': fs('a')}, {'a': fs('a', uid=1000, gid=1000)}), [])
    def test_timestamp_only(self):
        self.assertEqual(compare_states({'a': fs('a', mtime=5)}, {'a': fs('a', mtime=9)})[0].event_type, 'TIMESTAMP_CHANGED')
    def test_content_change_is_not_reported_as_timestamp(self):
        self.assertEqual(compare_states({'a': fs('a', 'x', mtime=5)}, {'a': fs('a', 'y', mtime=9)})[0].event_type, 'MODIFIED')
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

    def test_touch_forward_is_legitimate(self):
        ch = Change('/r/etc/app.conf', 'TIMESTAMP_CHANGED', fs('/r/etc/app.conf', mtime=5), fs('/r/etc/app.conf', mtime=9))
        self.assertEqual(classify(ch, self.cfg, now=DAY).verdict, 'LEGITIMATE')

    def test_timestamp_moved_backwards_is_suspicious_even_if_allowed(self):
        ch = Change('/r/home/a.log', 'TIMESTAMP_CHANGED', fs('/r/home/a.log', mtime=9), fs('/r/home/a.log', mtime=5))
        v = classify(ch, self.cfg, [{'pattern': '*.log', 'events': '*'}], now=DAY)
        self.assertEqual(v.verdict, 'SUSPICIOUS'); self.assertIn('timestomp', v.details); self.assertIn('overridden', v.details)

    def test_modified_and_backdated_is_flagged(self):
        ch = Change('/r/home/n.txt', 'MODIFIED', fs('/r/home/n.txt', 'x', mtime=9), fs('/r/home/n.txt', 'y', mtime=5))
        v = classify(ch, self.cfg, now=DAY)
        self.assertEqual(v.verdict, 'SUSPICIOUS'); self.assertIn('timestomp', v.details)

    def test_burst_counts_changes_close_in_time_only(self):
        from fim.rules import burst_sizes
        spread = [Change(f'/r/home/{i}', 'CREATED', None, fs(f'/r/home/{i}', mtime=i * 120 * 10**9)) for i in range(12)]
        same = [Change(f'/r/home/{i}.enc', 'CREATED', None, fs(f'/r/home/{i}.enc', mtime=7 * 10**9)) for i in range(12)]
        self.assertEqual(set(burst_sizes(spread)), {1})
        self.assertEqual(set(burst_sizes(same)), {12})

    def test_owner_change_is_suspicious(self):
        ch = Change('/r/home/x', 'OWNER_CHANGED', fs('/r/home/x', uid=1000, gid=1000), fs('/r/home/x', uid=0, gid=0))
        v = classify(ch, self.cfg, now=DAY)
        self.assertEqual(v.verdict, 'SUSPICIOUS'); self.assertIn('owner changed', v.details)

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

    def test_patterns_match_like_fnmatch(self):
        """matches() gộp pattern thành một regex nhưng phải cho kết quả như fnmatch trên từng hệ điều hành."""
        import fnmatch
        cases = [('*.tmp', 'a/b.tmp'), ('*.TMP', 'a/b.tmp'), ('*/etc/*', '/x/etc/passwd'), ('__pycache__/', 'sub/__pycache__/'),
                 ('__pycache__/', '__pycache__/'), ('[!a]*.log', 'b.log'), ('[!a]*.log', 'a.log'), ('etc\\*', 'etc/x'), ('passwd', 'passwd.bak')]
        for pat, s in cases:
            self.assertEqual(matches([pat], s), fnmatch.fnmatch(s, pat), (pat, s))
        self.assertTrue(matches(['*.swp', '*.tmp'], 'x', 'y.tmp')); self.assertFalse(matches([], 'y.tmp'))


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


    def test_watch_paths_pointing_to_same_directory_are_merged(self):
        """Trên Debian, Ubuntu mới /bin là symlink tới /usr/bin: hai mục cùng trỏ một thư mục chỉ được giữ một."""
        cfg = json.loads(self.cfgp.read_text())
        cfg['watch_paths'].append({'path': (self.t / 'w' / 'home' / '..' / 'etc').as_posix(), 'label': 'dup', 'critical': False})
        cfg['watch_paths'].append({'path': (self.t / 'w' / 'home').as_posix(), 'critical': True})
        self.cfgp.write_text(json.dumps(cfg))
        ws = service.load_config(str(self.cfgp))['watch_paths']
        self.assertEqual([(Path(w['path']).name, bool(w.get('critical'))) for w in ws], [('etc', True), ('home', True)])
        self.assertNotIn('label', ws[0])

    def test_current_state_writes_only_changed_rows(self):
        db = FimDB(self.t / 'x.db')
        try:
            a, b = fs('/w/a'), fs('/w/b')
            self.assertEqual(db.update_current({'/w/a': a, '/w/b': b}, {}), 2)
            self.assertEqual(db.update_current({'/w/a': a, '/w/b': b}, db.load_current()), 0)   # không đổi -> không ghi
            a2 = fs('/w/a', sha='z')
            self.assertEqual(db.update_current({'/w/a': a2}, db.load_current()), 2)             # 1 sửa + 1 xóa
            self.assertEqual(db.load_current(), {'/w/a': a2})
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

    def test_audit_after_many_spread_out_changes_is_not_mass_change(self):
        """scan đối chiếu baseline sau nhiều giờ: 12 ghi chú sửa rải rác không phải 'hàng loạt'."""
        service.initialize(str(self.cfgp))
        t0 = time.time()
        for i in range(12):
            p = self.t / 'w' / 'home' / f'note{i}.txt'; p.write_text('x')
            os.utime(p, (t0 + i * 600, t0 + i * 600))      # mỗi file cách nhau 10 phút
        _, results, _ = service.scan_baseline(str(self.cfgp))
        self.assertEqual(len(results), 12)
        self.assertTrue(all(v.verdict == 'LEGITIMATE' for _, v in results), [v.details for _, v in results])

    def test_old_database_is_upgraded_without_false_owner_changes(self):
        import sqlite3
        db_path = self.t / 'old.db'
        con = sqlite3.connect(db_path)                    # CSDL phiên bản cũ: bảng trạng thái chưa có uid/gid
        con.execute('CREATE TABLE baseline(path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER)')
        con.execute("INSERT INTO baseline VALUES('/w/a', 'h', 1, 5, 420)"); con.commit(); con.close()
        db = FimDB(db_path)
        try:
            old = db.load_baseline()
            self.assertIsNone(old['/w/a'].uid)
            self.assertEqual(compare_states(old, {'/w/a': fs('/w/a', 'h', mode=420, mtime=5, uid=1000, gid=1000)}), [])
        finally: db.close()

    @unittest.skipUnless(os.name == 'posix', 'quyền Unix chỉ có trên Linux')
    def test_database_file_readable_by_owner_only(self):
        service.initialize(str(self.cfgp))
        self.assertEqual(os.stat(self.t / 'fim.db').st_mode & 0o777, 0o600)

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


class IntegrityTest(_TempProject):
    """Chữ ký HMAC: sửa thẳng CSDL (không qua FIM) phải bị phát hiện."""
    def setUp(self):
        super().setUp(); os.environ.pop('FIM_HMAC_KEY', None)
        service.initialize(str(self.cfgp)); self.cfg = service.load_config(str(self.cfgp))

    def sql(self, q, *a):
        import sqlite3
        con = sqlite3.connect(self.cfg['database']); con.execute(q, a); con.commit(); con.close()

    def test_signed_after_init_and_whitelist_changes(self):
        self.assertEqual(service.integrity_status(str(self.cfgp)), {'baseline': 'OK', 'whitelist': 'OK'})
        db = service.open_db(self.cfg)
        try: db.whitelist_add('*.bak', 'ignore'); db.whitelist_remove(1)
        finally: db.close()
        service.accept(str(self.cfgp), str(self.t / 'w' / 'etc' / 'app.conf'))
        self.assertEqual(service.integrity_status(str(self.cfgp)), {'baseline': 'OK', 'whitelist': 'OK'})
        self.assertTrue(Path(self.cfg['integrity_key_file']).is_file())

    def test_baseline_hash_forged_in_database(self):
        # kẻ tấn công sửa file rồi sửa luôn hash trong baseline cho khớp -> scan không thấy thay đổi, nhưng chữ ký lộ
        conf = self.t / 'w' / 'etc' / 'app.conf'; conf.write_text('backdoor=1')
        from fim.core import sha256_file
        st = conf.stat()
        self.sql('UPDATE baseline SET sha256=?, size=?, mtime_ns=? WHERE path=?',
                 sha256_file(conf), st.st_size, st.st_mtime_ns, conf.resolve().as_posix())
        self.assertEqual(service.scan_baseline(str(self.cfgp))[1], [])
        self.assertEqual(service.integrity_status(str(self.cfgp))['baseline'], 'TAMPERED')
        service.scan_baseline(str(self.cfgp), record=True); service.scan_baseline(str(self.cfgp), record=True)
        db = service.open_db(self.cfg)
        try:
            alerts = [a for a in db.alerts('NEW') if a['message'].startswith('INTEGRITY baseline')]
            self.assertEqual(len(alerts), 1)            # quét lại không tạo alert trùng
            self.assertEqual(alerts[0]['severity'], 'HIGH')
        finally: db.close()

    def test_whitelist_rule_inserted_directly(self):
        self.sql("INSERT INTO whitelist(pattern,kind,events) VALUES('*','ignore','*')")
        self.assertEqual(service.integrity_status(str(self.cfgp))['whitelist'], 'TAMPERED')

    def test_deleted_signature_or_key_is_reported(self):
        self.sql("DELETE FROM meta WHERE key='baseline_hmac'")
        self.assertEqual(service.integrity_status(str(self.cfgp))['baseline'], 'UNSIGNED')
        service.sign(str(self.cfgp))
        self.assertEqual(service.integrity_status(str(self.cfgp))['baseline'], 'OK')
        Path(self.cfg['integrity_key_file']).unlink()       # xóa khóa không được làm tắt việc kiểm tra
        self.assertEqual(service.integrity_status(str(self.cfgp))['baseline'], 'NO_KEY')

    def test_wrong_key_from_environment(self):
        os.environ['FIM_HMAC_KEY'] = 'another-key'
        try: self.assertEqual(service.integrity_status(str(self.cfgp))['baseline'], 'TAMPERED')
        finally: del os.environ['FIM_HMAC_KEY']


class NotifyTest(_TempProject):
    """Gửi cảnh báo qua webhook tới một HTTP server cục bộ."""
    def setUp(self):
        super().setUp()
        import http.server, threading
        got = self.got = []
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(200); self.end_headers()
            def log_message(self, *a): pass
        self.srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        cfg = json.loads(self.cfgp.read_text())
        cfg['notify'] = {'min_level': 'MEDIUM', 'webhook': {'url': f'http://127.0.0.1:{self.srv.server_port}/hook'}}
        self.cfgp.write_text(json.dumps(cfg))

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); super().tearDown()

    def test_one_message_per_scan_with_all_alerts(self):
        service.initialize(str(self.cfgp))
        (self.t / 'w' / 'etc' / 'app.conf').write_text('x=2')
        (self.t / 'w' / 'etc' / 'new.conf').write_text('y')
        (self.t / 'w' / 'home' / 'ok.txt').write_text('legit')          # LOW -> không gửi
        service.scan_baseline(str(self.cfgp), record=True)
        self.assertEqual(len(self.got), 1)
        sent = sorted(a['path'].rsplit('/', 1)[-1] for a in self.got[0]['alerts'])
        self.assertEqual(sent, ['app.conf', 'new.conf'])
        self.assertIn('2 cảnh báo mới', self.got[0]['text'])

    def test_min_level_filter_and_no_alerts(self):
        from fim import notify
        cfg = service.load_config(str(self.cfgp)); cfg['notify']['min_level'] = 'HIGH'
        self.assertEqual(notify.send(cfg, [{'path': '/x', 'event': 'MODIFIED', 'severity': 'MEDIUM'}]), 0)
        self.assertEqual(notify.send(cfg, []), 0)
        self.assertEqual(self.got, [])

    def test_unreachable_channel_does_not_raise(self):
        from fim import notify
        cfg = service.load_config(str(self.cfgp)); cfg['notify']['webhook']['url'] = 'http://127.0.0.1:9/none'
        lg = service.logger_for(cfg['log_file'])
        self.assertEqual(notify.send(cfg, [{'path': '/x', 'event': 'MODIFIED', 'severity': 'HIGH'}], lg), 1)
        self.assertIn('thất bại', (self.t / 'fim.log').read_text(encoding='utf-8'))

    def test_message_lists_at_most_ten_alerts(self):
        from fim import notify
        items = [{'path': f'/f{i}', 'event': 'MODIFIED', 'severity': 'HIGH', 'score': 5, 'reasons': []} for i in range(13)]
        title, text = notify.format_message(items)
        self.assertIn('13 cảnh báo', title); self.assertIn('và 3 cảnh báo khác', text)


class DashboardAuthTest(_TempProject):
    def setUp(self):
        super().setUp()
        try: from fim.dashboard import create_app
        except ImportError: self.skipTest('flask not installed')
        service.initialize(str(self.cfgp))
        os.environ['FIM_DASHBOARD_PASSWORD'] = 'correct horse'
        self.c = create_app(str(self.cfgp)).test_client()
        with self.c.session_transaction() as s: s['csrf'] = 'tok'

    def tearDown(self):
        os.environ.pop('FIM_DASHBOARD_PASSWORD', None); super().tearDown()

    def login(self, pw, next_url='/alerts'):
        r = self.c.post(f'/login?next={next_url}', data={'password': pw, 'csrf': 'tok'})
        with self.c.session_transaction() as s: s['csrf'] = 'tok'     # đăng nhập tạo phiên mới -> đặt lại token
        return r

    def test_pages_require_login(self):
        for url in ('/', '/events', '/alerts', '/whitelist', '/scope'):
            r = self.c.get(url); self.assertEqual(r.status_code, 302, url); self.assertIn('/login', r.headers['Location'])
        self.c.post('/whitelist/add', data={'pattern': '*', 'kind': 'ignore', 'csrf': 'tok'})
        db = service.open_db(service.load_config(str(self.cfgp)))
        try: self.assertNotIn('*', db.ignore_patterns())
        finally: db.close()

    def test_wrong_then_right_password_and_logout(self):
        r = self.c.post('/login', data={'password': 'x', 'csrf': 'tok'})
        self.assertIn('Sai mật khẩu', r.get_data(as_text=True))
        r = self.login('correct horse')
        self.assertEqual((r.status_code, r.headers['Location']), (302, '/alerts'))
        self.assertEqual(self.c.get('/').status_code, 200)
        self.assertIn('Đăng xuất', self.c.get('/').get_data(as_text=True))
        self.c.post('/logout', data={'csrf': 'tok'})
        self.assertEqual(self.c.get('/').status_code, 302)

    def test_lockout_after_repeated_failures(self):
        for _ in range(5): self.c.post('/login', data={'password': 'bad', 'csrf': 'tok'})
        self.login('correct horse')                                  # đúng mật khẩu nhưng đang bị khóa
        self.assertEqual(self.c.get('/').status_code, 302)

    def test_changing_password_invalidates_sessions(self):
        self.login('correct horse'); self.assertEqual(self.c.get('/').status_code, 200)
        os.environ['FIM_DASHBOARD_PASSWORD'] = 'new password!'
        self.assertEqual(self.c.get('/').status_code, 302)

    def test_open_redirect_is_blocked(self):
        self.assertEqual(self.login('correct horse', '//evil.example').headers['Location'], '/')


class CliEncodingTest(_TempProject):
    def test_vietnamese_output_through_pipe(self):
        """Trước đây: UnicodeEncodeError trên Windows khi output bị pipe/chuyển hướng (cp1252)."""
        import subprocess, sys
        env = {k: v for k, v in os.environ.items() if k not in ('PYTHONIOENCODING', 'PYTHONUTF8')}
        cfg = json.loads(self.cfgp.read_text())
        cfg['watch_paths'][0] = {'path': cfg['watch_paths'][0]['path'], 'label': 'Cấu hình hệ thống', 'critical': True}
        self.cfgp.write_text(json.dumps(cfg, ensure_ascii=False), encoding='utf-8')
        main = Path(__file__).resolve().parent.parent / 'main.py'
        out = {}
        for cmd in ('init', 'scope', 'whitelist', 'verify'):
            r = subprocess.run([sys.executable, str(main), '--config', str(self.cfgp), cmd], capture_output=True, env=env)
            self.assertEqual(r.returncode, 0, (cmd, r.stderr.decode('utf-8', 'replace')))
            out[cmd] = r.stdout.decode('utf-8')
        self.assertIn('Cấu hình hệ thống', out['scope']); self.assertIn('Toàn vẹn CSDL: OK', out['verify'])


if __name__ == '__main__': unittest.main()
