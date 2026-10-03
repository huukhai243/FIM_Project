"""Web dashboard: lịch sử thay đổi, alert, whitelist, phạm vi giám sát."""
from __future__ import annotations
import os
from pathlib import Path
from flask import Flask, g, render_template, request, redirect, url_for, flash
from .config import load_config, FimError, short
from .service import open_db, accept

PAGE_SIZE = 50


def create_app(config='config.json') -> Flask:
    cfg = load_config(config)
    app = Flask(__name__)
    # chỉ dùng để ký cookie flash message; sinh ngẫu nhiên mỗi lần chạy (có thể đặt cố định qua biến môi trường)
    app.secret_key = os.environ.get('FIM_SECRET_KEY') or os.urandom(24)

    def db():
        if 'db' not in g: g.db = open_db(cfg)
        return g.db

    @app.teardown_appcontext
    def _close(_exc):
        d = g.pop('db', None)
        if d: d.close()

    @app.context_processor
    def _inject():
        if request.endpoint == 'static': return {}
        return {'new_alerts': db().conn.execute("SELECT COUNT(*) FROM alerts WHERE status='NEW'").fetchone()[0]}

    @app.route('/')
    def overview():
        st = db().stats()
        return render_template('overview.html', st=st, alerts=db().alerts('NEW', 8), cfg=cfg,
                               max_day=max([r['total'] for r in st['per_day']] or [1]))

    @app.route('/events')
    def events():
        f = {k: request.args.get(k) or None for k in ('level', 'verdict', 'event_type', 'q', 'source')}
        page = max(1, request.args.get('page', 1, type=int))
        total = db().count_events(**f)
        rows = db().events(PAGE_SIZE, (page - 1) * PAGE_SIZE, **f)
        return render_template('events.html', rows=rows, f=f, qs={k: v for k, v in f.items() if v}, page=page, total=total,
                               pages=max(1, -(-total // PAGE_SIZE)))

    @app.route('/alerts')
    def alerts():
        status = request.args.get('status', 'NEW')
        return render_template('alerts.html', rows=db().alerts(None if status == 'ALL' else status, 200), status=status)

    @app.post('/alerts/<int:aid>/ack')
    def ack(aid):
        db().ack_alert(aid); flash(f'Alert #{aid} đã được xác nhận.')
        return redirect(request.referrer or url_for('alerts'))

    @app.post('/alerts/ack-all')
    def ack_all():
        flash(f'Đã xác nhận {db().ack_all()} alert.'); return redirect(url_for('alerts'))

    @app.post('/alerts/<int:aid>/accept')
    def accept_alert(aid):
        row = db().conn.execute('SELECT path FROM alerts WHERE id=?', (aid,)).fetchone()
        if row:
            try:
                accept(cfg['_config_path'], row['path']); db().ack_alert(aid)
                flash(f'Đã chấp nhận {short(row["path"])} vào baseline và xác nhận alert #{aid}.')
            except FimError as e: flash(str(e), 'error')
        return redirect(request.referrer or url_for('alerts'))

    @app.route('/whitelist')
    def whitelist():
        return render_template('whitelist.html', rows=db().whitelist())

    @app.post('/whitelist/add')
    def whitelist_add():
        pat = request.form.get('pattern', '').strip()
        if not pat: flash('Pattern không được để trống.', 'error')
        else:
            ok = db().whitelist_add(pat, request.form.get('kind', 'ignore'), request.form.get('events') or '*',
                                    request.form.get('note', ''))
            flash(f'Đã thêm "{pat}".' if ok else f'"{pat}" đã tồn tại.', None if ok else 'error')
        return redirect(url_for('whitelist'))

    @app.post('/whitelist/<int:wid>/delete')
    def whitelist_delete(wid):
        db().whitelist_remove(wid); flash(f'Đã xóa rule #{wid}.'); return redirect(url_for('whitelist'))

    @app.route('/scope')
    def scope():
        base = db().load_baseline(); items = []
        for w in cfg['watch_paths']:
            r = w['path'].rstrip('/') + '/'
            files = [s for k, s in base.items() if k.startswith(r)]
            items.append(dict(w, exists=Path(w['path']).is_dir(), files=len(files), size=sum(s.size for s in files)))
        return render_template('scope.html', items=items, st=db().stats(), cfg=cfg)

    @app.post('/baseline/accept')
    def baseline_accept():
        try: flash(f'Đã cập nhật baseline: {accept(cfg["_config_path"])} file.')
        except FimError as e: flash(str(e), 'error')
        return redirect(url_for('scope'))

    app.add_template_filter(short, 'short')

    @app.template_filter('size')
    def _size(n):
        for u in ('B', 'KB', 'MB', 'GB'):
            if n < 1024: return f'{n:.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
            n /= 1024
        return f'{n:.1f} TB'

    return app
