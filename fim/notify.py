"""Gửi cảnh báo ra ngoài: Telegram, email (SMTP), webhook (Slack/Discord/SIEM...).

Chỉ dùng thư viện chuẩn. Mỗi lần quét gom mọi alert thành MỘT tin nhắn (ransomware sửa 500 file không được
thành 500 tin). Lỗi mạng chỉ ghi log, không làm dừng monitor. Bí mật (token, mật khẩu) nên đặt qua biến môi trường
thay vì ghi vào config: FIM_TELEGRAM_TOKEN, FIM_TELEGRAM_CHAT_ID, FIM_SMTP_PASSWORD, FIM_WEBHOOK_URL.
"""
from __future__ import annotations
import json, os, smtplib, socket, threading, urllib.parse, urllib.request
from email.message import EmailMessage
from .config import short

LEVELS = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
MAX_LINES = 10          # số alert liệt kê chi tiết trong một tin nhắn
TIMEOUT = 10


def _settings(cfg) -> dict:
    """Gộp khối "notify" trong config với biến môi trường (biến môi trường được ưu tiên)."""
    n = cfg.get('notify') or {}
    tg = dict(n.get('telegram') or {}); em = dict(n.get('email') or {}); wh = dict(n.get('webhook') or {})
    env = os.environ.get
    tg['bot_token'] = env('FIM_TELEGRAM_TOKEN') or tg.get('bot_token')
    tg['chat_id'] = env('FIM_TELEGRAM_CHAT_ID') or tg.get('chat_id')
    em['password'] = env('FIM_SMTP_PASSWORD') or em.get('password')
    wh['url'] = env('FIM_WEBHOOK_URL') or wh.get('url')
    return {'min_level': str(n.get('min_level', 'MEDIUM')).upper(), 'telegram': tg, 'email': em, 'webhook': wh}


def channels(cfg) -> list[str]:
    s = _settings(cfg); out = []
    if s['telegram'].get('bot_token') and s['telegram'].get('chat_id'): out.append('telegram')
    if s['email'].get('smtp_host') and s['email'].get('to'): out.append('email')
    if s['webhook'].get('url'): out.append('webhook')
    return out


def format_message(items: list[dict]) -> tuple[str, str]:
    """(tiêu đề, nội dung) cho một lô alert."""
    by = {lv: sum(i['severity'] == lv for i in items) for lv in ('HIGH', 'MEDIUM', 'LOW')}
    summary = ', '.join(f'{n} {lv}' for lv, n in by.items() if n)
    title = f'[FIM] {len(items)} cảnh báo mới trên {socket.gethostname()} ({summary})'
    lines = [title, '']
    for i in items[:MAX_LINES]:
        lines.append(f"• [{i['severity']}] {i['event']} {short(i['path'])} (score {i.get('score', '-')})")
        if i.get('reasons'): lines.append('    ' + ', '.join(i['reasons']))
    if len(items) > MAX_LINES: lines.append(f'... và {len(items) - MAX_LINES} cảnh báo khác (xem dashboard)')
    return title, '\n'.join(lines)


def _post(url, data: bytes, content_type):
    req = urllib.request.Request(url, data=data, headers={'Content-Type': content_type, 'User-Agent': 'FIM'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r: r.read()


def _telegram(s, title, text, items):
    url = f"https://api.telegram.org/bot{s['bot_token']}/sendMessage"
    _post(url, urllib.parse.urlencode({'chat_id': s['chat_id'], 'text': text[:4000]}).encode(),
          'application/x-www-form-urlencoded')


def _email(s, title, text, items):
    msg = EmailMessage(); msg['Subject'] = title
    msg['From'] = s.get('from') or s.get('username') or 'fim@localhost'
    to = s['to']; msg['To'] = ', '.join(to if isinstance(to, list) else [to]); msg.set_content(text)
    port = int(s.get('smtp_port', 587))
    cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    with cls(s['smtp_host'], port, timeout=TIMEOUT) as smtp:
        if port != 465 and s.get('starttls', True): smtp.starttls()
        if s.get('username'): smtp.login(s['username'], s.get('password') or '')
        smtp.send_message(msg)


def _webhook(s, title, text, items):
    # 'text' cho Slack/Mattermost, 'content' cho Discord, 'alerts' cho SIEM / script tự viết
    body = {'text': text, 'content': text[:1900], 'title': title, 'alerts': items}
    _post(s['url'], json.dumps(body, ensure_ascii=False).encode('utf-8'), 'application/json')


SENDERS = {'telegram': _telegram, 'email': _email, 'webhook': _webhook}


def send(cfg, items: list[dict], lg=None, background=False):
    """Gửi các alert có mức >= min_level qua mọi kênh đã cấu hình. Trả về số alert được gửi.

    background=True (monitor): gửi trong luồng riêng để mạng chậm không làm trễ lần quét tiếp theo.
    """
    s = _settings(cfg); chans = channels(cfg)
    items = [i for i in items if LEVELS.get(i['severity'], 0) >= LEVELS.get(s['min_level'], 1)]
    if not chans or not items: return 0
    title, text = format_message(items)

    def run():
        for c in chans:
            try:
                SENDERS[c](s[c], title, text, items)
                if lg: lg.info('Đã gửi %d cảnh báo qua %s', len(items), c)
            except Exception as e:      # lỗi mạng / cấu hình sai: chỉ ghi log
                if lg: lg.warning('Gửi cảnh báo qua %s thất bại: %s', c, e)

    if background: threading.Thread(target=run, name='fim-notify', daemon=True).start()
    else: run()
    return len(items)
