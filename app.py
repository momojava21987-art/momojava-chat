import os
import time
import sqlite3
import secrets

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'momo.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-' + secrets.token_hex(8))
socketio = SocketIO(app, cors_allowed_origins='*')

conns = {}     # phone -> number of connected devices
sessions = {}  # sid -> phone


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


with db() as _c:
    _c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        phone TEXT PRIMARY KEY, name TEXT NOT NULL, pw TEXT NOT NULL, token TEXT);
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL, receiver TEXT NOT NULL,
        content TEXT NOT NULL, ts INTEGER NOT NULL,
        status INTEGER NOT NULL DEFAULT 0);  -- 0 sent, 1 delivered, 2 read
    CREATE INDEX IF NOT EXISTS idx_pair ON messages(sender, receiver);
    ''')


def me():
    return sessions.get(request.sid)


@app.route('/')
def index():
    return render_template('index.html')


@socketio.on('login')
def login(d):
    phone = str(d.get('phone', '')).strip()
    name = str(d.get('name', '')).strip()[:30]
    password = str(d.get('password', ''))
    token = d.get('token')
    if not phone or len(phone) > 20:
        return emit('login_error', {'message': 'رقم الهاتف غير صالح'})

    with db() as c:
        u = c.execute('SELECT * FROM users WHERE phone=?', (phone,)).fetchone()
        if token:
            if not u or not secrets.compare_digest(u['token'] or '', str(token)):
                return emit('login_error', {'message': 'انتهت الجلسة', 'silent': True})
            out_token = u['token']
        else:
            if u:
                if not check_password_hash(u['pw'], password):
                    return emit('login_error', {'message': 'كلمة المرور غير صحيحة!'})
            else:
                if not name or len(password) < 4:
                    return emit('login_error', {'message': 'الاسم مطلوب وكلمة المرور 4 أحرف على الأقل'})
                c.execute('INSERT INTO users(phone,name,pw) VALUES(?,?,?)',
                          (phone, name, generate_password_hash(password)))
            out_token = secrets.token_hex(24)
            c.execute('UPDATE users SET token=? WHERE phone=?', (out_token, phone))
        u = c.execute('SELECT name FROM users WHERE phone=?', (phone,)).fetchone()
        c.execute('UPDATE messages SET status=1 WHERE receiver=? AND status=0', (phone,))

    if request.sid not in sessions:
        sessions[request.sid] = phone
        join_room(phone)
        conns[phone] = conns.get(phone, 0) + 1
        if conns[phone] == 1:
            socketio.emit('presence', {'phone': phone, 'online': True})
    emit('login_success', {'phone': phone, 'name': u['name'], 'token': out_token})
    socketio.emit('refresh')


@socketio.on('disconnect')
def on_disconnect():
    phone = sessions.pop(request.sid, None)
    if phone:
        conns[phone] = conns.get(phone, 1) - 1
        if conns[phone] <= 0:
            conns.pop(phone, None)
            socketio.emit('presence', {'phone': phone, 'online': False})


@socketio.on('get_contacts')
def get_contacts():
    m = me()
    if not m:
        return
    out = []
    with db() as c:
        for u in c.execute('SELECT phone,name FROM users WHERE phone!=?', (m,)).fetchall():
            p = u['phone']
            last = c.execute(
                'SELECT content,ts FROM messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) '
                'ORDER BY id DESC LIMIT 1', (m, p, p, m)).fetchone()
            unread = c.execute(
                'SELECT COUNT(*) FROM messages WHERE sender=? AND receiver=? AND status<2', (p, m)).fetchone()[0]
            out.append({'phone': p, 'name': u['name'], 'online': p in conns,
                        'last': last['content'] if last else '', 'ts': last['ts'] if last else 0,
                        'unread': unread})
    emit('contacts', out)


@socketio.on('get_history')
def get_history(d):
    m, p = me(), str(d.get('with', ''))
    if not m or not p:
        return
    with db() as c:
        rows = c.execute(
            'SELECT * FROM messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) '
            'ORDER BY id DESC LIMIT 200', (m, p, p, m)).fetchall()
    emit('history', {'with': p, 'messages': [dict(r) for r in reversed(rows)]})
    mark_read({'with': p})


@socketio.on('mark_read')
def mark_read(d):
    m, p = me(), str(d.get('with', ''))
    if not m or not p:
        return
    with db() as c:
        c.execute('UPDATE messages SET status=2 WHERE sender=? AND receiver=? AND status<2', (p, m))
    socketio.emit('messages_read', {'by': m}, room=p)
    emit('refresh')


@socketio.on('send_message')
def send_message(d):
    m, to = me(), str(d.get('to', ''))
    content = str(d.get('content', '')).strip()[:2000]
    if not m or not to or not content:
        return
    with db() as c:
        if not c.execute('SELECT 1 FROM users WHERE phone=?', (to,)).fetchone():
            return
        status = 1 if to in conns else 0
        ts = int(time.time())
        cur = c.execute('INSERT INTO messages(sender,receiver,content,ts,status) VALUES(?,?,?,?,?)',
                        (m, to, content, ts, status))
        msg = {'id': cur.lastrowid, 'sender': m, 'receiver': to,
               'content': content, 'ts': ts, 'status': status}
    socketio.emit('receive_message', msg, room=to)
    socketio.emit('receive_message', msg, room=m)


@socketio.on('typing')
def typing(d):
    m = me()
    if m:
        socketio.emit('typing', {'from': m}, room=str(d.get('to', '')))


# ---------- WebRTC signaling (relay only; the sender comes from the session, not the client) ----------
@socketio.on('call_user')
def call_user(d):
    m = me()
    if not m:
        return
    with db() as c:
        u = c.execute('SELECT name FROM users WHERE phone=?', (m,)).fetchone()
    socketio.emit('incoming_call', {'from': m, 'fromName': u['name'],
                                    'type': d.get('type'), 'sdp': d.get('sdp')}, room=str(d.get('to')))


@socketio.on('answer_call')
def answer_call(d):
    if me():
        socketio.emit('call_answered', {'sdp': d.get('sdp')}, room=str(d.get('to')))


@socketio.on('ice')
def ice(d):
    m = me()
    if m:
        socketio.emit('ice', {'from': m, 'candidate': d.get('candidate')}, room=str(d.get('to')))


@socketio.on('end_call')
def end_call(d):
    m = me()
    if m:
        socketio.emit('call_ended', {'from': m}, room=str(d.get('to')))


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000,
                 debug=os.environ.get('DEBUG') == '1', allow_unsafe_werkzeug=True)