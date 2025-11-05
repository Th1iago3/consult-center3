from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, send_from_directory, url_for, abort, send_file
import json
import os
import secrets
import requests
from datetime import datetime, timedelta
import logging
import time
import re
import uuid
from functools import wraps
import colorama
from colorama import Fore, Style
import urllib3
import fitz
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import hashlib
import hmac
import threading
import fcntl
import ssl
import certifi
import zipfile
from io import BytesIO
import shutil

# === INICIALIZAÇÃO ===
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'novidades')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('fonts', exist_ok=True)

# === CRIPTOGRAFIA E2E ===
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(data: str) -> str:
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    try:
        return cipher.decrypt(token.encode()).decode()
    except:
        return None

# === JWT SEGURO ===
JWT_SECRET = hashlib.sha3_512(secrets.token_bytes(64)).hexdigest()
JWT_ALGORITHM = 'HS512'
JWT_EXPIRATION = 3600

def generate_jwt(user_id: str, role: str, device_id: str):
    payload = {
        'user_id': encrypt_data(user_id),
        'role': encrypt_data(role),
        'device_id': encrypt_data(device_id),
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
        'iat': datetime.utcnow(),
        'jti': secrets.token_hex(16)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encrypt_data(token)

def verify_jwt(token: str):
    try:
        decrypted = decrypt_data(token)
        if not decrypted:
            return None
        payload = jwt.decode(decrypted, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {
            'user_id': decrypt_data(payload['user_id']),
            'role': decrypt_data(payload['role']),
            'device_id': decrypt_data(payload['device_id']),
            'jti': payload['jti']
        }
    except:
        return None

# === COOKIES SEGUROS E ÚNICOS ===
def set_secure_cookie(resp, name, value):
    domain = request.host.split(':')[0]
    resp.set_cookie(
        name=name,
        value=value,
        max_age=JWT_EXPIRATION,
        httponly=True,
        secure=True,
        samesite='Strict',
        domain=domain,
        path='/'
    )

# === DETECÇÃO DE BOTS / SELENIUM / WEBDRIVER ===
def is_real_browser():
    ua = request.headers.get('User-Agent', '').lower()
    headers = request.headers
    js = request.cookies.get('js_enabled')
    canvas = request.cookies.get('canvas_fp')
    webgl = request.cookies.get('webgl_fp')

    bot_patterns = ['bot', 'spider', 'crawler', 'headless', 'selenium', 'phantomjs', 'webdriver', 'puppeteer', 'playwright', 'scrapy', 'python-requests']
    if any(p in ua for p in bot_patterns):
        return False

    required_headers = ['Accept', 'Accept-Language', 'Accept-Encoding', 'Upgrade-Insecure-Requests']
    if not all(h in headers for h in required_headers):
        return False

    if not js or not canvas or not webgl:
        return False

    if not re.search(r'chrome|firefox|safari|edge', ua):
        return False

    return True

@app.before_request
def security_check():
    if request.endpoint in ['static', 'preview', 'creditos']:
        return

    if not is_real_browser():
        abort(403)

    fp = hashlib.sha256(f"{request.remote_addr}{request.headers.get('User-Agent')}".encode()).hexdigest()
    if 'device_id' not in session:
        session['device_id'] = fp

# === JSON COM LOCK + CRIPTOGRAFIA ===
def initialize_json(file_path, default_data={}):
    if not os.path.exists(file_path):
        save_data(default_data, file_path)

def load_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            fcntl.flock(file.fileno(), fcntl.LOCK_SH)
            raw = file.read()
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            decrypted = decrypt_data(raw)
            return json.loads(decrypted) if decrypted else default_data
    except:
        return default_data

def save_data(data, file_path):
    encrypted = encrypt_data(json.dumps(data, default=str))
    with open(file_path, 'w', encoding='utf-8') as file:
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        file.write(encrypted)
        fcntl.flock(file.fileno(), fcntl.LOCK_UN)

# === INICIALIZAÇÃO DE ARQUIVOS ===
initialize_json('users.json', {})
initialize_json('notifications.json', {})
initialize_json('gifts.json', {})
initialize_json('news.json', [])

# === MÓDULOS ===
module_status = {
    'cpfdata': 'ON', 'cpflv': 'OFF', 'cpf': 'ON', 'cpf2': 'ON', 'vacinas': 'ON',
    'cpf3': 'ON', 'nomelv': 'ON', 'nome': 'ON', 'nome2': 'ON', 'tel': 'OFF',
    'telLv': 'ON', 'teldual': 'OFF', 'datanome': 'ON', 'placa': 'ON',
    'placaestadual': 'OFF', 'fotor': 'ON', 'pix': 'ON', 'placalv': 'ON',
    'ip': 'ON', 'likeff': 'OFF', 'mae': 'ON', 'pai': 'ON', 'cnpjcompleto': 'ON',
    'atestado': 'OFF', 'cpf5': 'OFF', 'visitas': 'OFF', 'crash_ios': 'ON',
    'email': 'ON'
}
chave = "vmb1"

# === USO DE MÓDULOS ===
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})
    if user.get('role') == 'admin':
        return True
    permissions = user.get('permissions', {})
    if module not in permissions or datetime.now() > datetime.strptime(permissions[module], '%Y-%m-%d'):
        return False
    if 'modules' not in user:
        user['modules'] = {m: 0 for m in module_status}
    today = datetime.now().date().isoformat()
    if user.get('last_reset') != today:
        user['modules'] = {m: 0 for m in module_status}
        user['last_reset'] = today
    if increment:
        user['modules'][module] += 1
    limit = {'guest': 0, 'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(user.get('role'), 0)
    if user['modules'][module] > limit:
        return False
    users[user_id] = user
    save_data(users, 'users.json')
    return True

# === DECORATOR JWT ===
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            resp = make_response(redirect('/'))
            resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            return resp
        payload = verify_jwt(token)
        if not payload or payload['device_id'] != session.get('device_id'):
            resp = make_response(redirect('/'))
            resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            return resp
        g.user_id = payload['user_id']
        g.role = payload['role']
        users = load_data('users.json')
        user = users.get(g.user_id, {})
        if user.get('role') not in ['admin', 'guest'] and datetime.now() > datetime.strptime(user['expiration'], '%Y-%m-%d'):
            resp = make_response(redirect('/'))
            resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            return resp
        return f(*args, **kwargs)
    return decorated

# === LOGIN / REGISTER ===
@app.route('/', methods=['GET', 'POST'])
def login_or_register():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('user', '').strip()
        password = request.form.get('password', '').strip()
        users = load_data('users.json')
        device_id = session.get('device_id')

        if action == 'login':
            if username in users and check_password_hash(users[username]['password'], password):
                user = users[username]
                if user['role'] != 'admin' and datetime.now() > datetime.strptime(user['expiration'], '%Y-%m-%d'):
                    flash('Conta expirada.', 'error')
                    return render_template('login.html')
                if device_id not in user.get('devices', []):
                    user['devices'] = (user.get('devices', []) + [device_id])[-5:]
                    save_data(users, 'users.json')
                token = generate_jwt(username, user['role'], device_id)
                resp = make_response(redirect('/dashboard'))
                set_secure_cookie(resp, 'auth_token', token)
                set_secure_cookie(resp, 'js_enabled', '1')
                set_secure_cookie(resp, 'canvas_fp', hashlib.md5(str(time.time()).encode()).hexdigest())
                set_secure_cookie(resp, 'webgl_fp', secrets.token_hex(16))
                return resp
            flash('Credenciais inválidas.', 'error')

        elif action == 'register':
            if username in users:
                flash('Usuário já existe.', 'error')
                return render_template('login.html')
            hashed = generate_password_hash(password)
            users[username] = {
                'password': hashed,
                'plain_password': password,
                'role': 'guest',
                'expiration': '2099-12-31',
                'permissions': {},
                'modules': {m: 0 for m in module_status},
                'read_notifications': [],
                'affiliate_code': secrets.token_urlsafe(8),
                'devices': [device_id],
                'token': f"{username}-KEY{secrets.token_hex(13)}.center"
            }
            save_data(users, 'users.json')
            flash('Registrado com sucesso.', 'success')
            return redirect('/')

    return render_template('login.html')

# === DASHBOARD ===
@app.route('/dashboard', methods=['GET', 'POST'])
@jwt_required
def dashboard():
    users = load_data('users.json')
    user = users[g.user_id]
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    is_admin = g.role == 'admin'
    is_guest = g.role == 'guest'
    affiliate_link = url_for('login_or_register', aff=user.get('affiliate_code'), _external=True) if not is_guest else None
    max_limit = 999999 if is_admin else {'guest': 10, 'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(g.role, 0)

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'redeem':
            code = request.form.get('code')
            gifts = load_data('gifts.json')
            if code in gifts and gifts[code]['uses_left'] > 0:
                gift = gifts[code]
                exp_date = (datetime.now() + timedelta(days=gift['expiration_days'])).strftime('%Y-%m-%d')
                modules = module_status.keys() if gift['modules'] == 'all' else gift['modules']
                for m in modules:
                    if m in module_status:
                        user['permissions'][m] = exp_date
                if user['role'] == 'guest':
                    user['role'] = 'user_anual' if gift['expiration_days'] > 30 else 'user_mensal' if gift['expiration_days'] > 7 else 'user_semanal'
                    user['expiration'] = exp_date
                if 'token' not in user:
                    user['token'] = f"{g.user_id}-KEY{secrets.token_hex(13)}.center"
                gifts[code]['uses_left'] -= 1
                if gifts[code]['uses_left'] == 0:
                    del gifts[code]
                users[g.user_id] = user
                save_data(users, 'users.json')
                save_data(gifts, 'gifts.json')
                flash('Gift ativado!', 'success')

        elif is_admin and action == 'view_modules':
            target_user = request.form.get('user')
            module = request.form.get('module')
            if target_user in users:
                user_modules = users[target_user].get('modules', {})
                role = users[target_user].get('role', 'user_semanal')
                max_requests = {'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(role, 30) if role != 'admin' else 'Unlimited'
                return jsonify({"user": target_user, "modules": {module: user_modules.get(module, 0)} if module else user_modules, "maxRequests": max_requests})

    return render_template('dashboard.html', user=user, unread=unread_count, admin=is_admin, guest=is_guest, affiliate_link=affiliate_link, notifications=notifications, module_status=module_status, max_limit=max_limit)

# === ADMIN PANEL ===
@app.route('/i/settings/admin', methods=['GET', 'POST'])
@jwt_required
def admin_panel():
    if g.role != 'admin':
        abort(403)
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    gifts = load_data('gifts.json')

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == "add_user":
                user_input = request.form.get('user')
                password = request.form.get('password')
                expiration = request.form.get('expiration')
                role = request.form.get('role', 'user_semanal')
                if user_input in users:
                    return jsonify({'message': 'Usuário já existe.', 'category': 'error'})
                hashed_pw = generate_password_hash(password)
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                users[user_input] = {
                    'password': hashed_pw,
                    'plain_password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'permissions': {m: expiration for m in module_status.keys()} if role != 'guest' else {},
                    'modules': {m: 0 for m in module_status.keys()},
                    'read_notifications': [],
                    'affiliate_code': secrets.token_urlsafe(8) if role != 'guest' else None,
                    'devices': []
                }
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário adicionado!', 'category': 'success', 'user': user_input, 'password': password, 'token': token, 'expiration': expiration, 'role': role})

            elif action == "delete_user":
                user_input = request.form.get('user')
                password = request.form.get('password')
                if user_input in users and check_password_hash(users[user_input]['password'], password):
                    del users[user_input]
                    save_data(users, 'users.json')
                    return jsonify({'message': 'Usuário excluído!', 'category': 'success'})
                return jsonify({'message': 'Credenciais inválidas.', 'category': 'error'})

            elif action == "view_users":
                users_dict = {}
                for k, v in users.items():
                    user_data = {kk: vv for kk, vv in v.items() if kk != 'devices'}
                    if 'plain_password' in v:
                        user_data['password'] = v['plain_password']
                    users_dict[k] = user_data
                return jsonify({'users': users_dict})

            elif action == "send_message":
                message = request.form.get('message')
                user_input = request.form.get('user', 'all')
                notif_id = str(uuid.uuid4())
                if user_input == 'all':
                    for u in users:
                        if u != g.user_id:
                            notifications.setdefault(u, []).append({'id': notif_id, 'message': message, 'timestamp': datetime.now().isoformat()})
                else:
                    if user_input in users:
                        notifications.setdefault(user_input, []).append({'id': notif_id, 'message': message, 'timestamp': datetime.now().isoformat()})
                save_data(notifications, 'notifications.json')
                return jsonify({'message': 'Mensagem enviada!', 'category': 'success'})

            elif action == "reset_device":
                user_input = request.form.get('user')
                password = request.form.get('password')
                if user_input in users and check_password_hash(users[user_input]['password'], password):
                    users[user_input]['devices'] = []
                    save_data(users, 'users.json')
                    if user_input == g.user_id:
                        resp = make_response(jsonify({'message': 'Dispositivos resetados! Você foi deslogado.', 'category': 'success'}))
                        resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
                        return resp
                    return jsonify({'message': 'Dispositivos resetados!', 'category': 'success'})
                return jsonify({'message': 'Credenciais inválidas.', 'category': 'error'})

            elif action == "toggle_module":
                module = request.form.get('module')
                status = request.form.get('status')
                if module in module_status:
                    module_status[module] = status
                    return jsonify({'success': True, 'message': f'Módulo {module} {status}'})

            elif action == 'create_gift':
                modules = request.form.get('modules', 'all')
                expiration_days = int(request.form.get('expiration_days', 30))
                uses = int(request.form.get('uses', 1))
                code = secrets.token_urlsafe(12)
                gifts[code] = {
                    'modules': modules if modules == 'all' else modules.split(','),
                    'expiration_days': expiration_days,
                    'uses_left': uses,
                    'created': datetime.now().isoformat()
                }
                save_data(gifts, 'gifts.json')
                return jsonify({'message': 'Gift criado!', 'code': code, 'category': 'success'})

            elif action == "view_gifts":
                return jsonify({'gifts': gifts})

            elif action == 'get_stats':
                active_users = sum(1 for u in users.values() if u.get('role') != 'guest' and datetime.now() < datetime.strptime(u['expiration'], '%Y-%m-%d'))
                return jsonify({'active_users': active_users})

            elif action == 'backup':
                zip_buffer = BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for file_name in ['users.json', 'notifications.json', 'gifts.json', 'news.json']:
                        if os.path.exists(file_name):
                            zip_file.write(file_name)
                    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        if os.path.isfile(file_path):
                            zip_file.write(file_path, os.path.join('novidades', filename))
                zip_buffer.seek(0)
                return send_file(zip_buffer, as_attachment=True, download_name='backup.zip', mimetype='application/zip')

            elif action == 'restore':
                if 'zip_file' not in request.files:
                    return jsonify({'message': 'Nenhum arquivo.', 'category': 'error'})
                zip_file = request.files['zip_file']
                if not zip_file.filename.endswith('.zip'):
                    return jsonify({'message': 'Arquivo inválido.', 'category': 'error'})
                temp_dir = 'temp_restore'
                os.makedirs(temp_dir, exist_ok=True)
                try:
                    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                    for file_name in ['users.json', 'notifications.json', 'gifts.json', 'news.json']:
                        extracted = os.path.join(temp_dir, file_name)
                        if os.path.exists(extracted):
                            shutil.copy(extracted, file_name)
                    nov_dir = os.path.join(temp_dir, 'novidades')
                    if os.path.exists(nov_dir):
                        for filename in os.listdir(nov_dir):
                            shutil.copy(os.path.join(nov_dir, filename), app.config['UPLOAD_FOLDER'])
                    shutil.rmtree(temp_dir)
                    return jsonify({'message': 'Restauração concluída!', 'category': 'success'})
                except Exception as e:
                    shutil.rmtree(temp_dir)
                    return jsonify({'message': 'Erro na restauração.', 'category': 'error'})

        except Exception as e:
            return jsonify({'message': 'Algo deu errado.', 'category': 'error'})

    return render_template('admin.html', users=users, gifts=gifts, modules_state=module_status)

# === NOTIFICAÇÕES ===
@app.route('/notifications', methods=['GET', 'POST'])
@jwt_required
def notifications_page():
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    notifications = load_data('notifications.json').get(g.user_id, [])
    read_ids = user.get('read_notifications', [])
    unread = [n for n in notifications if n['id'] not in read_ids]
    read = [n for n in notifications if n['id'] in read_ids]
    if request.method == 'POST':
        notif_id = request.form.get('id')
        if notif_id not in read_ids:
            read_ids.append(notif_id)
            user['read_notifications'] = read_ids
            users[g.user_id] = user
            save_data(users, 'users.json')
        return jsonify({'success': True})
    return render_template('notifications.html', unread=unread, read=read, users=users)

# === NOVIDADES ===
@app.route('/novidades', methods=['GET'])
@jwt_required
def novidades():
    users = load_data('users.json')
    if users[g.user_id]['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    return render_template('novidades.html', news=news, users=users)

@app.route('/novidades/new', methods=['GET', 'POST'])
@jwt_required
def new_novidade():
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title')
        desc = request.form.get('desc')
        image = request.files.get('image')
        news = load_data('news.json')
        news_id = str(uuid.uuid4())
        image_path = None
        if image and image.filename:
            ext = os.path.splitext(image.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                image_filename = f'{news_id}{ext}'
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                image_path = f'/static/novidades/{image_filename}'
        news.append({
            'id': news_id,
            'title': title,
            'desc': desc,
            'image': image_path,
            'date': datetime.now().isoformat(),
            'sender': g.user_id
        })
        save_data(news, 'news.json')
        return redirect('/novidades')
    return render_template('new_novidade.html', users=users)

@app.route('/novidades/edit/<news_id>', methods=['GET', 'POST'])
@jwt_required
def edit_novidade(news_id):
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    item = next((n for n in news if n['id'] == news_id), None)
    if not item or (item['sender'] != g.user_id and user['role'] != 'admin'):
        abort(403)
    if request.method == 'POST':
        item['title'] = request.form.get('title')
        item['desc'] = request.form.get('desc')
        image = request.files.get('image')
        if image and image.filename:
            ext = os.path.splitext(image.filename)[1].lower()
            image_filename = f'{news_id}{ext}'
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            item['image'] = f'/static/novidades/{image_filename}'
        save_data(news, 'news.json')
        return redirect('/novidades')
    return render_template('edit_novidade.html', item=item, users=users)

@app.route('/novidades/delete/<news_id>', methods=['POST'])
@jwt_required
def delete_novidade(news_id):
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    item = next((n for n in news if n['id'] == news_id), None)
    if not item or (item['sender'] != g.user_id and user['role'] != 'admin'):
        abort(403)
    news.remove(item)
    if item['image']:
        try:
            os.remove(app.root_path + item['image'])
        except:
            pass
    save_data(news, 'news.json')
    flash('Novidade excluída!', 'success')
    return redirect('/novidades')

# === API GENÉRICA ===
def generic_api_call(url, module, process_func=None, flash_error=True):
    try:
        response = requests.get(url, verify=certifi.where(), timeout=30)
        response.raise_for_status()
        raw_text = response.text.lstrip('\ufeff')
        data = json.loads(raw_text)
        if not isinstance(data, (dict, list)):
            if flash_error:
                flash('Resposta da API inválida.', 'error')
            return None
        if process_func:
            try:
                processed = process_func(data)
                if processed is not None and isinstance(processed, (dict, list)):
                    data = processed
                else:
                    data = None
            except:
                data = None
        if data and manage_module_usage(g.user_id, module):
            return data
        if flash_error:
            flash('Sem resultado ou limite excedido.', 'error')
        return None
    except:
        if flash_error:
            flash('Erro de conexão.', 'error')
        return None

# === TODOS OS MÓDULOS ===
@app.route('/modulos/mae', methods=['GET', 'POST'])
@jwt_required
def mae():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('mae.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)
        nome = request.form.get('nome')
        if not nome:
            flash('NOME não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=mae"
            process = lambda d: d.get('response', []) if isinstance(d, dict) and d.get('status') else []
            result = generic_api_call(url, 'mae', process)
    return render_template('mae.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/pai', methods=['GET', 'POST'])
@jwt_required
def pai():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('pai.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)
        nome = request.form.get('nome')
        if not nome:
            flash('NOME não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=pai"
            process = lambda d: d.get('response', []) if isinstance(d, dict) and d.get('status') else []
            result = generic_api_call(url, 'pai', process)
    return render_template('pai.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/crash_ios', methods=['GET', 'POST'])
@jwt_required
def crash_ios():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifs = load_data('notifications.json')
    unread = len([n for n in notifs.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    numero = ""
    if request.method == 'POST':
        if not is_admin:
            token_input = request.form.get('token')
            if not token_input or token_input != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('crash_ios.html', is_admin=is_admin, notifications=unread, result=result, numero=numero)
        numero = request.form.get('numero', '').strip()
        if len(numero) < 10:
            flash('Número inválido.', 'error')
        else:
            if not manage_module_usage(g.user_id, 'crash_ios'):
                flash('Limite diário excedido.', 'error')
            else:
                bot_url = "https://rocket-client-dwsw.onrender.com"
                api_token = "401df5aba8f04b86adba63de442903d3"
                url = f"{bot_url}/crash-ios?token={api_token}&query={numero}"
                try:
                    resp = requests.get(url, timeout=15)
                    result = resp.json()
                    if not result.get('success'):
                        flash(result.get('error', 'Falha'), 'error')
                        result = None
                except Exception as e:
                    flash(f'Erro na API: {str(e)}', 'error')
                    result = None
    return render_template('crash_ios.html', is_admin=is_admin, notifications=unread, result=result, numero=numero)

@app.route('/modulos/cnpjcompleto', methods=['GET', 'POST'])
@jwt_required
def cnpjcompleto():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cnpj_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cnpjcompleto.html', is_admin=is_admin, notifications=unread_count, result=result, cnpj_input=cnpj_input)
        cnpj_input = request.form.get('cnpj', '').strip()
        if len(cnpj_input) != 14:
            flash('CNPJ inválido. Digite 14 números.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cnpj_input}&tipo=cnpjcompleto"
            def process(d):
                if not isinstance(d, dict):
                    return None
                empresa = d.get("empresa", {})
                estab = empresa.get("estabelecimento", {})
                secundarias = [f"{a.get('subclasse', '')} - {a.get('descricao', '')}" for a in estab.get("atividades_secundarias", [])]
                socios = [f"{s.get('nome', 'Não informado')} ({s.get('qualificacao_socio', {}).get('descricao', 'Não informado')})" for s in empresa.get("socios", [])]
                return {
                    "razao_social": empresa.get("razao_social", "Não informado"),
                    "nome_fantasia": estab.get("nome_fantasia") or "Não informado",
                    "cnpj": f"{cnpj_input[:2]}.{cnpj_input[2:5]}.{cnpj_input[5:8]}/{cnpj_input[8:12]}-{cnpj_input[12:]}",
                    "abertura": estab.get("data_inicio_atividade", "Não informado"),
                    "situacao": estab.get("situacao_cadastral", "Não informado"),
                    "atividade_principal": f"{estab.get('atividade_principal', {}).get('subclasse', '')} - {estab.get('atividade_principal', {}).get('descricao', '')}",
                    "atividades_secundarias": secundarias or ["Nenhuma"],
                    "logradouro": f"{estab.get('tipo_logradouro', '')} {estab.get('logradouro', '')}, {estab.get('numero', '')}",
                    "complemento": estab.get("complemento") or "",
                    "bairro": estab.get("bairro", "Não informado"),
                    "municipio": estab.get("cidade", {}).get("nome", "Não informado"),
                    "uf": estab.get("estado", {}).get("sigla", "Não informado"),
                    "cep": estab.get("cep", "Não informado"),
                    "telefone": f"({estab.get('ddd1', '')}) {estab.get('telefone1', '')}" if estab.get('ddd1') else "Não informado",
                    "email": estab.get("email", "Não informado"),
                    "capital_social": f"R$ {empresa.get('capital_social', '0')}",
                    "natureza_juridica": empresa.get("natureza_juridica", {}).get("descricao", "Não informado"),
                    "porte": empresa.get("porte", {}).get("descricao", "Não informado"),
                    "socios": socios or ["Não informados"]
                }
            result = generic_api_call(url, 'cnpjcompleto', process)
    return render_template('cnpjcompleto.html', is_admin=is_admin, notifications=unread_count, result=result, cnpj_input=cnpj_input)

@app.route('/modulos/cpf', methods=['GET', 'POST'])
@jwt_required
def cpf():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=cpfv1"
            process = lambda d: d if isinstance(d, dict) and 'CPF' in d and d['CPF'] and d.get('NOME') else None
            result = generic_api_call(url, 'cpf', process)
    return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/cpf2', methods=['GET', 'POST'])
@jwt_required
def cpf2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=cpf_serasa"
            def process(d):
                if not isinstance(d, dict):
                    return None
                dados = d.get("DADOS", {})
                result = {
                    "NOME": dados.get("NOME", "Não informado"),
                    "NOME_MAE": dados.get("NOME_MAE", "Não informado"),
                    "SEXO": dados.get("SEXO", "Não informado"),
                    "DT_NASCIMENTO": dados.get("NASC", "Não informado"),
                    "FLAG_OBITO": dados.get("SO", "Não informado"),
                    "DT_OBITO": dados.get("DT_OB", "Não informado"),
                    "FAIXA_RENDA": dados.get("FAIXA_RENDA_ID", "Não informado"),
                    "RENDA_PRESUMIDA": dados.get("RENDA", "Não informado"),
                    "CBO": dados.get("CBO", "Não informado"),
                    "STATUS_RECEITA_FEDERAL": dados.get("CD_SIT_CAD", "Não informado"),
                    "QT_VEICULOS": dados.get("QT_VEICULOS", "Não informado"),
                    "EMAIL": ', '.join(d.get("EMAIL", [])) or "Não informado",
                    "TELEFONES": "SEM RESULTADO"
                }
                enderecos = d.get("ENDERECOS", [])
                if enderecos:
                    end = enderecos[0]
                    result.update({
                        "TIPO_ENDERECO": end.get("TIPO_ENDERECO_ID", "Não informado"),
                        "LOGRADOURO": end.get("LOGR_NOME", "Não informado"),
                        "NUMERO": end.get("LOGR_NUMERO", "Não informado"),
                        "COMPLEMENTO": end.get("LOGR_COMPLEMENTO", "Não informado"),
                        "BAIRRO": end.get("BAIRRO", "Não informado"),
                        "CIDADE": end.get("CIDADE", "Não informado"),
                        "ESTADO": end.get("UF", "Não informado"),
                        "CEP": end.get("CEP", "Não informado")
                    })
                tels = d.get("TELEFONE", [])
                if tels:
                    phones = [f"({tel.get('DDD', '')}) {tel.get('TELEFONE', '')}" for tel in tels if tel.get('DDD') and tel.get('TELEFONE')]
                    result["TELEFONES"] = ', '.join(phones) if phones else "SEM RESULTADO"
                return result
            result = generic_api_call(url, 'cpf2', process)
    return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/email', methods=['GET', 'POST'])
@jwt_required
def email():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    result = None
    email_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('email.html', is_admin=is_admin, result=result, email=email_input)
        email_input = request.form.get('email', '').strip()
        if not email_input:
            flash('E-mail não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={email_input}&tipo=email2"
            def process(data):
                if not data or not isinstance(data, list) or not data[0].get("DADOS"):
                    return None
                d = data[0]["DADOS"][0]
                email_data = data[0].get("EMAIL", {})
                enderecos = data[0].get("ENDERECOS", [])
                parentes = data[0].get("PARENTES", [])
                telefones = data[0].get("TELEFONE", [])
                return {
                    "NOME": d.get("NOME", "Não informado"),
                    "CPF": d.get("CPF", "Não informado"),
                    "NOME_MAE": d.get("NOME_MAE", "Não informado"),
                    "SEXO": d.get("SEXO", "Não informado"),
                    "DT_NASCIMENTO": d.get("NASC", "Não informado"),
                    "FLAG_OBITO": d.get("SO", "Não informado"),
                    "DT_OBITO": d.get("DT_OB", "Não informado"),
                    "FAIXA_RENDA": data[0]["PODER_AQUISITIVO"][0]["FX_PODER_AQUISITIVO"] if data[0].get("PODER_AQUISITIVO") else "Não informado",
                    "RENDA_PRESUMIDA": d.get("RENDA", "Não informado"),
                    "CBO": d.get("CBO", "Não informado"),
                    "STATUS_RECEITA_FEDERAL": d.get("CD_SIT_CAD", "Não informado"),
                    "EMAIL_VALIDACAO": {
                        "EMAIL": email_data.get("EMAIL", "Não informado"),
                        "SCORE": email_data.get("EMAIL_SCORE", "Não informado"),
                        "ESTRUTURA": email_data.get("ESTRUTURA", "Não informado"),
                        "BLACKLIST": email_data.get("BLACKLIST", "Não informado"),
                        "DOMINIO": email_data.get("DOMINIO", "Não informado"),
                        "PRIORIDADE": email_data.get("PRIORIDADE", "Não informado")
                    },
                    "ENDERECOS": enderecos,
                    "PARENTES": parentes,
                    "TELEFONES": ", ".join(f"({t['DDD']}) {t['TELEFONE']}" for t in telefones if t.get('DDD') and t.get('TELEFONE')) or "SEM RESULTADO"
                }
            result = generic_api_call(url, 'email', process)
    return render_template('email.html', is_admin=is_admin, result=result, email=email_input)

@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
@jwt_required
def cpfdata():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=cpfv3"
            def process(d):
                if not isinstance(d, dict) or not d.get('nome'):
                    return None
                processed_result = {
                    'nome': d.get('nome', 'SEM INFORMAÇÃO').rstrip('---'),
                    'cpf': d.get('documentos', {}).get('cpf', 'SEM INFORMAÇÃO').replace('.', '').replace('-', ''),
                    'sexo': d.get('sexo', 'SEM INFORMAÇÃO'),
                    'dataNascimento': {'nascimento': 'SEM INFORMAÇÃO', 'idade': 'SEM INFORMAÇÃO', 'signo': 'SEM INFORMAÇÃO'},
                    'nomeMae': d.get('mae', 'SEM INFORMAÇÃO'),
                    'nomePai': d.get('pai', 'SEM INFORMAÇÃO'),
                    'telefone': [],
                    'nacionalidade': {
                        'municipioNascimento': d.get('endereco', {}).get('municipio_residencia', 'SEM INFORMAÇÃO'),
                        'paisNascimento': d.get('endereco', {}).get('pais', 'SEM INFORMAÇÃO')
                    },
                    'enderecos': [],
                    'cnsDefinitivo': d.get('cns', 'SEM INFORMAÇÃO'),
                    'raca': d.get('raca', 'SEM INFORMAÇÃO'),
                    'tipo_sanguineo': d.get('tipo_sanguineo', 'SEM INFORMAÇÃO'),
                    'nome_social': d.get('nome_social', None) or 'Não possui'
                }
                nasc = d.get('nascimento', 'SEM INFORMAÇÃO')
                if ' (' in nasc and ' anos)' in nasc:
                    date_str = nasc.split(' (')[0]
                    age_str = nasc.split(' (')[1].rstrip(' anos)')
                    processed_result['dataNascimento'] = {'nascimento': date_str, 'idade': age_str, 'signo': 'SEM INFORMAÇÃO'}
                    try:
                        birth_date = datetime.strptime(date_str, '%d/%m/%Y')
                        month, day = birth_date.month, birth_date.day
                        signos = [(1,20,'Aquário'), (2,19,'Peixes'), (3,21,'Áries'), (4,20,'Touro'), (5,21,'Gêmeos'), (6,21,'Câncer'), (7,23,'Leão'), (8,23,'Virgem'), (9,23,'Libra'), (10,23,'Escorpião'), (11,22,'Sagitário'), (12,22,'Capricórnio')]
                        signo = next((s for m,d,s in signos if (month > m or (month == m and day >= d))), 'Capricórnio')
                        processed_result['dataNascimento']['signo'] = signo
                    except: pass
                telefones = d.get('contatos', {}).get('telefones', [])
                processed_result['telefone'] = [{'ddi': '', 'ddd': phone.get('ddd', '').strip('()'), 'numero': phone.get('numero', '')} for phone in telefones]
                endereco = d.get('endereco', {})
                if endereco and 'municipio_residencia' in endereco:
                    parts = endereco['municipio_residencia'].split(' - ')
                    endereco['cidade'] = parts[0] if len(parts) > 0 else 'SEM INFORMAÇÃO'
                    endereco['uf'] = parts[1] if len(parts) > 1 else 'SEM INFORMAÇÃO'
                processed_result['enderecos'] = [endereco] if endereco else []
                return processed_result
            result = generic_api_call(url, 'cpfdata', process)
    return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/cpf3', methods=['GET', 'POST'])
@jwt_required
def cpf3():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=cpffull"
            process = lambda d: d if isinstance(d, dict) and 'CPF' in d and d['CPF'] else None
            result = generic_api_call(url, 'cpf3', process)
    return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/cpflv', methods=['GET', 'POST'])
@jwt_required
def cpflv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"https://api.bygrower.online/core/?token={chave}&base=cpfLv&query={cpf_input}"
            process = lambda d: d.get('resultado') if isinstance(d, dict) and d.get('resultado') and d['resultado'].get('status') == 'success' and 'data' in d['resultado'] and 'pessoa' in d['resultado']['data'] and 'identificacao' in d['resultado']['data']['pessoa'] and 'cpf' in d['resultado']['data']['pessoa']['identificacao'] else None
            result = generic_api_call(url, 'cpflv', process)
    return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/vacinas', methods=['GET', 'POST'])
@jwt_required
def vacinas():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = []
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        if not cpf_input or len(cpf_input) != 11 or not cpf_input.isdigit():
            flash('CPF inválido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=vacina"
            process = lambda d: d.get('response', {}).get('dados', []) if isinstance(d, dict) and d.get('status') else d.get('resultado', []) if isinstance(d, dict) and 'resultado' in d else []
            results = generic_api_call(url, 'vacinas', process) or []
    return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf_input)

@app.route('/modulos/datanome', methods=['GET', 'POST'])
@jwt_required
def datanome():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = []
    nome = ""
    datanasc = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('datanome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome, datanasc=datanasc)
        nome = request.form.get('nome', '').strip()
        datanasc = request.form.get('datanasc', '').strip()
        if not nome or not datanasc:
            flash('Nome e data são obrigatórios.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
            def process(d):
                raw_results = d.get('response', []) if isinstance(d, dict) and d.get('status') else d if isinstance(d, list) else []
                try:
                    user_date = datetime.strptime(datanasc, '%Y-%m-%d').date()
                except ValueError:
                    return []
                filtered = []
                for item in raw_results:
                    if isinstance(item, dict) and 'NASCIMENTO' in item and item['NASCIMENTO']:
                        try:
                            api_date_str = item['NASCIMENTO'].strip()
                            api_date = datetime.strptime(api_date_str, '%d/%m/%Y').date()
                            if api_date == user_date:
                                filtered.append(item)
                        except:
                            continue
                return filtered
            results = generic_api_call(url, 'datanome', process) or []
    return render_template('datanome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome, datanasc=datanasc)

@app.route('/modulos/placalv', methods=['GET', 'POST'])
@jwt_required
def placalv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('placalv.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa)
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Placa inválida.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placacompleta"
            process = lambda d: d.get('response', {}).get('dados') if isinstance(d, dict) and d.get('status') and 'response' in d and 'dados' in d['response'] and d['response']['dados'].get('veiculo', {}).get('placa') else None
            result = generic_api_call(url, 'placalv', process)
    return render_template('placalv.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa)

@app.route('/modulos/telLv', methods=['GET', 'POST'])
@jwt_required
def telLv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    telefone = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('tellv.html', is_admin=is_admin, notifications=unread_count, result=result, telefone=telefone)
        telefone = ''.join(c for c in request.form.get('telefone', '').strip() if c.isdigit())
        if not telefone or len(telefone) < 10 or len(telefone) > 11:
            flash('Telefone inválido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={telefone}&tipo=telefonev2"
            process = lambda d: d.get('response') if isinstance(d, dict) and d.get('status') and 'response' in d and d['response'].get('CPF') and d['response']['CPF'] != 'SEM RESULTADO' else None
            result = generic_api_call(url, 'telLv', process)
    return render_template('tellv.html', is_admin=is_admin, notifications=unread_count, result=result, telefone=telefone)

@app.route('/modulos/teldual', methods=['GET', 'POST'])
@jwt_required
def teldual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    telefone = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('teldual.html', is_admin=is_admin, notifications=unread_count, results=results, telefone=telefone)
        telefone = request.form.get('telefone', '').strip()
        if not telefone:
            flash('Telefone não fornecido.', 'error')
        else:
            url = f"https://api.bygrower.online/core/?token={chave}&base=teldual&query={telefone}"
            process = lambda d: d.get('resultado') if isinstance(d, dict) and 'resultado' in d and d['resultado'] and any('cpf' in item for item in d['resultado']) else None
            results = generic_api_call(url, 'teldual', process)
    return render_template('teldual.html', is_admin=is_admin, notifications=unread_count, results=results, telefone=telefone)

@app.route('/modulos/tel', methods=['GET', 'POST'])
@jwt_required
def tel():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    tel_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('tel.html', is_admin=is_admin, notifications=unread_count, results=results, tel=tel_input)
        tel_input = request.form.get('tel', '').strip()
        if not tel_input:
            flash('Telefone não fornecido.', 'error')
        else:
            url = f"https://api.bygrower.online/core/?token={chave}&base=telefone&query={tel_input}"
            process = lambda d: d.get('resultado') if isinstance(d, dict) and 'resultado' in d and 'cpf' in d['resultado'] else None
            results = generic_api_call(url, 'tel', process)
    return render_template('tel.html', is_admin=is_admin, notifications=unread_count, results=results, tel=tel_input)

@app.route('/modulos/placa', methods=['GET', 'POST'])
@jwt_required
def placa():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('placa.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa_input)
        placa_input = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa_input or len(placa_input) != 7 or not (placa_input[:3].isalpha() and placa_input[3:].isdigit()):
            flash('Placa inválida.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa_input}&tipo=placanormal"
            process = lambda d: d if isinstance(d, dict) and d.get('PLACA') == placa_input else None
            result = generic_api_call(url, 'placa', process)
    return render_template('placa.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa_input)

@app.route('/modulos/placaestadual', methods=['GET', 'POST'])
@jwt_required
def placaestadual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    placa = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('placaestadual.html', is_admin=is_admin, notifications=unread_count, results=results, placa=placa)
        placa = request.form.get('placa', '').strip().upper()
        if not placa:
            flash('Placa não fornecida.', 'error')
        else:
            url = f"https://api.bygrower.online/core/?token={chave}&base=placaestadual&query={placa}"
            process = lambda d: d.get('resultado') if isinstance(d, dict) and 'resultado' in d and isinstance(d['resultado'], list) and len(d['resultado']) > 0 and d['resultado'][0].get('retorno') == 'ok' else None
            results = generic_api_call(url, 'placaestadual', process)
    return render_template('placaestadual.html', is_admin=is_admin, notifications=unread_count, results=results, placa=placa)

@app.route('/modulos/pix', methods=['GET', 'POST'])
@jwt_required
def pix():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    chave_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('pix.html', is_admin=is_admin, notifications=unread_count, result=result, chave=chave_input)
        chave_input = request.form.get('chave', '').strip()
        if not chave_input or len(chave_input) < 11:
            flash('Chave inválida.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={chave_input}&tipo=pix"
            process = lambda d: d if isinstance(d, dict) and d.get('Status') == 'Sucesso' and 'nome' in d else None
            result = generic_api_call(url, 'pix', process)
    return render_template('pix.html', is_admin=is_admin, notifications=unread_count, result=result, chave=chave_input)

@app.route('/modulos/fotor', methods=['GET', 'POST'])
@jwt_required
def fotor():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    documento = ""
    selected_option = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('fotor.html', is_admin=is_admin, notifications=unread_count, results=results, documento=documento, selected_option=selected_option)
        documento = request.form.get('documento', '').strip().replace('.', '').replace('-', '')
        selected_option = request.form.get('estado', '')
        if not documento or len(documento) != 11 or selected_option not in ['fotorj', 'fotoce', 'fotosp', 'fotoes', 'fotoma', 'fotoro']:
            flash('Dados inválidos.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={documento}&tipo={selected_option}"
            def process(data):
                try:
                    response_outer = data.get("response")
                    if not isinstance(response_outer, dict):
                        return {"foto_base64": "", "cpf": documento, "found": False}
                    response_inner = response_outer.get("response")
                    if not isinstance(response_inner, list) or len(response_inner) == 0:
                        return {"foto_base64": "", "cpf": documento, "found": False}
                    item = response_inner[0]
                    fotob64 = item.get("fotob64", "").strip()
                    cpf_retornado = item.get("cpf", "").strip()
                    cpf_final = cpf_retornado if cpf_retornado and len(cpf_retornado) == 11 else documento
                    if fotob64 and fotob64.startswith('/9j/'):
                        return {"foto_base64": fotob64, "cpf": cpf_final, "found": True}
                    else:
                        return {"foto_base64": "", "cpf": cpf_final, "found": False}
                except:
                    return {"foto_base64": "", "cpf": documento, "found": False}
            results = generic_api_call(url, 'fotor', process)
            if results is None:
                results = {"foto_base64": "", "cpf": documento, "found": False}
    return render_template('fotor.html', is_admin=is_admin, notifications=unread_count, results=results, documento=documento, selected_option=selected_option)

@app.route('/modulos/nomelv', methods=['GET', 'POST'])
@jwt_required
def nomelv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('nomelv.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:100.org10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
            process = lambda d: d.get('response', []) if isinstance(d, dict) and d.get('status') else d if isinstance(d, list) else None
            results = generic_api_call(url, 'nomelv', process)
    return render_template('nomelv.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/nome', methods=['GET', 'POST'])
@jwt_required
def nome():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('nome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev1"
            process = lambda d: d if isinstance(d, list) and len(d) > 0 else d.get('resultado', []) if isinstance(d, dict) and 'resultado' in d else None
            results = generic_api_call(url, 'nome', process)
    return render_template('nome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/ip', methods=['GET', 'POST'])
@jwt_required
def ip():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    ip_address = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('ip.html', is_admin=is_admin, notifications=unread_count, results=results, ip_address=ip_address)
        ip_address = request.form.get('ip', '').strip()
        if not ip_address:
            flash('IP não fornecido.', 'error')
        else:
            url = f"https://ipwho.is/{ip_address}"
            def process(d):
                if not isinstance(d, dict) or not d.get('success', False):
                    return None
                return {
                    'ip': d.get('ip'),
                    'continent': d.get('continent'),
                    'continent_code': d.get('continent_code'),
                    'country': d.get('country'),
                    'country_code': d.get('country_code'),
                    'region': d.get('region'),
                    'region_code': d.get('region_code'),
                    'city': d.get('city'),
                    'district': d.get('district'),
                    'zip': d.get('zip'),
                    'lat': d.get('latitude'),
                    'lon': d.get('longitude'),
                    'timezone': d.get('timezone'),
                    'offset': d.get('offset'),
                    'currency': d.get('currency'),
                    'isp': d.get('isp'),
                    'org': d.get('org'),
                    'as': d.get('as'),
                    'asname': d.get('asname'),
                    'mobile': d.get('mobile'),
                    'proxy': d.get('proxy'),
                    'hosting': d.get('hosting')
                }
            results = generic_api_call(url, 'ip', process)
    return render_template('ip.html', is_admin=is_admin, notifications=unread_count, results=results, ip_address=ip_address)

@app.route('/modulos/likeff', methods=['GET', 'POST'])
@jwt_required
def likeff():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    uid = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('likeff.html', is_admin=is_admin, notifications=unread_count, result=result, uid=uid)
        uid = request.form.get('uid', '').strip()
        if not uid or not uid.isdigit():
            flash('UID inválido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={uid}&tipo=likeff"
            process = lambda d: d if isinstance(d, dict) and d.get('status') == 'success' and 'data' in d else None
            result = generic_api_call(url, 'likeff', process)
    return render_template('likeff.html', is_admin=is_admin, notifications=unread_count, result=result, uid=uid)

@app.route('/modulos/nome2', methods=['GET', 'POST'])
@jwt_required
def nome2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('nome2.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev3"
            process = lambda d: d.get('response', []) if isinstance(d, dict) and d.get('status') else None
            results = generic_api_call(url, 'nome2', process)
    return render_template('nome2.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/cpf5', methods=['GET', 'POST'])
@jwt_required
def cpf5():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf5.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)
        cpf_input = request.form.get('cpf', '').strip()
        if not cpf_input:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf_input}&tipo=cpfextra"
            process = lambda d: d if isinstance(d, dict) and 'CPF' in d else None
            result = generic_api_call(url, 'cpf5', process)
    return render_template('cpf5.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf_input)

@app.route('/modulos/visitas', methods=['GET', 'POST'])
@jwt_required
def visitas():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    url_input = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('visitas.html', is_admin=is_admin, notifications=unread_count, result=result, url=url_input)
        url_input = request.form.get('url', '').strip()
        if not url_input:
            flash('URL não fornecida.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={url_input}&tipo=visitas"
            process = lambda d: d if isinstance(d, dict) and 'visits' in d else None
            result = generic_api_call(url, 'visitas', process)
    return render_template('visitas.html', is_admin=is_admin, notifications=unread_count, result=result, url=url_input)

@app.route('/modulos/atestado', methods=['GET', 'POST'])
@jwt_required
def atestado():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    pdf_path = None
    nome = ""
    cpf = ""
    data = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('atestado.html', is_admin=is_admin, notifications=unread_count, pdf_path=pdf_path, nome=nome, cpf=cpf, data=data)
        nome = request.form.get('nome', '').strip()
        cpf = request.form.get('cpf', '').strip()
        data = request.form.get('data', '').strip()
        if not nome or not cpf or not data:
            flash('Todos os campos são obrigatórios.', 'error')
        else:
            try:
                doc = fitz.open("atestado.pdf")
                page = doc[0]
                font_path = os.path.join('fonts', 'DejaVuSans.ttf')
                bold_path = os.path.join('fonts', 'DejaVuSans-Bold.ttf')
                page.insert_text((100, 200), nome, fontsize=14, fontname="helv", fontfile=font_path)
                page.insert_text((100, 230), f"CPF: {cpf}", fontsize=12, fontname="helv", fontfile=font_path)
                page.insert_text((100, 260), f"Data: {data}", fontsize=12, fontname="helv", fontfile=font_path)
                output_path = f"static/atestado_{secrets.token_hex(8)}.pdf"
                doc.save(output_path)
                doc.close()
                pdf_path = f"/{output_path}"
                flash('Atestado gerado com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao gerar PDF: {str(e)}', 'error')
    return render_template('atestado.html', is_admin=is_admin, notifications=unread_count, pdf_path=pdf_path, nome=nome, cpf=cpf, data=data)

@app.route('/static/atestado_<filename>')
def serve_atestado(filename):
    return send_from_directory('static', f'atestado_{filename}')

# === LOGOUT ===
@app.route('/logout')
@jwt_required
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
    resp.set_cookie('js_enabled', '', expires=0)
    resp.set_cookie('canvas_fp', '', expires=0)
    resp.set_cookie('webgl_fp', '', expires=0)
    return resp

# === ESTÁTICO ===
@app.route('/preview.jpg')
def preview():
    return send_from_directory('.', 'preview.jpg')

@app.route('/@A30')
def creditos():
    return "@enfurecido - {'0x106a90000'}"

# === 404 ===
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# === EXECUÇÃO ===
if __name__ == '__main__':
    colorama.init()
    print(f"{Fore.GREEN}[+] Servidor iniciado com segurança máxima em https://0.0.0.0:8855{Style.RESET_ALL}")
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855, threads=16, connection_limit=1000, cleanup_interval=30)
