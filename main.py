from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session, send_from_directory, url_for, abort, send_file
import json
import os
import secrets
import requests
from datetime import datetime, timedelta, date
import logging
import time
import re
import uuid
from functools import wraps
import colorama
from colorama import Fore, Style
import urllib3
import socket
import fitz # PyMuPDF for PDF editing
import jwt # For JWT handling
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24).hex() # More secure secret key
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'novidades')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()
# JWT Secret (should be env var in production)
JWT_SECRET = os.urandom(32).hex()
JWT_EXPIRATION = 3600 # 1 hour
# Rate limiting storage (improved with expiration)
login_attempts = {}
# Module status
module_status = {
    'cpfdata': 'ON',
    'cpflv': 'OFF',
    'cpf': 'ON',
    'cpf2': 'ON',
    'vacinas': 'ON',
    'cpf3': 'ON',
    'nomelv': 'ON',
    'nome': 'ON',
    'nome2': 'ON',
    'tel': 'OFF',
    'telLv': 'ON',
    'teldual': 'OFF',
    'datanome': 'ON',
    'placa': 'ON',
    'placaestadual': 'OFF',
    'fotor': 'ON',
    'pix': 'ON',
    'placalv': 'ON',
    'ip': 'ON',
    'likeff': 'OFF',
    'mae': 'ON',
    'pai': 'ON',
    'cnpjcompleto': 'ON',
    'atestado': 'ON',
    'cpf5': 'OFF',
    'visitas': 'OFF',
    'crash_ios': 'ON'
}
chave = "vmb1" # API key
# JSON File Management (with locking for concurrency)
import fcntl
def initialize_json(file_path, default_data={}):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            fcntl.flock(file, fcntl.LOCK_EX)
            json.load(file)
            fcntl.flock(file, fcntl.LOCK_UN)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(file_path, 'w', encoding='utf-8') as file:
            fcntl.flock(file, fcntl.LOCK_EX)
            json.dump(default_data, file)
            fcntl.flock(file, fcntl.LOCK_UN)
def load_data(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            fcntl.flock(file, fcntl.LOCK_SH)
            data = json.load(file)
            fcntl.flock(file, fcntl.LOCK_UN)
            if 'news.json' in file_path and not isinstance(data, list):
                data = []
                save_data(data, file_path)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        default_data = [] if 'news.json' in file_path else {}
        save_data(default_data, file_path)
        return default_data
def save_data(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        json.dump(data, file, indent=4, default=str)
        fcntl.flock(file, fcntl.LOCK_UN)
# Logging with IP masking for privacy
def log_access(endpoint, message=''):
    try:
        response = requests.get('https://ipinfo.io/json', verify=False)
        ip_info = response.json()
        ip = ip_info.get('ip', '')
        # Mask IP (last octet)
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            ip = '.'.join(ip_parts[:3]) + '.xxx'
    except:
        ip = 'unknown'
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip} - {now} accessed {endpoint}. {message}")
# Module Usage Management (with daily reset)
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})
    if user.get('role') == 'admin':
        return True
    permissions = user.get('permissions', {})
    if module not in permissions or (permissions[module] and datetime.now() > datetime.strptime(permissions[module], '%Y-%m-%d')):
        return False
    if 'modules' not in user:
        user['modules'] = {m: 0 for m in module_status.keys()}
    today = datetime.now().date().isoformat()
    if 'last_reset' not in user or user['last_reset'] != today:
        user['modules'] = {m: 0 for m in module_status.keys()}
        user['last_reset'] = today
    if increment:
        user['modules'][module] += 1
    usage_limit = {
        'guest': 0,
        'user_semanal': 30,
        'user_mensal': 250,
        'user_anual': 500
    }.get(user.get('role', 'guest'), 0)
    if user['modules'][module] > usage_limit:
        return False
    users[user_id] = user
    save_data(users, 'users.json')
    return True
# Rate Limiting for Login (with IP + UA key)
def check_login_attempts(identifier):
    now = time.time()
    if identifier not in login_attempts:
        login_attempts[identifier] = {'count': 0, 'last_attempt': now}
    attempts = login_attempts[identifier]
    if now - attempts['last_attempt'] > 300:
        attempts['count'] = 0
    attempts['last_attempt'] = now
    attempts['count'] += 1
    if attempts['count'] > 5:
        return False, "Muitas tentativas. Tente novamente em 5 minutos."
    login_attempts[identifier] = attempts
    return True, ""
# JWT Utilities
def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
# Auth Decorator (JWT in secure cookie)
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            flash('Sessão inválida. Faça login.', 'error')
            return redirect('/')
        user_id = verify_jwt(token)
        if not user_id:
            flash('Sessão expirada. Faça login novamente.', 'error')
            resp = make_response(redirect('/'))
            resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            return resp
        g.user_id = user_id
        users = load_data('users.json')
        user = users.get(g.user_id, {})
        if not user:
            resp = make_response(redirect('/'))
            resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            return resp
        # Expiration check
        if user['role'] != 'admin' and user['role'] != 'guest':
            expiration_date = datetime.strptime(user['expiration'], '%Y-%m-%d')
            if datetime.now() > expiration_date:
                flash('Sua conta expirou. Contate o suporte.', 'error')
                resp = make_response(redirect('/'))
                resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
                return resp
        return f(*args, **kwargs)
    return decorated
# Before Request (bot detection, UA check)
@app.before_request
def security_check():
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'bot' in user_agent or 'spider' in user_agent:
        abort(403)
    if request.endpoint not in ['login_or_register', 'creditos', 'preview']:
        pass # Removed redirect, assuming it's a typo
# Login/Register (with hashed passwords, UA limit)
@app.route('/', methods=['GET', 'POST'])
def login_or_register():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('user', '').strip()
        password = request.form.get('password', '').strip()
        user_agent = request.headers.get('User-Agent', '')
        identifier = f"{request.remote_addr}_{user_agent}" # IP + UA for rate limit
        can_attempt, msg = check_login_attempts(identifier)
        if not can_attempt:
            flash(msg, 'error')
            return render_template('login.html')
        users = load_data('users.json')
        if action == 'login':
            if not username or not password:
                flash('Usuário e senha são obrigatórios.', 'error')
                return render_template('login.html')
            if username in users and check_password_hash(users[username]['password'], password):
                user = users[username]
                if user['role'] != 'guest':
                    expiration_date = datetime.strptime(user['expiration'], '%Y-%m-%d')
                    if datetime.now() > expiration_date:
                        flash('Conta expirada. Contate o suporte.', 'error')
                        return render_template('login.html')
                # Device management - Allow if no devices or empty list
                deny_device = 'devices' in user and user['devices'] and user_agent not in user['devices']
                if deny_device:
                    flash('Dispositivo não autorizado.', 'error')
                    return render_template('login.html')
                user['devices'] = list(set(user.get('devices', []) + [user_agent]))[:5] # Limit to 5 devices
                save_data(users, 'users.json')
                token = generate_jwt(username)
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('auth_token', token, max_age=JWT_EXPIRATION, httponly=True, secure=True, samesite='Strict')
                return resp
            else:
                flash('Credenciais inválidas.', 'error')
                return render_template('login.html')
        elif action == 'register':
            if not username or not password:
                flash('Usuário e senha são obrigatórios.', 'error')
                return render_template('login.html')
            if username in users:
                flash('Usuário já existe.', 'error')
                return render_template('login.html')
            # Check UA uniqueness - prevents multiple registrations from same device
            ua_exists = any(user_agent in u.get('devices', []) for u in users.values())
            if ua_exists:
                flash('Este dispositivo já registrou uma conta. Use login em contas existentes.', 'error')
                return render_template('login.html')
            aff_code = request.args.get('aff')
            referred_by = next((u for u, d in users.items() if d.get('affiliate_code') == aff_code), None)
            hashed_pw = generate_password_hash(password)
            users[username] = {
                'password': hashed_pw,
                'plain_password': password, # Save plain text password (insecure, but as per request)
                'role': 'guest',
                'expiration': '2099-12-31',
                'permissions': {},
                'modules': {m: 0 for m in module_status.keys()},
                'read_notifications': [],
                'referred_by': referred_by,
                'affiliate_code': secrets.token_urlsafe(8) if referred_by else None,
                'devices': [user_agent]
            }
            save_data(users, 'users.json')
            flash('Registro concluído. Faça login.', 'success')
            return redirect('/')
    return render_template('login.html')
# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@jwt_required
def dashboard():
    users = load_data('users.json')
    user = users[g.user_id]
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    is_admin = user['role'] == 'admin'
    is_guest = user['role'] == 'guest'
    affiliate_link = None if is_guest else url_for('login_or_register', aff=user.get('affiliate_code'), _external=True)
    max_limit = {
        'guest': 10,
        'user_semanal': 30,
        'user_mensal': 250,
        'user_anual': 500
    }.get(user['role'], 0) if not is_admin else 999999
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'redeem':
            code = request.form.get('code')
            gifts = load_data('gifts.json')
            if code in gifts and gifts[code]['uses_left'] > 0:
                gift = gifts[code]
                exp_date = (datetime.now() + timedelta(days=gift['expiration_days'])).strftime('%Y-%m-%d')
                user['permissions'] = user.get('permissions', {})
                modules = module_status.keys() if gift['modules'] == 'all' else gift['modules']
                for m in modules:
                    if m in module_status:
                        user['permissions'][m] = exp_date
                if user['role'] == 'guest':
                    user['role'] = 'user_semanal' if gift['expiration_days'] <= 7 else 'user_mensal' if gift['expiration_days'] <= 30 else 'user_anual'
                    user['expiration'] = exp_date
                if 'token' not in user:
                    user['token'] = f"{g.user_id}-KEY{secrets.token_hex(13)}.center"
                gifts[code]['uses_left'] -= 1
                if gifts[code]['uses_left'] == 0:
                    del gifts[code]
                users[g.user_id] = user
                save_data(users, 'users.json')
                save_data(gifts, 'gifts.json')
            else:
                pass
        elif is_admin and action == 'view_modules':
            target_user = request.form.get('user')
            module = request.form.get('module')
            if target_user in users:
                user_modules = users[target_user].get('modules', {})
                role = users[target_user].get('role', 'user_semanal')
                max_requests = {'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(role, 30) if role != 'admin' else 'Unlimited'
                return jsonify({"user": target_user, "modules": {module: user_modules.get(module, 0)} if module else user_modules, "maxRequests": max_requests})
    return render_template('dashboard.html', users=users, admin=is_admin, guest=is_guest, unread_notifications=unread_count, affiliate_link=affiliate_link, notifications=notifications, module_status=module_status, max_limit=max_limit)
# Admin Panel (with more security checks)
@app.route('/i/settings/admin', methods=['GET', 'POST'])
@jwt_required
def admin_panel():
    users = load_data('users.json')
    if users.get(g.user_id, {}).get('role') != 'admin':
        abort(403)
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
                    'plain_password': password, # Save plain text password (insecure, but as per request)
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
                # Send plain password as 'password'
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
                        # Force logout if resetting own devices
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
                import zipfile
                from io import BytesIO
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
                import zipfile
                import shutil
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
# Notifications
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
# Novidades
@app.route('/novidades', methods=['GET'])
@jwt_required
def novidades():
    users = load_data('users.json')
    if users[g.user_id]['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    return render_template('novidades.html', news=news, users=users)
# New Novidade
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
# Edit Novidade
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
# Delete Novidade
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
# Generic API Call
def generic_api_call(url, module, process_func=None, flash_error=True):
    try:
        response = requests.get(url, verify=False, timeout=30)
        response.raise_for_status()
        raw_text = response.text.lstrip('\ufeff')
        data = json.loads(raw_text)
       
        # Validação robusta: Deve ser dict ou list, senão erro
        if not isinstance(data, (dict, list)):
            print(f"[ERROR] Resposta inválida de {url}: tipo {type(data)} - Conteúdo: {str(data)[:200]}...")
            if flash_error:
                flash('Resposta da API inválida (não é JSON válido).', 'error')
            return None
       
        # Se process_func, aplica só se tipo válido
        if process_func:
            # Chama process_func com guard extra
            try:
                processed = process_func(data)
                if processed is not None and isinstance(processed, (dict, list)):
                    data = processed
                else:
                    print(f"[WARN] process_func retornou inválido para {url}: {type(processed)}")
                    data = None
            except Exception as proc_e:
                print(f"[ERROR] Erro no process_func para {url}: {str(proc_e)}")
                data = None
       
        # Se data final é válida e uso permitido
        if data and (isinstance(data, dict) or isinstance(data, list)) and manage_module_usage(g.user_id, module):
            return data
       
        if flash_error:
            flash('Algo deu errado. Ou, nenhum resultado foi encontrado.', 'error')
        return None
       
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON inválido em {url}: {str(e)} - Raw preview: {response.text[:200]}...")
        if flash_error:
            flash('Erro ao processar resposta da API (JSON malformado).', 'error')
        return None
    except requests.exceptions.RequestException as req_e:
        print(f"[ERROR] Requisição falhou para {url}: {str(req_e)}")
        if flash_error:
            flash('Erro de conexão com a API.', 'error')
        return None
    except Exception as e:
        print(f"[ERROR] Erro geral na API {url}: {str(e)}")
        if flash_error:
            flash('Algo deu errado na consulta.', 'error')
        return None
       
# Module Routes
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
    token_input = ""
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
                except Exception as e:
                    flash(f'Erro na API: {str(e)}', 'error')
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
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv1"
            process = lambda d: d if isinstance(d, dict) and 'CPF' in d and d['CPF'] and d.get('NOME') else None
            result = generic_api_call(url, 'cpf', process)
    return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
@app.route('/modulos/cpf2', methods=['GET', 'POST'])
@jwt_required
def cpf2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpf_serasa"
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
                # Address from first ENDERECOS
                enderecos = d.get("ENDERECOS", [])
                if enderecos:
                    end = enderecos[0]
                    result["TIPO_ENDERECO"] = end.get("TIPO_ENDERECO_ID", "Não informado")
                    result["LOGRADOURO"] = end.get("LOGR_NOME", "Não informado")
                    result["NUMERO"] = end.get("LOGR_NUMERO", "Não informado")
                    result["COMPLEMENTO"] = end.get("LOGR_COMPLEMENTO", "Não informado")
                    result["BAIRRO"] = end.get("BAIRRO", "Não informado")
                    result["CIDADE"] = end.get("CIDADE", "Não informado")
                    result["ESTADO"] = end.get("UF", "Não informado")
                    result["UF"] = end.get("UF", "Não informado")
                    result["CEP"] = end.get("CEP", "Não informado")
                else:
                    result["TIPO_ENDERECO"] = "Não informado"
                    result["LOGRADOURO"] = "Não informado"
                    result["NUMERO"] = "Não informado"
                    result["COMPLEMENTO"] = "Não informado"
                    result["BAIRRO"] = "Não informado"
                    result["CIDADE"] = "Não informado"
                    result["ESTADO"] = "Não informado"
                    result["UF"] = "Não informado"
                    result["CEP"] = "Não informado"
                # Telefones
                tels = d.get("TELEFONE", [])
                if tels:
                    phones = [f"({tel.get('DDD', '')}) {tel.get('TELEFONE', '')}" for tel in tels if tel.get('DDD') and tel.get('TELEFONE')]
                    result["TELEFONES"] = ', '.join(phones) if phones else "SEM RESULTADO"
                return result
            result = generic_api_call(url, 'cpf2', process)
    return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
    
@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
@jwt_required
def cpfdata():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv3"
            def process(d):
                if not isinstance(d, dict) or not d.get('nome'):
                    return None
                processed_result = {
                    'nome': d.get('nome', 'SEM INFORMAÇÃO').rstrip('---'),
                    'cpf': d.get('documentos', {}).get('cpf', 'SEM INFORMAÇÃO').replace('.', '').replace('-', ''),
                    'sexo': d.get('sexo', 'SEM INFORMAÇÃO'),
                    'dataNascimento': {
                        'nascimento': 'SEM INFORMAÇÃO',
                        'idade': 'SEM INFORMAÇÃO',
                        'signo': 'SEM INFORMAÇÃO'
                    },
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
                # Parse nascimento
                nasc = d.get('nascimento', 'SEM INFORMAÇÃO')
                if ' (' in nasc and ' anos)' in nasc:
                    date_str = nasc.split(' (')[0]
                    age_str = nasc.split(' (')[1].rstrip(' anos)')
                    processed_result['dataNascimento'] = {
                        'nascimento': date_str,
                        'idade': age_str,
                        'signo': 'SEM INFORMAÇÃO'
                    }
                    try:
                        birth_date = datetime.strptime(date_str, '%d/%m/%Y')
                        month = birth_date.month
                        day = birth_date.day
                        if (month == 1 and day >= 20) or (month == 2 and day <= 18):
                            signo = 'Aquário'
                        elif (month == 2 and day >= 19) or (month == 3 and day <= 20):
                            signo = 'Peixes'
                        elif (month == 3 and day >= 21) or (month == 4 and day <= 19):
                            signo = 'Áries'
                        elif (month == 4 and day >= 20) or (month == 5 and day <= 20):
                            signo = 'Touro'
                        elif (month == 5 and day >= 21) or (month == 6 and day <= 20):
                            signo = 'Gêmeos'
                        elif (month == 6 and day >= 21) or (month == 7 and day <= 22):
                            signo = 'Câncer'
                        elif (month == 7 and day >= 23) or (month == 8 and day <= 22):
                            signo = 'Leão'
                        elif (month == 8 and day >= 23) or (month == 9 and day <= 22):
                            signo = 'Virgem'
                        elif (month == 9 and day >= 23) or (month == 10 and day <= 22):
                            signo = 'Libra'
                        elif (month == 10 and day >= 23) or (month == 11 and day <= 21):
                            signo = 'Escorpião'
                        elif (month == 11 and day >= 22) or (month == 12 and day <= 21):
                            signo = 'Sagitário'
                        else:
                            signo = 'Capricórnio'
                        processed_result['dataNascimento']['signo'] = signo
                    except:
                        pass
                else:
                    processed_result['dataNascimento'] = {
                        'nascimento': nasc,
                        'idade': 'SEM INFORMAÇÃO',
                        'signo': 'SEM INFORMAÇÃO'
                    }
                # Telefone
                telefones = d.get('contatos', {}).get('telefones', [])
                processed_result['telefone'] = [
                    {
                        'ddi': '',
                        'ddd': phone.get('ddd', '').strip('()'),
                        'numero': phone.get('numero', '')
                    }
                    for phone in telefones
                ]
                if not processed_result['telefone']:
                    processed_result['telefone'] = [{'ddi': '', 'ddd': '', 'numero': ''}]
                # Enderecos
                endereco = d.get('endereco', {})
                if endereco:
                    if 'municipio_residencia' in endereco:
                        parts = endereco['municipio_residencia'].split(' - ')
                        if len(parts) > 0:
                            endereco['cidade'] = parts[0]
                        if len(parts) > 1:
                            endereco['uf'] = parts[1]
                    processed_result['enderecos'] = [endereco]
                return processed_result
            result = generic_api_call(url, 'cpfdata', process)
    return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
@app.route('/modulos/cpf3', methods=['GET', 'POST'])
@jwt_required
def cpf3():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpffull"
            process = lambda d: d if isinstance(d, dict) and 'CPF' in d and d['CPF'] else None
            result = generic_api_call(url, 'cpf3', process)
    return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
@app.route('/modulos/cpflv', methods=['GET', 'POST'])
@jwt_required
def cpflv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            url = f"https://api.bygrower.online/core/?token={chave}&base=cpfLv&query={cpf}"
            process = lambda d: d.get('resultado') if isinstance(d, dict) and d.get('resultado') and d['resultado'].get('status') == 'success' and 'data' in d['resultado'] and 'pessoa' in d['resultado']['data'] and 'identificacao' in d['resultado']['data']['pessoa'] and 'cpf' in d['resultado']['data']['pessoa']['identificacao'] else None
            result = generic_api_call(url, 'cpflv', process)
    return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
@app.route('/modulos/vacinas', methods=['GET', 'POST'])
@jwt_required
def vacinas():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = []
    cpf = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf)
        cpf = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Por favor, insira um CPF válido com 11 dígitos.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=vacina"
            process = lambda d: d.get('response', {}).get('dados', []) if isinstance(d, dict) and d.get('status') else d.get('resultado', []) if isinstance(d, dict) and 'resultado' in d else []
            results = generic_api_call(url, 'vacinas', process) or []
    return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf)
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
            flash('Nome e data de nascimento são obrigatórios.', 'error')
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
            flash('Por favor, insira uma placa válida no formato AAA1234.', 'error')
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
            flash('Por favor, insira um telefone válido (10 ou 11 dígitos).', 'error')
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
    placa = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('placa.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa)
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Por favor, insira uma placa válida no formato AAA1234.', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placanormal"
            process = lambda d: d if isinstance(d, dict) and d.get('PLACA') == placa else None
            result = generic_api_call(url, 'placa', process)
    return render_template('placa.html', is_admin=is_admin, notifications=unread_count, result=result, placa=placa)
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
    chave = ""
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('pix.html', is_admin=is_admin, notifications=unread_count, result=result, chave=chave)
        chave = request.form.get('chave', '').strip()
        if not chave or len(chave) < 11:
            flash('Por favor, insira uma chave válida (CPF, telefone ou e-mail).', 'error')
        else:
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={chave}&tipo=pix"
            process = lambda d: d if isinstance(d, dict) and d.get('Status') == 'Sucesso' and 'nome' in d else None
            result = generic_api_call(url, 'pix', process)
    return render_template('pix.html', is_admin=is_admin, notifications=unread_count, result=result, chave=chave)
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
        documento = request.form.get('documento', '').strip()
        selected_option = request.form.get('estado', '')
        if not documento:
            flash('Documento não fornecido.', 'error')
        else:
            base_url = "http://br1.stormhost.online:10004/api/token=@signficativo/consulta"
            tipo_map = {
                "fotorj": "fotorj",
                "fotoce": "fotoce",
                "fotosp": "fotosp",
                "fotoes": "fotoes",
                "fotoma": "fotoma",
                "fotoro": "fotoro"
            }
            tipo = tipo_map.get(selected_option)
            if not tipo:
                flash('Estado inválido.', 'error')
            else:
                url = f"{base_url}?dado={documento}&tipo={tipo}"
                def process(d):
                    if not isinstance(d, dict):
                        return None
                    outer_response = d.get("response")
                    if not isinstance(outer_response, dict):
                        return None
                    inner_response = outer_response.get("response")
                    if not isinstance(inner_response, list) or not inner_response:
                        return None
                    first_item = inner_response[0]
                    if not isinstance(first_item, dict):
                        return None
                    fotob64 = first_item.get("fotob64")
                    cpf = first_item.get("cpf", "") or documento
                    if fotob64:
                        return {
                            "foto_base64": fotob64,
                            "cpf": cpf
                        }
                    return None
                results = generic_api_call(url, 'fotor', process)
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
            url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
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
            process = lambda d: {
                'ip': d.get('ip'),
                'continent': d.get('continent'),
                'country': d.get('country'),
                'region': d.get('region'),
                'city': d.get('city'),
                'latitude': d.get('latitude'),
                'longitude': d.get('longitude'),
                'provider': d.get('connection', {}).get('isp', 'Não disponível')
            } if isinstance(d, dict) and d.get('success') else None
            results = generic_api_call(url, 'ip', process)
    return render_template('ip.html', is_admin=is_admin, notifications=unread_count, results=results, ip_address=ip_address)
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
            url = f"https://api.bygrower.online/core/?token={chave}&base=nomeData&query={nome}"
            process = lambda d: d.get('resultado', {}).get('itens') if isinstance(d, dict) and d.get('resultado') and 'itens' in d['resultado'] else None
            results = generic_api_call(url, 'nome2', process)
    return render_template('nome2.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)
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
        server_name = 'br'
        if not uid:
            flash('UID não fornecido.', 'error')
        else:
            token_url = "http://teamxcutehack.serv00.net/like/token_ind.json"
            ffinfo_url = f"https://lk-team-ffinfo-five.vercel.app/ffinfo?id={uid}"
            like_api_url = f"https://likeapiff.thory.in/like?uid={uid}&server_name={server_name}&token_url={requests.utils.quote(token_url)}"
            try:
                ffinfo_response = requests.get(ffinfo_url, timeout=30)
                ffinfo_response.raise_for_status()
                ffinfo_data = json.loads(ffinfo_response.text.lstrip('\ufeff'))
                if not ffinfo_data or "account_info" not in ffinfo_data or "├ Likes" not in ffinfo_data["account_info"]:
                    flash('Resposta inválida da API ffinfo.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, notifications=unread_count, result=result, uid=uid)
                likes_before = int(str(ffinfo_data["account_info"]["├ Likes"]).replace(',', ''))
                like_response = requests.get(like_api_url, timeout=30, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
                like_response.raise_for_status()
                like_data = json.loads(like_response.text.lstrip('\ufeff'))
                if not like_data or "LikesafterCommand" not in like_data:
                    flash('Resposta inválida da API de likes.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, notifications=unread_count, result=result, uid=uid)
                likes_after = int(like_data["LikesafterCommand"])
                likes_sended = likes_after - likes_before
                result = {
                    "LikesafterCommand": likes_after,
                    "LikesbeforeCommand": likes_before,
                    "likeSended": likes_sended,
                    "PlayerNickname": like_data.get("PlayerNickname", "Unknown"),
                    "UID": like_data.get("UID", uid),
                    "credit": "@thoryxff",
                    "status": 1,
                    "thanks": "super thanks to thoryxff for providing this like source code!",
                    "owner": "cutehack Chx 💀"
                }
                if not manage_module_usage(g.user_id, 'likeff'):
                    flash('Limite de uso atingido para LIKEFF.', 'error')
                    result = None
            except Exception:
                flash('Algo deu errado.', 'error')
    return render_template('likeff.html', is_admin=is_admin, notifications=unread_count, result=result, uid=uid)
# Atestado
@app.route('/modulos/atestado', methods=['GET', 'POST'])
@jwt_required
def atestado():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    role = user['role']
    if not is_admin and role not in ['user_mensal', 'user_anual']:
        flash('Acesso negado.', 'error')
        return redirect('/dashboard')
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    edited_pdf_path = None
    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token')
            if not token or token != user.get('token'):
                flash('Token inválido.', 'error')
                return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, edited_pdf=edited_pdf_path)
        if not manage_module_usage(g.user_id, 'atestado'):
            flash('Limite atingido.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, edited_pdf=edited_pdf_path)
        nome_paciente = request.form.get('nome_paciente', 'ERICK GABRIEL COTA').strip().upper()
        cpf = request.form.get('cpf', '413.759.068-01').strip()
        profissional = request.form.get('profissional', 'CAROLINA SAAD HASSEM').strip().upper()
        crm = request.form.get('crm', '191662').strip()
        data_atendimento_input = request.form.get('data_atendimento', '').strip()
        cidade = request.form.get('cidade', 'Guaratinguetá').strip().title()
        uf = request.form.get('uf', 'SP').strip().upper()
        cid = request.form.get('cid', 'J11').strip().upper()
        dias_afastamento = request.form.get('dias_afastamento', '01 (UM)').strip().upper()
       
        # Generate automatic numbers
        import random
        n_atend = str(random.randint(1000000, 9999999)) # 7 digits
        n_pront = f"{random.randint(0, 9999999999):010d}" # 10 digits with leading zeros
       
        # Generate data_assinatura
        data_assinatura = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
       
        # Generate data_atendimento if not provided
        if not data_atendimento_input:
            months = {
                1: 'Janeiro', 2: 'Fevereiro', 3: 'Março', 4: 'Abril',
                5: 'Maio', 6: 'Junho', 7: 'Julho', 8: 'Agosto',
                9: 'Setembro', 10: 'Outubro', 11: 'Novembro', 12: 'Dezembro'
            }
            month_name = months[datetime.now().month]
            data_atendimento = f"{datetime.now().day} de {month_name} de {datetime.now().year}"
        else:
            data_atendimento = data_atendimento_input
       
        original_pdf = 'atestado.pdf'
        if not os.path.exists(original_pdf):
            flash('Template não encontrado.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, edited_pdf=edited_pdf_path)
        edited_pdf = f'static/edited_atestado_{uuid.uuid4().hex}.pdf'
        try:
            doc = fitz.open(original_pdf)
            page = doc[0]
            # Register fonts
            font_normal = page.insert_font(fontfile='fonts/DejaVuSans.ttf', fontname='DejaNormal')
            font_bold = page.insert_font(fontfile='fonts/DejaVuSans-Bold.ttf', fontname='DejaBold')
            def insert_text(text, point, font_size=10, bold=False):
                page.insert_text(
                    point,
                    text,
                    fontsize=font_size,
                    fontname='DejaBold' if bold else 'DejaNormal',
                    color=(0, 0, 0)
                )
            # Do not clear areas to avoid white blocks
            # for rect in [...]: clear_area(rect) # Removed
            positions = {
                "nome_paciente": (70, 105),
                "cpf": (70, 120),
                "profissional": (70, 135),
                "n_atend": (380, 105),
                "n_pront": (380, 120),
                "data_assinatura": (380, 135),
                "cidade_data": (180, 260),
                "cid": (70, 360),
                "dias_afastamento": (70, 410),
                "profissional_assinatura": (300, 460),
                "crm_assinatura": (300, 475),
            }
            insert_text(nome_paciente, positions["nome_paciente"], bold=True)
            insert_text(cpf, positions["cpf"])
            insert_text(profissional, positions["profissional"])
            insert_text(n_atend, positions["n_atend"])
            insert_text(n_pront, positions["n_pront"])
            insert_text(data_assinatura, positions["data_assinatura"])
            insert_text(f"{cidade}, {uf} - {data_atendimento}", positions["cidade_data"])
            insert_text(cid, positions["cid"], bold=True)
            insert_text(dias_afastamento, positions["dias_afastamento"], bold=True)
            insert_text(f"Dr(a). {profissional}", positions["profissional_assinatura"])
            insert_text(f"{crm} CRM", positions["crm_assinatura"])
            corpo = f"Atesto para os devidos fins que {nome_paciente} foi atendido(a) neste serviço, necessitando de afastamento por {dias_afastamento} dia(s) das suas atividades profissionais."
            page.insert_textbox(
                fitz.Rect(65, 300, 520, 350),
                corpo,
                fontsize=11,
                fontname='DejaNormal',
                align=fitz.TEXT_ALIGN_JUSTIFY
            )
            doc.save(edited_pdf, garbage=4, deflate=True, clean=True)
            doc.close()
            edited_pdf_path = edited_pdf
        except Exception as e:
            print(f"Error generating atestado: {e}")
            flash('Algo deu errado ao gerar atestado.', 'error')
    return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, edited_pdf=edited_pdf_path)
   
@app.route('/download_edited/<path:filename>')
@jwt_required
def download_edited(filename):
    return send_from_directory(app.root_path, filename, as_attachment=True)
# Logout
@app.route('/logout')
@jwt_required
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('auth_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return resp
# Credits
@app.route('/@A30')
def creditos():
    return "@enfurecido - {'0x106a90000'}"
# Preview
@app.route('/preview.jpg')
def preview():
    return send_from_directory(app.root_path, 'preview.jpg', mimetype='image/jpeg')
if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json', {})
    initialize_json('gifts.json')
    initialize_json('news.json', [])
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
