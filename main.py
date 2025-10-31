from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session, send_from_directory, url_for, abort, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
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
import fitz  # PyMuPDF for PDF editing
import hashlib  # For hashing user-agents
import base64   # For additional encoding in security
from werkzeug.security import generate_password_hash, check_password_hash  # Better password handling

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24).hex()  # More secure, hex for readability
app.config['JWT_SECRET_KEY'] = os.urandom(32).hex()  # Separate key for JWT
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True  # Only send over HTTPS in production
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SAMESITE'] = 'Strict'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Since SAMESITE=Strict
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)  # Token expiration
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'novidades')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

jwt = JWTManager(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()

# Rate limiting storage (improved with IP and user-agent hashing)
login_attempts = {}
ip_blacklist = set()  # Anti-hacker: Blacklist IPs after too many failures

# Module status (can be toggled by admins)
module_status = {
    'cpfdata': 'ON',
    'cpflv': 'OFF',
    'cpf': 'ON',
    'cpf2': 'OFF',
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
    'atestado': 'ON'
}
chave = "vmb1"  # API key for some external services

# JSON File Management (with file locking for concurrency)
import fcntl  # For file locking

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
            fcntl.flock(file, fcntl.LOCK_EX)
            data = json.load(file)
            fcntl.flock(file, fcntl.LOCK_UN)
            if 'news.json' in file_path and not isinstance(data, list):
                data = []
                save_data(data, file_path)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        default_data = [] if 'news.json' in file_path else {}
        with open(file_path, 'w', encoding='utf-8') as file:
            fcntl.flock(file, fcntl.LOCK_EX)
            json.dump(default_data, file)
            fcntl.flock(file, fcntl.LOCK_UN)
        return default_data

def save_data(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        json.dump(data, file, indent=4, default=str)  # Handle datetime serialization
        fcntl.flock(file, fcntl.LOCK_UN)

# Logging with IP hashing for privacy
def log_access(endpoint, message=''):
    try:
        response = requests.get('https://ipinfo.io/json', verify=False)
        response.raise_for_status()
        ip_info = response.json()
        ip = ip_info.get('ip', '')
    except requests.RequestException:
        ip = request.remote_addr
        message += f" [Error fetching real IP]"
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()  # Hash IP for logging
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip_hash} - {now} accessed {endpoint}. {message}")

# Module Usage Management (with daily reset and limits)
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})
    if user.get('role') == 'admin':
        return True  # Admins have unlimited access
    # Check permissions
    permissions = user.get('permissions', {})
    if module not in permissions or (permissions[module] and datetime.now() > datetime.strptime(permissions[module], '%Y-%m-%d')):
        flash(f'Você não tem permissão para acessar o módulo {module}.', 'error')
        return False
    # Usage tracking
    if 'modules' not in user:
        user['modules'] = {m: 0 for m in module_status.keys()}
    if increment:
        user['modules'][module] += 1
    today = datetime.now().date().isoformat()
    if 'last_reset' not in user or user['last_reset'] != today:
        user['modules'] = {k: 0 for k in user['modules']}
        user['last_reset'] = today
    usage_limit = {
        'guest': 0,
        'user_semanal': 30,
        'user_mensal': 250,
        'user_anual': 500
    }.get(user.get('role', 'guest'), 0)
    if user['modules'][module] > usage_limit:
        flash(f'Você excedeu o limite diário de {usage_limit} requisições para o módulo {module}.', 'error')
        return False
    users[user_id] = user
    save_data(users, 'users.json')
    return True

# Improved Rate Limiting for Login Attempts (with IP blacklisting)
def check_login_attempts(user_id):
    now = time.time()
    ip = request.remote_addr
    user_agent_hash = hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()
    key = f"{ip}:{user_agent_hash}"  # Combined key for anti-hacker
    if key in ip_blacklist:
        return False, "Acesso bloqueado devido a atividades suspeitas."
    if key not in login_attempts:
        login_attempts[key] = {'count': 0, 'last_attempt': now}
    attempts = login_attempts[key]
    if now - attempts['last_attempt'] > 300:  # Reset after 5 minutes
        attempts['count'] = 0
        attempts['last_attempt'] = now
    attempts['count'] += 1
    if attempts['count'] > 5:
        ip_blacklist.add(key)  # Blacklist for 1 hour
        threading.Timer(3600, lambda: ip_blacklist.discard(key)).start()  # Auto-unblock
        return False, "Muitas tentativas de login. Tente novamente em 5 minutos."
    login_attempts[key] = attempts
    return True, ""

# Before Request Security Check (improved with header validation)
@app.before_request
def security_check():
    # Anti-hacker: Check for suspicious headers
    if 'X-Forwarded-For' in request.headers or 'Proxy-Authorization' in request.headers:
        abort(403)  # Block proxies or suspicious headers
    if request.endpoint not in ['login_or_register', 'creditos', 'preview']:
        try:
            g.user_id = get_jwt_identity()
            if not g.user_id:
                raise Exception
        except:
            flash('Você precisa estar logado para acessar esta página.', 'error')
            return redirect('/')
        users = load_data('users.json')
        user = users.get(g.user_id, {})
        if not user:
            return redirect('/')
        # Check expiration
        if user['role'] != 'admin' and user['role'] != 'guest':
            expiration_date = datetime.strptime(user['expiration'], '%Y-%m-%d')
            if datetime.now() > expiration_date:
                flash('Sua conta expirou. Contate o suporte.', 'error')
                return redirect('/')
        # Validate user-agent consistency
        current_ua_hash = hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()
        stored_ua_hash = user.get('ua_hash')
        if stored_ua_hash and current_ua_hash != stored_ua_hash:
            flash('Dispositivo não autorizado. Login recusado.', 'error')
            return redirect('/')

# Login or Register (improved with hashed passwords and user-agent check)
@app.route('/', methods=['GET', 'POST'])
def login_or_register():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'login':
            username = request.form.get('user')
            password = request.form.get('password')
            users = load_data('users.json')
            can_login, message = check_login_attempts(username)
            if not can_login:
                flash(message, 'error')
                return render_template('login.html')
            if username in users and check_password_hash(users[username]['password'], password):
                if users[username]['role'] != 'guest':
                    expiration_date = datetime.strptime(users[username]['expiration'], '%Y-%m-%d')
                    if datetime.now() > expiration_date:
                        flash('Conta expirada. Contate o suporte.', 'error')
                        return render_template('login.html')
            
                user_agent = request.headers.get('User-Agent')
                ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
                if users[username].get('ua_hash') and users[username]['ua_hash'] != ua_hash:
                    flash('Dispositivo não autorizado. Login recusado.', 'error')
                    return render_template('login.html')
                if not users[username].get('ua_hash'):
                    users[username]['ua_hash'] = ua_hash
                    save_data(users, 'users.json')
            
                access_token = create_access_token(identity=username)
                resp = make_response(redirect('/dashboard'))
                set_access_cookies(resp, access_token)
                login_attempts.pop(username, None)
                return resp
            else:
                flash('Algo deu errado. Tente novamente.', 'error')  # Generic error
                return render_template('login.html')
        elif action == 'register':
            username = request.form.get('user')
            password = request.form.get('password')
            if not username or not password or len(username) < 3 or len(password) < 6:  # Basic validation
                flash('Algo deu errado. Tente novamente.', 'error')  # Generic
                return render_template('login.html')
            users = load_data('users.json')
            if username in users:
                flash('Algo deu errado. Tente novamente.', 'error')  # Generic instead of 'user exists'
                return render_template('login.html')
            user_agent = request.headers.get('User-Agent')
            ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
            # Check if ua_hash already used by any user (one account per device)
            for u in users.values():
                if u.get('ua_hash') == ua_hash:
                    flash('Algo deu errado. Tente novamente.', 'error')  # Generic
                    return render_template('login.html')
            # Handle affiliate
            aff_code = request.args.get('aff')
            referred_by = None
            if aff_code:
                for u, data in users.items():
                    if data.get('affiliate_code') == aff_code:
                        referred_by = u
                        break
            users[username] = {
                'password': generate_password_hash(password),
                'role': 'guest',
                'expiration': '2099-12-31',  # Permanent for guests
                'permissions': {},  # No modules
                'modules': {m: 0 for m in module_status.keys()},
                'read_notifications': [],
                'referred_by': referred_by,
                'affiliate_code': secrets.token_urlsafe(8) if referred_by else None,
                'ua_hash': ua_hash  # Store hashed user-agent
            }
            save_data(users, 'users.json')
            flash('Registro concluído com sucesso! Faça login.', 'success')
            return redirect('/')
        else:
            flash('Algo deu errado. Tente novamente.', 'error')
            return render_template('login.html')
    return render_template('login.html')

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@jwt_required()
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
    }.get(user['role'], 0)
    if is_admin:
        max_limit = 999999  # Large number for unlimited
    if user['role'] != 'guest':
        if datetime.now() > datetime.strptime(user['expiration'], '%Y-%m-%d'):
            flash('Sua sessão expirou. Faça login novamente.', 'error')
            return redirect('/')
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'redeem':
            code = request.form.get('code')
            gifts = load_data('gifts.json')
            if code in gifts and gifts[code]['uses_left'] > 0:
                gift = gifts[code]
                exp_date = (datetime.now() + timedelta(days=gift['expiration_days'])).strftime('%Y-%m-%d')
                if 'permissions' not in user:
                    user['permissions'] = {}
                if gift['modules'] == 'all':
                    for m in module_status.keys():
                        user['permissions'][m] = exp_date
                else:
                    for m in gift['modules']:
                        if m in module_status:
                            user['permissions'][m] = exp_date
                if user['role'] == 'guest':
                    if gift['expiration_days'] <= 7:
                        user['role'] = 'user_semanal'
                    elif gift['expiration_days'] <= 30:
                        user['role'] = 'user_mensal'
                    else:
                        user['role'] = 'user_anual'
                    user['expiration'] = exp_date
                if 'token' not in user:
                    user['token'] = f"{g.user_id}-KEY{secrets.token_hex(13)}.center"
                gifts[code]['uses_left'] -= 1
                if gifts[code]['uses_left'] == 0:
                    del gifts[code]
                save_data(users, 'users.json')
                save_data(gifts, 'gifts.json')
                flash('Gift resgatado com sucesso!', 'success')
            else:
                flash('Código inválido ou expirado.', 'error')
        elif is_admin:
            if action == 'view_modules':
                target_user = request.form.get('user')
                module = request.form.get('module')
                if target_user in users:
                    user_modules = users[target_user].get('modules', {})
                    role = users[target_user].get('role', 'user_semanal')
                    max_requests = {'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(role, 30)
                    if is_admin:
                        return jsonify({"user": target_user, "modules": user_modules, "maxRequests": "Unlimited for admin"})
                    return jsonify({"user": target_user, "modules": {module: user_modules.get(module, 0)}, "maxRequests": max_requests})
    return render_template('dashboard.html', users=users, admin=is_admin, guest=is_guest, unread_notifications=unread_count, affiliate_link=affiliate_link, notifications=notifications, module_status=module_status, max_limit=max_limit)

# Admin Panel
@app.route('/i/settings/admin', methods=['GET', 'POST'])
@jwt_required()
def admin_panel():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    gifts = load_data('gifts.json')
    user_id = g.user_id
    if users.get(user_id, {}).get('role') != 'admin':
        abort(403)
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'bot' in user_agent or 'spider' in user_agent:
        abort(403)
    if request.method == 'POST':
        action = request.form.get('action')
        user_input = request.form.get('user')
        password = request.form.get('password', '')
        expiration = request.form.get('expiration', '')
        message = request.form.get('message', '')
        role = request.form.get('role', 'user_semanal')
        module = request.form.get('module', '')
        status = request.form.get('status', '')
        if action == "add_user" and user_input and password and expiration and len(password) >= 6:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                users[user_input] = {
                    'password': generate_password_hash(password),
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'permissions': {m: None for m in module_status.keys()} if role != 'guest' else {},
                    'modules': {m: 0 for m in module_status.keys()},
                    'read_notifications': [],
                    'affiliate_code': secrets.token_urlsafe(8) if role != 'guest' else None,
                    'ua_hash': ''  # Will be set on first login
                }
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário adicionado com sucesso!', 'category': 'success', 'user': user_input, 'password': password, 'token': token, 'expiration': expiration, 'role': role})
            return jsonify({'message': 'Algo deu errado.', 'category': 'error'})  # Generic
        elif action == "delete_user" and user_input and password:
            if user_input in users and check_password_hash(users[user_input]['password'], password):
                del users[user_input]
                save_data(users, 'users.json')
                if g.user_id == user_input:
                    resp = make_response(jsonify({'message': 'Usuário excluído. Você foi deslogado.', 'category': 'success'}))
                    unset_jwt_cookies(resp)
                    return resp
                return jsonify({'message': 'Usuário excluído com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Algo deu errado.', 'category': 'error'})  # Generic
        elif action == "view_users":
            return jsonify({'users': {k: {kk: vv for kk, vv in v.items() if kk != 'password'} for k, v in users.items()}})  # Hide passwords
        elif action == "send_message" and message:
            notif_id = str(uuid.uuid4())
            user_input = request.form.get('user', 'all')
            if user_input == 'all':
                for user in users:
                    if user != user_id:
                        notifications.setdefault(user, []).append({'id': notif_id, 'message': message, 'timestamp': datetime.now().isoformat()})
            else:
                if user_input in users:
                    notifications.setdefault(user_input, []).append({'id': notif_id, 'message': message, 'timestamp': datetime.now().isoformat()})
                else:
                    return jsonify({'message': 'Algo deu errado.', 'category': 'error'})
            save_data(notifications, 'notifications.json')
            return jsonify({'message': 'Mensagem enviada com sucesso!', 'category': 'success'})
        elif action == "reset_device" and user_input and password:
            if user_input in users and check_password_hash(users[user_input]['password'], password):
                users[user_input]['ua_hash'] = ''
                save_data(users, 'users.json')
                return jsonify({'message': 'Dispositivo resetado com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Algo deu errado.', 'category': 'error'})
        elif action == "toggle_module" and module and status:
            if module in module_status:
                module_status[module] = status
                return jsonify({'success': True, 'message': f'Módulo {module} atualizado para {status}'})
            return jsonify({'success': False, 'message': 'Módulo não encontrado'})
        elif action == 'create_gift':
            modules = request.form.get('modules')  # comma separated or 'all'
            expiration_days = int(request.form.get('expiration_days', 30))
            uses = int(request.form.get('uses', 1))
            code = secrets.token_urlsafe(12)
            gifts[code] = {
                'modules': modules.split(',') if modules != 'all' else 'all',
                'expiration_days': expiration_days,
                'uses_left': uses,
                'created': datetime.now().isoformat()
            }
            save_data(gifts, 'gifts.json')
            return jsonify({'message': 'Gift criado com sucesso!', 'code': code, 'category': 'success'})
        elif action == "view_gifts":
            return jsonify({'gifts': gifts})
        elif action == 'get_stats':
            active_users = sum(1 for u in users.values() if u.get('role') != 'guest' and 'expiration' in u and datetime.now() < datetime.strptime(u['expiration'], '%Y-%m-%d'))
            return jsonify({'active_users': active_users})
        elif action == 'backup':
            import zipfile
            from io import BytesIO
            json_files = ['users.json', 'notifications.json', 'gifts.json', 'news.json']
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for file_name in json_files:
                    file_path = file_name  # assuming in current dir
                    if os.path.exists(file_path):
                        zip_file.write(file_path, arcname=file_name)
                # Include images from novidades folder
                upload_folder = app.config['UPLOAD_FOLDER']
                for filename in os.listdir(upload_folder):
                    file_path = os.path.join(upload_folder, filename)
                    if os.path.isfile(file_path):
                        arcname = os.path.join('novidades', filename)
                        zip_file.write(file_path, arcname=arcname)
            zip_buffer.seek(0)
            return send_file(zip_buffer, as_attachment=True, download_name='system_backup.zip', mimetype='application/zip')
        elif action == 'restore':
            if 'zip_file' not in request.files:
                return jsonify({'message': 'Nenhum arquivo enviado.', 'category': 'error'})
            zip_file = request.files['zip_file']
            if zip_file.filename == '':
                return jsonify({'message': 'Nenhum arquivo selecionado.', 'category': 'error'})
            if not zip_file.filename.endswith('.zip'):
                return jsonify({'message': 'Arquivo inválido. Deve ser .zip.', 'category': 'error'})
            import zipfile
            import shutil
            temp_dir = 'temp_restore'
            os.makedirs(temp_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                json_files = ['users.json', 'notifications.json', 'gifts.json', 'news.json']
                for file_name in json_files:
                    extracted_path = os.path.join(temp_dir, file_name)
                    if os.path.exists(extracted_path):
                        shutil.copy(extracted_path, file_name)
                # Restore images
                nov_temp_dir = os.path.join(temp_dir, 'novidades')
                if os.path.exists(nov_temp_dir):
                    upload_folder = app.config['UPLOAD_FOLDER']
                    for filename in os.listdir(nov_temp_dir):
                        src_path = os.path.join(nov_temp_dir, filename)
                        dest_path = os.path.join(upload_folder, filename)
                        if os.path.isfile(src_path):
                            shutil.copy(src_path, dest_path)
                shutil.rmtree(temp_dir)
                return jsonify({'message': 'Restauração concluída com sucesso!', 'category': 'success'})
            except Exception as e:
                shutil.rmtree(temp_dir)
                return jsonify({'message': f'Erro na restauração: {str(e)}', 'category': 'error'})
    return render_template('admin.html', users=users, gifts=gifts, modules_state=module_status)

# Notifications Page
@app.route('/notifications', methods=['GET', 'POST'])
@jwt_required()
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
            save_data(users, 'users.json')
        return jsonify({'success': True})
    return render_template('notifications.html', unread=unread, read=read, users=users)

# Novidades Page
@app.route('/novidades', methods=['GET'])
@jwt_required()
def novidades():
    users = load_data('users.json')
    if users[g.user_id]['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    return render_template('novidades.html', news=news, users=users)

# Create Novidade
@app.route('/novidades/new', methods=['GET', 'POST'])
@jwt_required()
def new_novidade():
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title')
        desc = request.form.get('desc')
        image = request.files.get('image')
        if not title or not desc:  # Validation
            flash('Algo deu errado.', 'error')
            return render_template('new_novidade.html', users=users)
        news = load_data('news.json')
        news_id = str(uuid.uuid4())
        image_path = None
        if image and image.filename:
            ext = os.path.splitext(image.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                image_filename = f'{news_id}{ext}'
                image_path_full = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image.save(image_path_full)
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
        flash('Novidade enviada com sucesso!', 'success')
        return redirect('/novidades')
    return render_template('new_novidade.html', users=users)

# Edit Novidade
@app.route('/novidades/edit/<news_id>', methods=['GET', 'POST'])
@jwt_required()
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
        title = request.form.get('title')
        desc = request.form.get('desc')
        if not title or not desc:  # Validation
            flash('Algo deu errado.', 'error')
            return render_template('edit_novidade.html', item=item, users=users)
        item['title'] = title
        item['desc'] = desc
        image = request.files.get('image')
        if image and image.filename:
            ext = os.path.splitext(image.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                image_filename = f'{news_id}{ext}'
                image_path_full = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                image.save(image_path_full)
                item['image'] = f'/static/novidades/{image_filename}'
        save_data(news, 'news.json')
        flash('Novidade editada com sucesso!', 'success')
        return redirect('/novidades')
    return render_template('edit_novidade.html', item=item, users=users)

# Delete Novidade
@app.route('/novidades/delete/<news_id>', methods=['POST'])
@jwt_required()
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
            os.remove(os.path.join(app.root_path + item['image']))
        except:
            pass
    save_data(news, 'news.json')
    flash('Novidade excluída com sucesso!', 'success')
    return redirect('/novidades')

# Module Routes (all protected with jwt_required and generic errors)
@app.route('/modulos/mae', methods=['GET', 'POST'])
@jwt_required()
def mae():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome')
        if not nome or len(nome) < 3:  # Validation
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=mae"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('status') and data.get('response'):
                    valid_results = [r for r in data['response'] if r.get('CPF') and r.get('NOME')]
                    if valid_results:
                        if manage_module_usage(g.user_id, 'mae'):
                            result = valid_results
                        else:
                            flash('Algo deu errado.', 'error')
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('mae.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/pai', methods=['GET', 'POST'])
@jwt_required()
def pai():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome')
        if not nome or len(nome) < 3:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=pai"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('status') and data.get('response'):
                    valid_results = [r for r in data['response'] if r.get('CPF') and r.get('NOME') and r.get('PAI')]
                    if valid_results:
                        if manage_module_usage(g.user_id, 'pai'):
                            result = valid_results
                        else:
                            flash('Algo deu errado.', 'error')
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('pai.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/cnpjcompleto', methods=['GET', 'POST'])
@jwt_required()
def cnpjcompleto():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cnpj_input = ""
    if request.method == 'POST':
        cnpj_input = request.form.get('cnpj', '').strip()
        if len(cnpj_input) != 14 or not cnpj_input.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cnpj_input}&tipo=cnpjcompleto"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                empresa = data.get("empresa", {})
                estab = empresa.get("estabelecimento", {})
                secundarias = [
                    f"{a.get('subclasse', '')} - {a.get('descricao', '')}"
                    for a in estab.get("atividades_secundarias", [])
                ]
                socios = [
                    f"{s.get('nome', 'Não informado')} ({s.get('qualificacao_socio', {}).get('descricao', 'Não informado')})"
                    for s in empresa.get("socios", [])
                ]
                result = {
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
                if manage_module_usage(g.user_id, 'cnpjcompleto'):
                    pass
                else:
                    flash('Algo deu errado.', 'error')
                    result = None
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cnpjcompleto.html', is_admin=is_admin, notifications=unread_count, result=result, cnpj_input=cnpj_input)

@app.route('/modulos/cpf', methods=['GET', 'POST'])
@jwt_required()
def cpf():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv1"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'CPF' in data and data['CPF'] and data.get('NOME'):
                    if manage_module_usage(g.user_id, 'cpf'):
                        result = data
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/cpf2', methods=['GET', 'POST'])
@jwt_required()
def cpf2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=cpf1&query={cpf}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpf2'):
                        result = data['resultado']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
@jwt_required()
def cpfdata():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv3"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data and data.get('nome'):
                    if manage_module_usage(g.user_id, 'cpfdata'):
                        raw_result = data
                        processed_result = {
                            'nome': raw_result.get('nome', 'SEM INFORMAÇÃO').rstrip('---'),
                            'cpf': raw_result.get('documentos', {}).get('cpf', 'SEM INFORMAÇÃO').replace('.', '').replace('-', ''),
                            'sexo': raw_result.get('sexo', 'SEM INFORMAÇÃO'),
                            'dataNascimento': {
                                'nascimento': 'SEM INFORMAÇÃO',
                                'idade': 'SEM INFORMAÇÃO',
                                'signo': 'SEM INFORMAÇÃO'
                            },
                            'nomeMae': raw_result.get('mae', 'SEM INFORMAÇÃO'),
                            'nomePai': raw_result.get('pai', 'SEM INFORMAÇÃO'),
                            'telefone': [],
                            'nacionalidade': {
                                'municipioNascimento': raw_result.get('endereco', {}).get('municipio_residencia', 'SEM INFORMAÇÃO'),
                                'paisNascimento': raw_result.get('endereco', {}).get('pais', 'SEM INFORMAÇÃO')
                            },
                            'enderecos': [],
                            'cnsDefinitivo': raw_result.get('cns', 'SEM INFORMAÇÃO'),
                            'raca': raw_result.get('raca', 'SEM INFORMAÇÃO'),
                            'tipo_sanguineo': raw_result.get('tipo_sanguineo', 'SEM INFORMAÇÃO'),
                            'nome_social': raw_result.get('nome_social', None) or 'Não possui'
                        }
                        # Parse nascimento
                        nasc = raw_result.get('nascimento', 'SEM INFORMAÇÃO')
                        if ' (' in nasc and ' anos)' in nasc:
                            date_str = nasc.split(' (')[0]
                            age_str = nasc.split(' (')[1].rstrip(' anos)')
                            processed_result['dataNascimento'] = {
                                'nascimento': date_str,
                                'idade': age_str,
                                'signo': 'SEM INFORMAÇÃO'
                            }
                            # Calculate signo
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
                        telefones = raw_result.get('contatos', {}).get('telefones', [])
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
                        endereco = raw_result.get('endereco', {})
                        if endereco:
                            if 'municipio_residencia' in endereco:
                                parts = endereco['municipio_residencia'].split(' - ')
                                if len(parts) > 0:
                                    endereco['cidade'] = parts[0]
                                if len(parts) > 1:
                                    endereco['uf'] = parts[1]
                            processed_result['enderecos'] = [endereco]
                        result = processed_result
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/cpf3', methods=['GET', 'POST'])
@jwt_required()
def cpf3():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpffull"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'CPF' in data and data['CPF']:
                    if manage_module_usage(g.user_id, 'cpf3'):
                        result = data
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/cpflv', methods=['GET', 'POST'])
@jwt_required()
def cpflv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=cpfLv&query={cpf}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if (data.get('resultado') and
                    data['resultado'].get('status') == 'success' and
                    'data' in data['resultado'] and
                    'pessoa' in data['resultado']['data'] and
                    'identificacao' in data['resultado']['data']['pessoa'] and
                    'cpf' in data['resultado']['data']['pessoa']['identificacao']):
                    if manage_module_usage(g.user_id, 'cpflv'):
                        result = data['resultado']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/vacinas', methods=['GET', 'POST'])
@jwt_required()
def vacinas():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = []
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=vacina"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                imunizacoes = []
                if isinstance(data, dict):
                    if data.get('status') and 'response' in data and 'dados' in data['response']:
                        imunizacoes = data['response']['dados']
                    elif 'resultado' in data and isinstance(data['resultado'], list):
                        imunizacoes = data['resultado']
                if imunizacoes:
                    if manage_module_usage(g.user_id, 'vacinas'):
                        results = imunizacoes
                    else:
                        flash('Algo deu errado.', 'error')
                        results = []
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf)

@app.route('/modulos/datanome', methods=['GET', 'POST'])
@jwt_required()
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
        nome = request.form.get('nome', '').strip()
        datanasc = request.form.get('datanasc', '').strip()
        if not nome or not datanasc:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                raw_results = []
                if isinstance(data, list):
                    raw_results = data
                elif isinstance(data, dict) and 'resultado' in data and isinstance(data['resultado'], list):
                    raw_results = data['resultado']
                try:
                    user_date = datetime.strptime(datanasc, '%Y-%m-%d').date()
                except ValueError:
                    flash('Algo deu errado.', 'error')
                    return render_template('datanome.html', is_admin=is_admin, notifications=unread_count,
                                           results=results, nome=nome, datanasc=datanasc)
                for item in raw_results:
                    if 'NASCIMENTO' in item and item['NASCIMENTO']:
                        try:
                            api_date_str = item['NASCIMENTO'].strip()
                            api_date = datetime.strptime(api_date_str, '%d/%m/%Y').date()
                            if api_date == user_date:
                                results.append(item)
                        except (ValueError, AttributeError):
                            continue
                if results:
                    if manage_module_usage(g.user_id, 'datanome'):
                        pass
                    else:
                        flash('Algo deu errado.', 'error')
                        results = []
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('datanome.html', is_admin=is_admin, notifications=unread_count,
                           results=results, nome=nome, datanasc=datanasc)

@app.route('/modulos/placalv', methods=['GET', 'POST'])
@jwt_required()
def placalv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placacompleta"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('status') and 'response' in data and 'dados' in data['response']:
                    veiculo = data['response']['dados'].get('veiculo', {})
                    if veiculo and veiculo.get('placa'):
                        if manage_module_usage(g.user_id, 'placalv'):
                            result = data['response']['dados']
                        else:
                            flash('Algo deu errado.', 'error')
                            result = None
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('placalv.html', is_admin=is_admin, notifications=unread_count,
                           result=result, placa=placa)

@app.route('/modulos/telLv', methods=['GET', 'POST'])
@jwt_required()
def telLv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    telefone = ""
    if request.method == 'POST':
        telefone = ''.join(c for c in request.form.get('telefone', '').strip() if c.isdigit())
        if not telefone or len(telefone) < 10 or len(telefone) > 11:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={telefone}&tipo=telefonev2"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('status') and 'response' in data:
                    response_data = data['response']
                    if response_data.get('CPF') and response_data['CPF'] != 'SEM RESULTADO':
                        if manage_module_usage(g.user_id, 'telLv'):
                            result = response_data
                        else:
                            flash('Algo deu errado.', 'error')
                            result = None
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('tellv.html', is_admin=is_admin, notifications=unread_count,
                           result=result, telefone=telefone)

@app.route('/modulos/teldual', methods=['GET', 'POST'])
@jwt_required()
def teldual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    telefone = ""
    if request.method == 'POST':
        telefone = request.form.get('telefone', '').strip()
        if not telefone:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=teldual&query={telefone}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and data['resultado'] and any('cpf' in item for item in data['resultado']):
                    if manage_module_usage(g.user_id, 'teldual'):
                        results = data['resultado']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('teldual.html', is_admin=is_admin, notifications=unread_count, results=results, telefone=telefone)

@app.route('/modulos/tel', methods=['GET', 'POST'])
@jwt_required()
def tel():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    tel_input = ""
    if request.method == 'POST':
        tel_input = request.form.get('tel', '').strip()
        if not tel_input:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=telefone&query={tel_input}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and 'cpf' in data['resultado']:
                    if manage_module_usage(g.user_id, 'tel'):
                        results = data['resultado']['msg']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('tel.html', is_admin=is_admin, notifications=unread_count, results=results, tel=tel_input)

@app.route('/modulos/placa', methods=['GET', 'POST'])
@jwt_required()
def placa():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placanormal"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('PLACA') == placa:
                    if manage_module_usage(g.user_id, 'placa'):
                        result = data
                    else:
                        flash('Algo deu errado.', 'error')
                        result = None
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('placa.html', is_admin=is_admin, notifications=unread_count,
                           result=result, placa=placa)

@app.route('/modulos/placaestadual', methods=['GET', 'POST'])
@jwt_required()
def placaestadual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper()
        if not placa:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=placaestadual&query={placa}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and isinstance(data['resultado'], list) and len(data['resultado']) > 0 and data['resultado'][0].get('retorno') == 'ok':
                    if manage_module_usage(g.user_id, 'placaestadual'):
                        results = data['resultado']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('placaestadual.html', is_admin=is_admin, notifications=unread_count, results=results, placa=placa)

@app.route('/modulos/pix', methods=['GET', 'POST'])
@jwt_required()
def pix():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    chave = ""
    if request.method == 'POST':
        chave = request.form.get('chave', '').strip()
        if not chave or len(chave) < 11:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={chave}&tipo=pix"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('Status') == 'Sucesso' and 'nome' in data:
                    if manage_module_usage(g.user_id, 'pix'):
                        result = data
                    else:
                        flash('Algo deu errado.', 'error')
                        result = None
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('pix.html', is_admin=is_admin, notifications=unread_count,
                           result=result, chave=chave)

@app.route('/modulos/fotor', methods=['GET', 'POST'])
@jwt_required()
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
        documento = request.form.get('documento', '').strip()
        selected_option = request.form.get('estado', '')
        if not documento or not selected_option:
            flash('Algo deu errado.', 'error')
        else:
            try:
                base_url = "https://br1.stormhost.online:10004/api/token=@signficativo/consulta"
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
                    flash('Algo deu errado.', 'error')
                    return render_template(
                        'fotor.html',
                        is_admin=is_admin,
                        notifications=unread_count,
                        results=results,
                        documento=documento,
                        selected_option=selected_option
                    )
                url = f"{base_url}?dado={documento}&tipo={tipo}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                raw = response.text.strip()
                data = json.loads(raw.lstrip('\ufeff'))
                inner = data.get("response", {}).get("response", [])
                if not inner or not isinstance(inner, list) or not inner[0].get("fotob64"):
                    flash('Algo deu errado.', 'error')
                else:
                    foto_b64 = inner[0]["fotob64"]
                    cpf_ret = inner[0].get("cpf", "")
                    results = {
                        "foto_base64": foto_b64,
                        "cpf": cpf_ret or documento
                    }
                    if manage_module_usage(g.user_id, 'fotor'):
                        pass
                    else:
                        flash('Algo deu errado.', 'error')
                        results = None
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template(
        'fotor.html',
        is_admin=is_admin,
        notifications=unread_count,
        results=results,
        documento=documento,
        selected_option=selected_option
    )

@app.route('/modulos/nomelv', methods=['GET', 'POST'])
@jwt_required()
def nomelv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome or len(nome) < 3:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                results_list = []
                if isinstance(data, list) and len(data) > 0:
                    results_list = data
                elif isinstance(data, dict) and 'resultado' in data and isinstance(data['resultado'], list):
                    results_list = data['resultado']
                else:
                    flash('Algo deu errado.', 'error')
                    results_list = []
                if results_list:
                    if manage_module_usage(g.user_id, 'nomelv'):
                        results = results_list
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('nomelv.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/nome', methods=['GET', 'POST'])
@jwt_required()
def nome():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome or len(nome) < 3:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev1"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado') and len(data['resultado']) > 0:
                    if manage_module_usage(g.user_id, 'nome'):
                        results = data['resultado']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('nome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/ip', methods=['GET', 'POST'])
@jwt_required()
def ip():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    ip_address = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip', '').strip()
        if not ip_address:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://ipwho.is/{ip_address}"
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('success'):
                    if manage_module_usage(g.user_id, 'ip'):
                        results = {
                            'ip': data.get('ip'),
                            'continent': data.get('continent'),
                            'country': data.get('country'),
                            'region': data.get('region'),
                            'city': data.get('city'),
                            'latitude': data.get('latitude'),
                            'longitude': data.get('longitude'),
                            'provider': data.get('connection', {}).get('isp', 'Não disponível')
                        }
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('ip.html', is_admin=is_admin, notifications=unread_count, results=results, ip_address=ip_address)

@app.route('/modulos/nome2', methods=['GET', 'POST'])
@jwt_required()
def nome2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome or len(nome) < 3:
            flash('Algo deu errado.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=nomeData&query={nome}"
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado') and 'itens' in data['resultado']:
                    if manage_module_usage(g.user_id, 'nome2'):
                        results = data['resultado']['itens']
                    else:
                        flash('Algo deu errado.', 'error')
                else:
                    flash('Algo deu errado.', 'error')
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('nome2.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/likeff', methods=['GET', 'POST'])
@jwt_required()
def likeff():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    result = None
    uid = ""
    if request.method == 'POST':
        uid = request.form.get('uid', '').strip()
        server_name = 'br'
        if not uid:
            flash('Algo deu errado.', 'error')
        else:
            try:
                token_url = "http://teamxcutehack.serv00.net/like/token_ind.json"
                ffinfo_url = f"https://lk-team-ffinfo-five.vercel.app/ffinfo?id={uid}"
                like_api_url = f"https://likeapiff.thory.in/like?uid={uid}&server_name={server_name}&token_url={requests.utils.quote(token_url)}"
                ffinfo_response = requests.get(ffinfo_url, timeout=30)
                ffinfo_response.raise_for_status()
                ffinfo_data = json.loads(ffinfo_response.text.lstrip('\ufeff'))
                if not ffinfo_data:
                    flash('Algo deu errado.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                if "account_info" not in ffinfo_data or "├ Likes" not in ffinfo_data["account_info"]:
                    flash('Algo deu errado.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                likes_before = int(str(ffinfo_data["account_info"]["├ Likes"]).replace(',', ''))
                like_response = requests.get(like_api_url, timeout=30, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
                if like_response.status_code != 200:
                    flash('Algo deu errado.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                like_data = json.loads(like_response.text.lstrip('\ufeff'))
                if not like_data or "LikesafterCommand" not in like_data:
                    flash('Algo deu errado.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
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
                if manage_module_usage(g.user_id, 'likeff'):
                    pass
                else:
                    flash('Algo deu errado.', 'error')
                    result = None
            except Exception as e:
                flash('Algo deu errado.', 'error')
    return render_template('likeff.html', is_admin=is_admin,
                         notifications=unread_count,
                         result=result, uid=uid)

# Atestado
@app.route('/modulos/atestado', methods=['GET', 'POST'])
@jwt_required()
def atestado():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    role = user['role']
    if not is_admin and role not in ['user_mensal', 'user_anual']:
        flash('Acesso negado. Este módulo é apenas para usuários mensais, anuais ou admins.', 'error')
        return redirect('/dashboard')
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications.get(g.user_id, []) if n['id'] not in user.get('read_notifications', [])])
    pdf_preview = None
    edited_pdf_path = None
    if request.method == 'POST':
        if not manage_module_usage(g.user_id, 'atestado'):
            flash('Algo deu errado.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, pdf_preview=None)
        # DADOS DO FORMULÁRIO with validation
        nome_paciente = request.form.get('nome_paciente', '').strip().upper()
        cpf = request.form.get('cpf', '').strip()
        profissional = request.form.get('profissional', '').strip().upper()
        crm = request.form.get('crm', '').strip()
        data_atendimento = request.form.get('data_atendimento', '').strip()
        data_assinatura = request.form.get('data_assinatura', '').strip()
        cidade = request.form.get('cidade', '').strip().title()
        uf = request.form.get('uf', '').strip().upper()
        cid = request.form.get('cid', '').strip().upper()
        dias_afastamento = request.form.get('dias_afastamento', '').strip().upper()
        n_atend = request.form.get('n_atend', '').strip()
        n_pront = request.form.get('n_pront', '').strip()
        if not nome_paciente or not cpf or not profissional:  # Basic validation
            flash('Algo deu errado.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, pdf_preview=None)
        # CAMINHOS
        original_pdf = 'atestado.pdf'
        if not os.path.exists(original_pdf):
            flash('Algo deu errado.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, pdf_preview=None)
        edited_pdf = f'static/edited_atestado_{uuid.uuid4().hex}.pdf'
        preview_img = f'static/preview_{uuid.uuid4().hex}.png'
        try:
            # ABRIR PDF
            doc = fitz.open(original_pdf)
            page = doc[0]
            # CARREGAR FONTES LOCAIS (adicionar à página)
            font_normal_path = 'fonts/DejaVuSans.ttf'
            font_bold_path = 'fonts/DejaVuSans-Bold.ttf'
            font_normal_name = page.insert_font(fontfile=font_normal_path) if os.path.exists(font_normal_path) else "helv"
            font_bold_name = page.insert_font(fontfile=font_bold_path) if os.path.exists(font_bold_path) else "hebo"
            # FUNÇÃO PARA INSERIR TEXTO COM FONTE PERSONALIZADA
            def insert_text(text, point, font_size=10, bold=False):
                fontname = font_bold_name if bold else font_normal_name
                page.insert_text(
                    point,
                    text,
                    fontsize=font_size,
                    fontname=fontname,
                    color=(0, 0, 0)
                )
            # LIMPAR ÁREAS
            def clear_area(rect):
                page.draw_rect(rect, color=(1,1,1), fill=(1,1,1))
            # POSIÇÕES (ajustadas para seu PDF)
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
            # LIMPAR CAMPOS
            for rect in [
                fitz.Rect(65, 100, 300, 115),
                fitz.Rect(65, 115, 300, 130),
                fitz.Rect(65, 130, 300, 145),
                fitz.Rect(375, 100, 520, 115),
                fitz.Rect(375, 115, 520, 130),
                fitz.Rect(375, 130, 520, 145),
                fitz.Rect(175, 255, 420, 270),
                fitz.Rect(65, 355, 150, 370),
                fitz.Rect(65, 405, 250, 420),
                fitz.Rect(295, 455, 520, 470),
                fitz.Rect(295, 470, 520, 485),
                fitz.Rect(65, 300, 520, 350),  # corpo do texto
            ]:
                clear_area(rect)
            # INSERIR TEXTOS
            insert_text(nome_paciente or 'ERICK GABRIEL COTA', positions["nome_paciente"], font_size=10, bold=True)
            insert_text(cpf or '413.759.068-01', positions["cpf"], font_size=10)
            insert_text(profissional or 'CAROLINA SAAD HASSEM', positions["profissional"], font_size=10)
            insert_text(n_atend or '4532519', positions["n_atend"], font_size=10)
            insert_text(n_pront or '0009372517', positions["n_pront"], font_size=10)
            insert_text(data_assinatura or '28/10/2025 14:08:57', positions["data_assinatura"], font_size=10)
            insert_text(f"{cidade or 'Guaratinguetá'}, {uf or 'SP'} - {data_atendimento or '28 de Outubro de 2025'}", positions["cidade_data"], font_size=10)
            insert_text(cid or 'J11', positions["cid"], font_size=10, bold=True)
            insert_text(dias_afastamento or '01 (UM)', positions["dias_afastamento"], font_size=10, bold=True)
            insert_text(f"Dr(a). {profissional or 'CAROLINA SAAD HASSEM'}", positions["profissional_assinatura"], font_size=10)
            insert_text(f"{crm or '191662'} CRM", positions["crm_assinatura"], font_size=10)
            # CORPO DO ATESTADO
            corpo = f"Atesto para os devidos fins que {nome_paciente or 'ERICK GABRIEL COTA'} foi atendido(a) neste serviço, necessitando de afastamento por {dias_afastamento or '01 (UM)'} dia(s) das suas atividades profissionais."
            page.insert_textbox(
                fitz.Rect(65, 300, 520, 350),
                corpo,
                fontsize=11,
                fontname="helv",
                align=fitz.TEXT_ALIGN_JUSTIFY
            )
            # SALVAR PDF
            doc.save(edited_pdf, garbage=4, deflate=True, clean=True)
            doc.close()
            # GERAR PRÉ-VISUALIZAÇÃO
            doc_prev = fitz.open(edited_pdf)
            pix = doc_prev[0].get_pixmap(dpi=150)
            pix.save(preview_img)
            doc_prev.close()
            pdf_preview = preview_img
            edited_pdf_path = edited_pdf
        except Exception as e:
            flash('Algo deu errado.', 'error')
            return render_template('atestado_c.html', is_admin=is_admin, notifications=unread_count, pdf_preview=None)
    return render_template(
        'atestado_c.html',
        is_admin=is_admin,
        notifications=unread_count,
        pdf_preview=pdf_preview,
        edited_pdf=edited_pdf_path
    )

# Download Edited PDF
@app.route('/download_edited/<path:filename>')
@jwt_required()
def download_edited(filename):
    return send_from_directory(app.root_path, filename, as_attachment=True)

# Logout
@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    unset_jwt_cookies(resp)
    return resp

# Credits
@app.route('/@A30')
def creditos():
    return "@enfurecido - {'0x106a90000'}"

# Preview Image
@app.route('/preview.jpg')
def preview():
    return send_from_directory(app.root_path, 'preview.jpg', mimetype='image/jpeg')

if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json', default_data={})
    initialize_json('gifts.json')
    initialize_json('news.json', default_data=[])
    import threading  # For blacklist timer
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
