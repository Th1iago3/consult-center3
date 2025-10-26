from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session
from flask_socketio import SocketIO, emit
import json
import os
import secrets
import requests
from datetime import datetime, timedelta
import jwt
import time
import colorama
from colorama import Fore, Style
import re
import base64
from functools import wraps
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import uuid  # Adicionado para UUIDs dinâmicos

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['RSA_PRIVATE_KEY'] = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
app.config['RSA_PUBLIC_KEY'] = app.config['RSA_PRIVATE_KEY'].public_key()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()

# Rate limiting storage (in-memory for simplicity)
login_attempts = {}
module_status = {
    'cpfdata': 'ON',
    'cpflv': 'OFF',
    'cpf': 'ON',
    'cpf2': 'ON',
    'vacinas': 'ON',
    'cpf3': 'ON',
    'nomelv': 'ON',
    'nome': 'OFF',
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
    'likeff': 'OFF'
}

chave = "vmb1"

# Encryption Functions
def encrypt_with_rsa(data, public_key):
    return public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_with_rsa(encrypted_data):
    private_key = app.config['RSA_PRIVATE_KEY']
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def encrypt_with_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + ct

def decrypt_with_aes(encrypted, key):
    iv = encrypted[:16]
    ct = encrypted[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ct) + decryptor.finalize()
    return decrypted.decode()

def generate_keys():
    user_key = secrets.token_bytes(32)  # AES key
    public_key_pem = app.config['RSA_PUBLIC_KEY'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return user_key, public_key_pem

def generate_byte_cookie():
    return os.urandom(32)  # 32 bytes for randomness

def byte_to_hex(byte_data):
    return base64.b16encode(byte_data).decode('ascii')

def validate_byte_hex(byte_cookie, hex_cookie):
    hex_back_to_bytes = base64.b16decode(hex_cookie.encode('ascii'))
    return hex_back_to_bytes == byte_cookie

def generate_custom_cookies():
    cookies = {
        "JSESSIONID": secrets.token_urlsafe(16),
        "TS" + secrets.token_hex(4): secrets.token_hex(128),
        "TS" + secrets.token_hex(4): secrets.token_hex(128),
        "_ga": f"GA1.4.{secrets.token_hex(8)}.{int(time.time())}",
        "_ga_" + secrets.token_hex(4): f"GS1.1.{int(time.time())}.4.1.{int(time.time() + 3600)}.0.0.0",
        "_gat_gtag_UA_" + secrets.token_hex(4) + "_1": "1",
        "_gid": f"GA.{secrets.randbelow(10)}.{secrets.choice('abcdefghijklmnopqrstuvwxyz')}.{secrets.token_hex(4)}",
        "TS" + secrets.token_hex(4): secrets.token_hex(128),
        "Mabel": secrets.token_hex(8),
        "TS" + secrets.token_hex(4): secrets.token_hex(128),
        "Omega": base64.b64encode(secrets.token_bytes(32)).decode()
    }
    return cookies

def decode_json_with_bom(response_text):
    if response_text.startswith('\ufeff'):
        response_text = response_text[1:]
    return json.loads(response_text)

def check_referrer():
    referrer = request.headers.get('Referer', '')
    return referrer.startswith('https://consult-center3.onrender.com')

def check_user_agent():
    user_agent = request.headers.get('User-Agent', '')
    browser_pattern = re.compile(r'(Chrome|Firefox|Safari|Edge|Opera)', re.IGNORECASE)
    return bool(browser_pattern.search(user_agent))

# JSON File Management
def initialize_json(file_path):
    try:
        with open(file_path, 'r') as file:
            json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(file_path, 'w') as file:
            json.dump({}, file)

def load_data(file_path):
    with open(file_path, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return {}

def save_data(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

# Token Management
def generate_token(user_id):
    users = load_data('users.json')
    exp_time = timedelta(days=3650) if users.get(user_id, {}).get('role') == 'admin' else timedelta(minutes=15)
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + exp_time}
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return None

# Logging
def log_access(endpoint, message=''):
    try:
        response = requests.get('https://ipinfo.io/json')
        response.raise_for_status()
        ip_info = response.json()
        ip = ip_info.get('ip', '')
    except requests.RequestException:
        ip = request.remote_addr
        message += f" [Error fetching real IP]"
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip} - {now} accessed {endpoint}. {message}")

def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})

    if user.get('role') == 'admin':
        return True  # Admins have unlimited access

    if 'modules' not in user:
        user['modules'] = {m: 0 for m in [
            'cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv',
            'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5', 'likeff', 'teldual'
        ]}

    if increment:
        user['modules'][module] += 1

    today = datetime.now().date()
    if 'last_reset' not in user or user['last_reset'] != today.isoformat():
        user['modules'] = {k: 0 for k in user['modules']}  # Reset all modules to 0
        user['last_reset'] = today.isoformat()

    usage_limit = {
        'user_semanal': 30,
        'user_mensal': 250,
        'user_anual': 500
    }.get(user.get('role', 'user_semanal'), 30)

    if user['modules'][module] > usage_limit:
        flash(f'Você excedeu o limite diário de {usage_limit} requisições para o módulo {module}.', 'error')
        return False

    users[user_id] = user
    save_data(users, 'users.json')
    return True


def reset_all():
    if 'user_id' in g:
        token = generate_token(g.user_id)
        byte_cookie = generate_byte_cookie()
        hex_cookie = byte_to_hex(byte_cookie)
        encrypted_token = encrypt_with_rsa(token, app.config['RSA_PUBLIC_KEY'])
        
        resp = make_response()
        resp.set_cookie('auth_token', base64.b64encode(encrypted_token).decode('ascii'), httponly=True, secure=True, samesite='Strict')
        resp.set_cookie('byte_cookie', base64.b64encode(byte_cookie).decode('ascii'), httponly=True, secure=True, samesite='Strict')
        resp.set_cookie('hex_cookie', hex_cookie, httponly=True, secure=True, samesite='Strict')
        
        custom_cookies = generate_custom_cookies()
        for key, value in custom_cookies.items():
            resp.set_cookie(key, value, httponly=True, secure=True, samesite='Strict')
        
        # Update session keys if needed
        session['user_key'], _ = generate_keys()
        session['session_id'] = secrets.token_hex(16)  # Adiciona um ID único para a sessão
        session['user_id'] = g.user_id  # Associa o user_id à sessão
        
        return resp
    else:
        return jsonify({"error": "User not authenticated"}), 401
        
# Session Management
def invalidate_session(user_id):
    users = load_data('users.json')
    if user_id in users:
        del users[user_id]
        save_data(users, 'users.json')
        session.clear()
        log_access("Session Invalidated", f"User {user_id} removed due to suspicious activity.")
    resp = redirect('/')
    resp.set_cookie('auth_token', '', expires=0)
    resp.set_cookie('byte_cookie', '', expires=0)
    resp.set_cookie('hex_cookie', '', expires=0)
    return resp

def verify_session_integrity():
    token_cookie = request.cookies.get('auth_token')
    byte_cookie = request.cookies.get('byte_cookie')
    hex_cookie = request.cookies.get('hex_cookie')

    if not all([token_cookie, byte_cookie, hex_cookie]):
        return False, "Cookies ausentes"

    try:
        encrypted_token = base64.b64decode(token_cookie)
        token = decrypt_with_rsa(encrypted_token)
        user_id = decode_token(token)

        byte_cookie_decoded = base64.b64decode(byte_cookie)
        if not validate_byte_hex(byte_cookie_decoded, hex_cookie):
            return False, "Cookies manipulados detectados"

        if 'session_id' not in session or session['user_id'] != user_id:
            return False, "Sessão não corresponde ao usuário autenticado"

        return True, "Sessão válida"
    except Exception as e:
        return False, f"Erro ao verificar sessão: {str(e)}"

# Rate Limiting for Login Attempts
def check_login_attempts(user_id):
    now = time.time()
    if user_id not in login_attempts:
        login_attempts[user_id] = {'count': 0, 'last_attempt': now}
    
    attempts = login_attempts[user_id]
    if now - attempts['last_attempt'] > 300:  # Reset after 5 minutes
        attempts['count'] = 0
        attempts['last_attempt'] = now
    
    attempts['count'] += 1
    if attempts['count'] > 5:  # Max 5 attempts in 5 minutes
        return False, "Muitas tentativas de login. Tente novamente em 5 minutos."
    login_attempts[user_id] = attempts
    return True, ""

@app.before_request
def security_check():
    if request.endpoint not in ['login', '/@A30']:
        if not check_referrer() or not check_user_agent():
            log_access(request.endpoint, "Invalid referrer or user agent")
            return redirect('/')

        is_valid, message = verify_session_integrity()
        if not is_valid:
            log_access(request.endpoint, f"Suspicious activity: {message}")
            if 'user_id' in g:
                return invalidate_session(g.user_id)
            return redirect('/')

        token_cookie = request.cookies.get('auth_token')
        if not token_cookie:
            log_access(request.endpoint, "Unauthenticated user")
            return redirect('/')

        try:
            encrypted_token = base64.b64decode(token_cookie)
            token = decrypt_with_rsa(encrypted_token)
            user_id = decode_token(token)
            if user_id in [None, "expired"]:
                flash('Sua sessão expirou. Faça login novamente.', 'error')
                resp = redirect('/')
                resp.set_cookie('auth_token', '', expires=0)
                return resp

            users = load_data('users.json')
            if user_id not in users:
                flash('Sessão inválida. Faça login novamente.', 'error')
                return redirect('/')
            
            g.user_id = user_id
        except Exception as e:
            log_access(request.endpoint, f"Error decoding token: {str(e)}")
            flash('Dados de sessão inválidos. Faça login novamente.', 'error')
            return redirect('/')

def reset_session_cookies():
    if 'user_id' in g:
        token = generate_token(g.user_id)
        byte_cookie = generate_byte_cookie()
        hex_cookie = byte_to_hex(byte_cookie)
        encrypted_token = encrypt_with_rsa(token, app.config['RSA_PUBLIC_KEY'])
        
        resp = make_response()
        resp.set_cookie('auth_token', base64.b64encode(encrypted_token).decode('ascii'), httponly=True, secure=True, samesite='Strict')
        resp.set_cookie('byte_cookie', base64.b64encode(byte_cookie).decode('ascii'), httponly=True, secure=True, samesite='Strict')
        resp.set_cookie('hex_cookie', hex_cookie, httponly=True, secure=True, samesite='Strict')
        
        custom_cookies = generate_custom_cookies()
        for key, value in custom_cookies.items():
            resp.set_cookie(key, value, httponly=True, secure=True, samesite='Strict')
        
        session['user_key'], _ = generate_keys()
        session['session_id'] = secrets.token_hex(16)
        session['user_id'] = g.user_id
        
        return resp
    return jsonify({"error": "User not authenticated"}), 401
        
        
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('password')
        users = load_data('users.json')
        user_agent = request.headers.get('User-Agent')

        # Check login attempts
        can_login, message = check_login_attempts(user)
        if not can_login:
            flash(message, 'error')
            return render_template('login.html')

        if user in users and users[user]['password'] == password:
            expiration_date = datetime.strptime(users[user]['expiration'], '%Y-%m-%d')
            if datetime.now() < expiration_date:
                token = generate_token(user)
                user_key, public_key = generate_keys()
                session['user_key'] = user_key
                session['public_key'] = public_key
                session['user_id'] = user
                session['session_id'] = secrets.token_hex(16)
                
                # Gerar UUIDs dinâmicos para módulos
                session['module_uuids'] = {
                    'cpf': str(uuid.uuid4()),
                    'cpf2': str(uuid.uuid4()),
                    'cpfdata': str(uuid.uuid4()),
                    'cpflv': str(uuid.uuid4()),
                    'cpf3': str(uuid.uuid4()),
                    'vacinas': str(uuid.uuid4()),
                    'nomelv': str(uuid.uuid4()),
                    'nome': str(uuid.uuid4()),
                    'nome2': str(uuid.uuid4()),
                    'tel': str(uuid.uuid4()),
                    'tellv': str(uuid.uuid4()),
                    'teldual': str(uuid.uuid4()),
                    'datanome': str(uuid.uuid4()),
                    'placa': str(uuid.uuid4()),
                    'placaestadual': str(uuid.uuid4()),
                    'fotor': str(uuid.uuid4()),
                    'pix': str(uuid.uuid4()),
                    'placalv': str(uuid.uuid4()),
                    'ip': str(uuid.uuid4()),
                    'likeff': str(uuid.uuid4())
                }
                
                byte_cookie = generate_byte_cookie()
                hex_cookie = byte_to_hex(byte_cookie)
                encrypted_token = encrypt_with_rsa(token, app.config['RSA_PUBLIC_KEY'])
                custom_cookies = generate_custom_cookies()
                
                resp = redirect('/dashboard')
                for key, value in custom_cookies.items():
                    resp.set_cookie(key, value, httponly=True, secure=True, samesite='Strict')
                
                resp.set_cookie('auth_token', base64.b64encode(encrypted_token).decode('ascii'), httponly=True, secure=True, samesite='Strict')
                resp.set_cookie('byte_cookie', base64.b64encode(byte_cookie).decode('ascii'), httponly=True, secure=True, samesite='Strict')
                resp.set_cookie('hex_cookie', hex_cookie, httponly=True, secure=True, samesite='Strict')
                
                # Device management logic: if 'devices' key is absent, allow unlimited devices
                if 'devices' not in users[user]:
                    # User supports unlimited devices, no restriction applied
                    save_data(users, 'users.json')
                else:
                    # User has device restriction
                    if users[user]['devices'] and user_agent not in users[user]['devices']:
                        flash('Dispositivo não autorizado. Login recusado.', 'error')
                        return render_template('login.html')
                    else:
                        users[user]['devices'] = [user_agent]
                        save_data(users, 'users.json')

                # Reset login attempts on successful login
                login_attempts[user] = {'count': 0, 'last_attempt': time.time()}
                return resp
            else:
                flash('Usuário expirado. Contate seu vendedor para renovar seu plano!', 'error')
        else:
            flash('Usuário ou senha incorretos.', 'error')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'

    if datetime.now() > datetime.strptime(users[g.user_id]['expiration'], '%Y-%m-%d'):
        flash('Sua sessão expirou. Faça login novamente.', 'error')
        resp = redirect('/')
        resp.set_cookie('auth_token', '', expires=0)
        return resp

    if request.method == 'POST':
        action = request.form.get('action')
        user = request.form.get('user')
        module = request.form.get('module')

        if action == 'view_modules' and user in users:
            user_modules = users[user].get('modules', {})
            role = users[user].get('role', 'user_semanal')
            max_requests = {'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(role, 30)
            if is_admin:
                return jsonify({"user": user, "modules": user_modules, "maxRequests": "Unlimited for admin"})
            return jsonify({"user": user, "modules": {module: user_modules.get(module, 0)}, "maxRequests": max_requests})

    content = render_template('dashboard.html', admin=is_admin, notifications=notifications, users=users, module_status=module_status, token=session.get('token'), module_uuids=session.get('module_uuids', {}))
    if 'user_key' in session:
        return make_response(content)
    return jsonify({"error": "Session key missing"}), 403

@app.route('/i/settings/admin', methods=['GET', 'POST'])
def admin_panel():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    user_id = g.user_id

    if users.get(user_id, {}).get('role') != 'admin':
        return jsonify({"error": "Access denied"}), 403

    user_agent = request.headers.get('User-Agent', '').lower()
    if 'bot' in user_agent or 'spider' in user_agent:
        return jsonify({"error": "Access denied"}), 403

    if request.method == 'POST':
        action = request.form.get('action')
        user_input = request.form.get('user')
        password = request.form.get('password', '')
        expiration = request.form.get('expiration', '')
        message = request.form.get('message', '')
        role = request.form.get('role', 'user_semanal')
        module = request.form.get('module', '')
        status = request.form.get('status', '')

        if action == "add_user" and user_input and password and expiration:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                users[user_input] = {
                    'password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'modules': {m: 0 for m in ['cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv', 'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5', 'teldual', 'likeff']},
                    'devices': []
                }
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário adicionado com sucesso!', 'category': 'success', 'user': user_input, 'password': password, 'token': token, 'expiration': expiration, 'role': role})
            return jsonify({'message': 'Usuário já existe!', 'category': 'error'})

        elif action == "delete_user" and user_input and password:
            if user_input in users and users[user_input]['password'] == password:
                del users[user_input]
                save_data(users, 'users.json')
                if g.user_id == user_input:
                    resp = make_response(jsonify({'message': 'Usuário excluído. Você foi deslogado.', 'category': 'success'}))
                    resp.set_cookie('auth_token', '', expires=0)
                    return resp
                return jsonify({'message': 'Usuário excluído com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Usuário ou senha incorretos.', 'category': 'error'})

        elif action == "view_users":
            return jsonify({'users': users})

        elif action == "send_message" and user_input and message:
            if user_input == 'all':
                for user in users:
                    if user != user_id:
                        notifications.setdefault(user, []).append({'message': message, 'timestamp': datetime.now().isoformat()})
                save_data(notifications, 'notifications.json')
                return jsonify({'message': 'Mensagem enviada para todos os usuários', 'category': 'success'})
            if user_input in users:
                notifications.setdefault(user_input, []).append({'message': message, 'timestamp': datetime.now().isoformat()})
                save_data(notifications, 'notifications.json')
                return jsonify({'message': f'Mensagem enviada para {user_input}', 'category': 'success'})
            return jsonify({'message': 'Usuário não encontrado.', 'category': 'error'})

        elif action == "reset_device" and user_input and password:
            if user_input in users and users[user_input]['password'] == password:
                if 'devices' in users[user_input]:
                    users[user_input]['devices'] = []
                    save_data(users, 'users.json')
                return jsonify({'message': 'Dispositivos resetados com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Usuário ou senha incorretos.', 'category': 'error'})

        elif action == "toggle_module" and module and status:
            if module in module_status:
                module_status[module] = status
                return jsonify({'success': True, 'message': f'Módulo {module} atualizado para {status}'})
            return jsonify({'success': False, 'message': 'Módulo não encontrado'})

    content = render_template('admin.html', users=users, token=session.get('token'), modules_state=module_status)
    if 'user_key' in session:
        return make_response(content)
    return jsonify({"error": "Session key missing"}), 403
    
    

@app.route('/@A30')
def creditos():
    return "@enfurecido - {'0x106a90000'}"

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    resp = make_response(redirect('/'))
    resp.set_cookie('auth_token', '', expires=0)
    resp.set_cookie('byte_cookie', '', expires=0)
    resp.set_cookie('hex_cookie', '', expires=0)
    return resp
    
# Module Routes with dynamic UUID validation
@app.route('/modulos/<module_uuid>/cpf', methods=['GET', 'POST'])
def cpf(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('cpf') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = ""

    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv1"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                # Verifica se a resposta contém campos indicativos de sucesso (ex: 'CPF' presente e não nulo)
                if 'CPF' in data and data['CPF'] and data.get('NOME'):
                    if manage_module_usage(g.user_id, 'cpf'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPF.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)
    
@app.route('/modulos/<module_uuid>/cpf2', methods=['GET', 'POST'])
def cpf2(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('cpf2') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"https://api.bygrower.online/core/?token={chave}&base=cpf1&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpf2'):
                        result = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPF2.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/<module_uuid>/cpfdata', methods=['GET', 'POST'])
def cpfdata(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('cpfdata') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('cpfdata.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=datav1"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('DATA DE NASCIMENTO'):
                    if manage_module_usage(g.user_id, 'cpfdata'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPFDATA.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpfdata.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/<module_uuid>/cpflv', methods=['GET', 'POST'])
def cpflv(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('cpflv') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv2"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('NOME') and data.get('CPF'):
                    if manage_module_usage(g.user_id, 'cpflv'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPFLV.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/<module_uuid>/cpf3', methods=['GET', 'POST'])
def cpf3(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('cpf3') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"https://api.bygrower.online/core/?token={chave}&base=cpf2&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpf3'):
                        result = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPF3.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/<module_uuid>/vacinas', methods=['GET', 'POST'])
def vacinas(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('vacinas') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('vacinas.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=vacina"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'vacinas'):
                        result = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para VACINAS.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o CPF fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('vacinas.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/<module_uuid>/tel', methods=['GET', 'POST'])
def tel(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('tel') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    tel = request.form.get('tel', '')

    if request.method == 'POST':
        if not tel:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, result=result, tel=tel)

                url = f"https://api.bygrower.online/core/?token={chave}&base=telefone1&query={tel}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'tel'):
                        result = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para TEL.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o telefone fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, result=result, tel=tel)

@app.route('/modulos/<module_uuid>/tellv', methods=['GET', 'POST'])
def tellv(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('tellv') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    tel = request.form.get('tel', '')

    if request.method == 'POST':
        if not tel:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, tel=tel)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={tel}&tipo=telv2"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('NOME'):
                    if manage_module_usage(g.user_id, 'tellv'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para TELV.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o telefone fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, tel=tel)

@app.route('/modulos/<module_uuid>/teldual', methods=['GET', 'POST'])
def teldual(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('teldual') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    tel = request.form.get('tel', '')

    if request.method == 'POST':
        if not tel:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('teldual.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel)

                url = f"https://api.bygrower.online/core/?token={chave}&base=telefone2&query={tel}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'teldual'):
                        results = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para TELDUAL.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o telefone fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('teldual.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel)

@app.route('/modulos/<module_uuid>/datanome', methods=['GET', 'POST'])
def datanome(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('datanome') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = request.form.get('nome', '')

    if request.method == 'POST':
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('datanome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=datav2"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if isinstance(data, list) and len(data) > 0:
                    if manage_module_usage(g.user_id, 'datanome'):
                        results = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para DATANOME.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o nome fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('datanome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

@app.route('/modulos/<module_uuid>/placa', methods=['GET', 'POST'])
def placa(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('placa') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))

    result = None
    placa = ""

    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Por favor, insira uma placa válida no formato AAA1234.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications,
                                               result=result, placa=placa)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placanormal"
                logger.info(f"Requisição para API (placa normal): {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                # Verifica se há dados válidos
                if isinstance(data, dict) and data.get('PLACA') == placa:
                    if manage_module_usage(g.user_id, 'placa'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para PLACA.', 'error')
                        result = None
                else:
                    flash('Nenhum veículo encontrado para esta placa.', 'error')

            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')

    return render_template('placa.html', is_admin=is_admin, notifications=user_notifications,
                           result=result, placa=placa)

@app.route('/modulos/<module_uuid>/placaestadual', methods=['GET', 'POST'])
def placaestadual(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('placaestadual') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    placa = ""

    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper()
        if not placa:
            flash('Placa não fornecida.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('placaestadual.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

                url = f"https://api.bygrower.online/core/?token={chave}&base=placaestadual&query={placa}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if 'resultado' in data and isinstance(data['resultado'], list) and len(data['resultado']) > 0 and data['resultado'][0].get('retorno') == 'ok':
                    if manage_module_usage(g.user_id, 'placa'):
                        results = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para PLACA.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para a placa fornecida. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('placaestadual.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

@app.route('/modulos/<module_uuid>/pix', methods=['GET', 'POST'])
def pix(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('pix') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))

    result = None
    chave = ""

    if request.method == 'POST':
        chave = request.form.get('chave', '').strip()
        if not chave or len(chave) < 11:
            flash('Por favor, insira uma chave válida (CPF, telefone ou e-mail).', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('pix.html', is_admin=is_admin, notifications=user_notifications,
                                               result=result, chave=chave)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={chave}&tipo=pix"
                logger.info(f"Requisição para API (pix): {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                # Verifica se a consulta foi bem-sucedida
                if isinstance(data, dict) and data.get('Status') == 'Sucesso' and 'nome' in data:
                    if manage_module_usage(g.user_id, 'pix'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para PIX.', 'error')
                        result = None
                else:
                    flash('Nenhum registro encontrado para esta chave Pix.', 'error')

            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')

    return render_template('pix.html', is_admin=is_admin, notifications=user_notifications,
                           result=result, chave=chave)
    
@app.route('/modulos/<module_uuid>/fotor', methods=['GET', 'POST'])
def fotor(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('fotor') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    documento = ""
    selected_option = ""

    if request.method == 'POST':
        documento = request.form.get('documento', '').strip()
        selected_option = request.form.get('estado', '')
        if not documento:
            flash('Documento não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('fotor.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option)

                if selected_option == "fotoba":
                    url = f"https://api.bygrower.online/core/?token={chave}&base=FotoBA&query={documento}"
                elif selected_option == "fotorj":
                    url = f"https://api.bygrower.online/core/?token={chave}&base=FotoRJ&query={documento}"
                elif selected_option == "fotomg":
                    url = f"http://82.29.58.211:2000/mg_cpf_foto/{documento}"
                else:
                    url = f"https://api.bygrower.online/core/?token={chave}&base=FotoSP&query={documento}"

                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if selected_option == "fotomg" and data and "foto_base64" in data:
                    results = {
                        "CPF": data.get("CPF", ""),
                        "Nome": data.get("Nome", ""),
                        "Nome da Mãe": data.get("Nome da Mãe", ""),
                        "Nome do Pai": data.get("Nome do Pai", ""),
                        "Data de Nascimento": data.get("Data de Nascimento", ""),
                        "Categoria CNH Concedida": data.get("Categoria CNH Concedida", ""),
                        "Validade CNH": data.get("Validade CNH", ""),
                        "foto_base64": data.get("foto_base64", "")
                    }
                elif data:
                    results = data['resultado']

                if results and manage_module_usage(g.user_id, 'fotor'):
                    reset_all()
                elif results:
                    flash('Limite de uso atingido para FOTOR.', 'error')
                    results = None
                else:
                    flash(f'Nenhum resultado encontrado para o documento fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('fotor.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option)

@app.route('/modulos/<module_uuid>/nomelv', methods=['GET', 'POST'])
def nomelv(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('nomelv') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = ""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                # Agora aceita lista direta ou dentro de 'resultado'
                if isinstance(data, list) and len(data) > 0:
                    results_list = data
                elif isinstance(data, dict) and 'resultado' in data and isinstance(data['resultado'], list):
                    results_list = data['resultado']
                else:
                    flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
                    results_list = []

                if results_list:
                    if manage_module_usage(g.user_id, 'nomelv'):
                        results = results_list
                        reset_all()
                    else:
                        flash('Limite de uso atingido para NOMELV.', 'error')
                else:
                    flash('Nenhum resultado encontrado para o nome fornecido.', 'error')

            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

@app.route('/modulos/<module_uuid>/nome', methods=['GET', 'POST'])
def nome(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('nome') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = ""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}S&tipo=nomev1"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado') and len(data['resultado']) > 0:
                    if manage_module_usage(g.user_id, 'nome'):
                        results = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para NOME.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o nome fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))

@app.route('/modulos/<module_uuid>/ip', methods=['GET', 'POST'])
def ip(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('ip') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    ip_address = ""

    if request.method == 'POST':
        ip_address = request.form.get('ip', '').strip()
        if not ip_address:
            flash('IP não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address, token=token)

                url = f"https://ipwho.is/{ip_address}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

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
                        reset_all()
                    else:
                        flash('Limite de uso atingido para IP.', 'error')
                else:
                    flash(f'IP não encontrado ou inválido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address, token=session.get('token'))

@app.route('/modulos/<module_uuid>/nome2', methods=['GET', 'POST'])
def nome2(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('nome2') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = ""

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                url = f"https://api.bygrower.online/core/?token={chave}&base=nomeData&query={nome}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado') and 'itens' in data['resultado']:
                    if manage_module_usage(g.user_id, 'nome2'):
                        results = data['resultado']['itens']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para NOME2.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o nome fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))

@app.route('/modulos/<module_uuid>/likeff', methods=['GET', 'POST'])
def likeff(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('likeff') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    # Verificar se o usuário está autenticado
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    # Carregar dados do usuário e notificações
    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None

    if request.method == 'POST':
        # Obter parâmetros
        uid = request.form.get('uid', '').strip()
        server_name = 'br'  # Fixado como "br" conforme solicitado
        
        if not uid:
            flash('UID não fornecido.', 'error')
        else:
            try:
                # Verificar token para não-admin
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('likeff.html', is_admin=is_admin, 
                                            notifications=user_notifications, 
                                            result=result, uid=uid)

                # URLs das APIs
                token_url = "http://teamxcutehack.serv00.net/like/token_ind.json"
                ffinfo_url = f"https://lk-team-ffinfo-five.vercel.app/ffinfo?id={uid}"
                like_api_url = f"https://likeapiff.thory.in/like?uid={uid}&server_name={server_name}&token_url={requests.utils.quote(token_url)}"

                # Obter dados do ffinfo
                ffinfo_response = requests.get(ffinfo_url, timeout=10)
                ffinfo_response.raise_for_status()
                ffinfo_data = decode_json_with_bom(ffinfo_response.text)

                if not ffinfo_data:
                    flash('Resposta vazia da API ffinfo.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, 
                                        notifications=user_notifications, 
                                        result=result, uid=uid)

                # Verificar chave de likes
                if "account_info" not in ffinfo_data or "├ Likes" not in ffinfo_data["account_info"]:
                    flash('Chave de likes ausente na resposta da API ffinfo.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, 
                                        notifications=user_notifications, 
                                        result=result, uid=uid)

                # Extrair likes antes
                likes_before = int(str(ffinfo_data["account_info"]["├ Likes"]).replace(',', ''))

                # Chamar API de likes
                like_response = requests.get(like_api_url, timeout=10)
                if like_response.status_code != 200:
                    flash(f'Falha na API de likes com código {like_response.status_code}.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, 
                                        notifications=user_notifications, 
                                        result=result, uid=uid)

                like_data = decode_json_with_bom(like_response.text)
                if not like_data or "LikesafterCommand" not in like_data:
                    flash('JSON inválido da API de likes.', 'error')
                    return render_template('likeff.html', is_admin=is_admin, 
                                        notifications=user_notifications, 
                                        result=result, uid=uid)

                # Calcular likes enviados
                likes_after = int(like_data["LikesafterCommand"])
                likes_sended = likes_after - likes_before

                # Montar resposta final
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

                # Gerenciar uso do módulo
                if manage_module_usage(g.user_id, 'likeff'):
                    reset_all()  # Resetar cookies/sessão após uso bem-sucedido
                else:
                    flash('Limite de uso atingido para LIKEFF.', 'error')
                    result = None

            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida.', 'error')

    return render_template('likeff.html', is_admin=is_admin, 
                         notifications=user_notifications, 
                         result=result, uid=uid if 'uid' in locals() else '', 
                         token=session.get('token'))
    
@app.route('/modulos/<module_uuid>/placalv', methods=['GET', 'POST'])
def placalv(module_uuid):
    if 'module_uuids' not in session or session['module_uuids'].get('placalv') != module_uuid:
        flash('Acesso inválido ao módulo.', 'error')
        return redirect('/dashboard')
    
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    placa = request.form.get('placa', '')

    if request.method == 'POST':
        if not placa:
            flash('Placa não fornecida.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placav2"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('PLACA') and data.get('MARCA'):
                    if manage_module_usage(g.user_id, 'placalv'):
                        result = data
                        reset_all()
                    else:
                        flash('Limite de uso atingido para PLACALV.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para a placa fornecida.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

# Fim :D
if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
