from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session
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
    if request.endpoint not in ['login']:
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

    content = render_template('dashboard.html', admin=is_admin, notifications=notifications, users=users, token=session.get('token'))
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

        if action == "add_user" and user_input and password and expiration:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                users[user_input] = {
                    'password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'modules': {m: 0 for m in ['cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv', 'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5', 'visitas', 'teldual']},
                    'devices': []  # Default to limited devices for new users
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

    content = render_template('admin.html', users=users, token=session.get('token'))
    if 'user_key' in session:
        return make_response(content)
    return jsonify({"error": "Session key missing"}), 403



@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    resp = make_response(redirect('/'))
    resp.set_cookie('auth_token', '', expires=0)
    resp.set_cookie('byte_cookie', '', expires=0)
    resp.set_cookie('hex_cookie', '', expires=0)
    return resp
    
# Module Routes (implement each with manage_module_usage)
@app.route('/modulos/cpf', methods=['GET', 'POST'])
def cpf():
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

                url = f"https://api.bygrower.online/core/?token=lenda&base=cpf&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado', {}).get('status') in ['OK', 'success']:
                    if manage_module_usage(g.user_id, 'cpf'):
                        result = data['resultado']
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

@app.route('/modulos/cpf2', methods=['GET', 'POST'])
def cpf2():
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

                url = f"https://api.bygrower.online/core/?token=lenda&base=cpf1&query={cpf}"
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

@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
def cpfdata():
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
                        return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"https://api.bygrower.online/core/?token=lenda&base=cpfDatasus&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpfdata'):
                        result = data['resultado']
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

        if result:
            result = {
                'nome': result.get('nome', 'SEM INFORMAÇÃO'),
                'cpf': result.get('cpf', 'SEM INFORMAÇÃO'),
                'sexo': result.get('sexo', 'SEM INFORMAÇÃO'),
                'dataNascimento': {
                    'nascimento': result.get('dataNascimento', {}).get('nascimento', 'SEM INFORMAÇÃO'),
                    'idade': result.get('dataNascimento', {}).get('idade', 'SEM INFORMAÇÃO'),
                    'signo': result.get('dataNascimento', {}).get('signo', 'SEM INFORMAÇÃO')
                },
                'nomeMae': result.get('nomeMae', 'SEM INFORMAÇÃO').strip() or 'SEM INFORMAÇÃO',
                'nomePai': result.get('nomePai', 'SEM INFORMAÇÃO').strip() or 'SEM INFORMAÇÃO',
                'telefone': [
                    {
                        'ddi': phone.get('ddi', 'SEM INFORMAÇÃO'),
                        'ddd': phone.get('ddd', 'SEM INFORMAÇÃO'),
                        'numero': phone.get('numero', 'SEM INFORMAÇÃO')
                    }
                    for phone in result.get('telefone', [])
                ] if result.get('telefone') else [{'ddi': 'SEM INFORMAÇÃO', 'ddd': 'SEM INFORMAÇÃO', 'numero': 'SEM INFORMAÇÃO'}],
                'nacionalidade': {
                    'municipioNascimento': result.get('nacionalidade', {}).get('municipioNascimento', 'SEM INFORMAÇÃO'),
                    'paisNascimento': result.get('nacionalidade', {}).get('paisNascimento', 'SEM INFORMAÇÃO')
                },
                'enderecos': result.get('enderecos', []),
                'cnsDefinitivo': result.get('cnsDefinitivo', 'SEM INFORMAÇÃO')
            }

    return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/cpf3', methods=['GET', 'POST'])
def cpf3():
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

                url = f"https://api.bygrower.online/core/?token=lenda&base=cpfSipni&query={cpf}"
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
                    flash(f'Nenhum resultado encontrado para o CPF fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/cpflv', methods=['GET', 'POST'])
def cpflv():
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
                        return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                url = f"https://api.bygrower.online/core/?token=lenda&base=cpfLv&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if (data.get('resultado') and 
                    data['resultado'].get('status') == 'success' and 
                    'data' in data['resultado'] and 
                    'pessoa' in data['resultado']['data'] and 
                    'identificacao' in data['resultado']['data']['pessoa'] and 
                    'cpf' in data['resultado']['data']['pessoa']['identificacao']):
                    if manage_module_usage(g.user_id, 'cpflv'):
                        result = data['resultado']
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

    return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=session.get('token'))

@app.route('/modulos/vacinas', methods=['GET', 'POST'])
def cpf5():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
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
                        return render_template('cpf5.html', is_admin=is_admin, notifications=user_notifications, results=results, cpf=cpf)

                url = f"https://api.bygrower.online/core/?token=lenda&base=vacinas&query={cpf}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpf5'):
                        results = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para CPF5.', 'error')
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

    return render_template('cpf5.html', is_admin=is_admin, notifications=user_notifications, results=results, cpf=cpf, token=session.get('token'))

@app.route('/modulos/datanome', methods=['GET', 'POST'])
def datanome():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    nome = request.form.get('nome', '')
    datanasc = request.form.get('datanasc', '')
    result = []

    if request.method == 'POST':
        if not nome or not datanasc:
            flash('Nome e data de nascimento são obrigatórios.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token=lenda&base=nome&query={nome}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado') and len(data['resultado']) > 0:
                    for item in data['resultado']:
                        if 'nascimento' in item:
                            api_date = datetime.strptime(item['nascimento'].strip(), '%d/%m/%Y')
                            user_date = datetime.strptime(datanasc, '%Y-%m-%d')
                            if api_date == user_date:
                                result.append(item)
                    
                    if result and manage_module_usage(g.user_id, 'datanome'):
                        reset_all()
                    elif not result:
                        flash(f'Nenhum resultado encontrado para o nome e data fornecidos. Resposta: {data}', 'error')
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
            except ValueError:
                flash('Formato de data inválido.', 'error')

    return render_template('datanome.html', is_admin=is_admin, notifications=user_notifications, result=result, nome=nome, datanasc=datanasc, token=session.get('token'))

@app.route('/modulos/placalv', methods=['GET', 'POST'])
def placalv():
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
        placa = request.form.get('placa', '').strip()
        if not placa:
            flash('Placa não fornecida.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

                url = f"https://api.bygrower.online/core/?token=lenda&base=placaLv&query={placa}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'placalv'):
                        result = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para PLACALV.', 'error')
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

    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

@app.route('/modulos/telLv', methods=['GET', 'POST'])
def tellv():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    telefone = ""

    if request.method == 'POST':
        telefone = request.form.get('telefone', '').strip()
        if not telefone:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, telefone=telefone, token=token)

                url = f"https://api.bygrower.online/core/?token=lenda&base=telefoneLv&query={telefone}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if (data.get('resultado') and 
                    data['resultado'].get('status') == "success" and 
                    'data' in data['resultado'] and 
                    isinstance(data['resultado']['data'], list) and 
                    any('cpf' in item.get('identificacao', {}) for item in data['resultado']['data'])):
                    if manage_module_usage(g.user_id, 'tellv'):
                        result = data['resultado']['data'][0]
                        reset_all()
                    else:
                        flash('Limite de uso atingido para TELLV.', 'error')
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

    return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, telefone=telefone, token=session.get('token'))

@app.route('/modulos/teldual', methods=['GET', 'POST'])
def teldual():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    telefone = ""

    if request.method == 'POST':
        telefone = request.form.get('telefone', '').strip()
        if not telefone:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('teldual.html', is_admin=is_admin, notifications=user_notifications, results=results, telefone=telefone, token=token)

                url = f"https://api.bygrower.online/core/?token=lenda&base=teldual&query={telefone}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if 'resultado' in data and data['resultado'] and any('cpf' in item for item in data['resultado']):
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

    return render_template('teldual.html', is_admin=is_admin, notifications=user_notifications, results=results, telefone=telefone, token=session.get('token'))

@app.route('/modulos/tel', methods=['GET', 'POST'])
def tel():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    tel = ""

    if request.method == 'POST':
        tel = request.form.get('tel', '').strip()
        if not tel:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                if not is_admin:
                    token = request.form.get('token', '')
                    if not token or token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não fornecido.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel, token=token)

                url = f"https://api.bygrower.online/core/?token=lenda&base=telefone&query={tel}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if 'resultado' in data and 'cpf' in data['resultado']:
                    if manage_module_usage(g.user_id, 'tel'):
                        results = data['resultado']['msg']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para TEL.', 'error')
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

    return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel, token=session.get('token'))

@app.route('/modulos/placa', methods=['GET', 'POST'])
def placa():
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
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

                url = f"https://api.bygrower.online/core/?token=lenda&base=placa&query={placa}"
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
                    flash(f'Nenhum resultado encontrado para a placa fornecida.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

@app.route('/modulos/placaestadual', methods=['GET', 'POST'])
def placaestadual():
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

                url = f"https://api.bygrower.online/core/?token=lenda&base=placaestadual&query={placa}"
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

@app.route('/modulos/fotor', methods=['GET', 'POST'])
def fotor():
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
                    url = f"https://api.bygrower.online/core/?token=lenda&base=FotoBA&query={documento}"
                elif selected_option == "fotorj":
                    url = f"https://api.bygrower.online/core/?token=lenda&base=FotoRJ&query={documento}"
                elif selected_option == "fotomg":
                    url = f"http://82.29.58.211:2000/mg_cpf_foto/{documento}"
                else:
                    url = f"https://api.bygrower.online/core/?token=lenda&base=FotoSP&query={documento}"

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

@app.route('/modulos/nomelv', methods=['GET', 'POST'])
def nomelv():
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
                        return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                url = f"https://api.bygrower.online/core/?token=lenda&base=nome&query={nome}"
                logger.info(f"Requisição para API: {url}")
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = decode_json_with_bom(response.text)

                if data.get('resultado') and len(data['resultado']) > 0:
                    if manage_module_usage(g.user_id, 'nomelv'):
                        results = data['resultado']
                        reset_all()
                    else:
                        flash('Limite de uso atingido para NOMELV.', 'error')
                else:
                    flash(f'Nenhum resultado encontrado para o nome fornecido. Resposta: {data}', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')

    return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))

@app.route('/modulos/nome', methods=['GET', 'POST'])
def nome():
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

                url = f"https://api.bygrower.online/core/?token=lenda&base=nome&query={nome}"
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

@app.route('/modulos/ip', methods=['GET', 'POST'])
def ip():
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

@app.route('/modulos/nome2', methods=['GET', 'POST'])
def nome2():
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=nomeData&query={nome}"
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
# Fim :D
if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
