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
import subprocess
import base64
from functools import wraps
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import httpx
import asyncio
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
    # Generate a random byte array
    return os.urandom(32)  # 32 bytes for randomness

def byte_to_hex(byte_data):
    # Convert bytes to hex string
    return base64.b16encode(byte_data).decode('ascii')

def validate_byte_hex(byte_cookie, hex_cookie):
    # Convert hex string back to bytes and compare
    hex_back_to_bytes = base64.b16decode(hex_cookie.encode('ascii'))
    return hex_back_to_bytes == byte_cookie

# Generate custom cookies with the specified format
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
    # Remove o BOM (Byte Order Mark) se presente
    if response_text.startswith('\ufeff'):
        response_text = response_text[1:]
    return json.loads(response_text)

def check_referrer():
    referrer = request.headers.get('Referer', '')
    if not referrer.startswith('https://consult-center3.onrender.com'):
        return False
    return True

def check_user_agent():
    user_agent = request.headers.get('User-Agent', '')
    browser_pattern = re.compile(r'(Chrome|Firefox|Safari|Edge|Opera)', re.IGNORECASE)
    if not browser_pattern.search(user_agent):
        return False
    return True

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

# Token Management with time-based expiration
def generate_token(user_id):
    users = load_data('users.json')
    exp_time = timedelta(days=3650) if users.get(user_id, {}).get('role') == 'admin' else timedelta(minutes=15)  # Now minutes instead of hours
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
        response = requests.get('https://ipinfo.io//json')
        response.raise_for_status()
        ip_info = response.json()
        ip = ip_info.get('ip', '')  # Fallback to 'Unknown' if we can't fetch the IP
    except requests.RequestException as e:
        ip = request.remote_addr
        message += f" [Error fetching real IP: {str(e)}]"

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip} - {now} accessed {endpoint}. {message}")

# Notifications
def load_notifications():
    return load_data('notifications.json')

def save_notifications(notifications):
    save_data(notifications, 'notifications.json')

def send_notification(user_id, message):
    notifications = load_notifications()
    if user_id not in notifications:
        notifications[user_id] = []
    notifications[user_id].append({
        'message': message,
        'timestamp': datetime.now().isoformat()
    })
    save_notifications(notifications)

def get_player_info(uid):
    url = "https://recargajogo.com.br/api/auth/player_id_login"

    payload = {
        "app_id": 100067,
        "login_id": uid
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'Content-Type': "application/json",
        'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
        'sec-ch-ua-mobile': "?1",
        'sec-ch-ua-platform': "\"Android\"",
        'Origin': "https://recargajogo.com.br",
        'Sec-Fetch-Site': "same-origin",
        'Sec-Fetch-Mode': "cors",
        'Sec-Fetch-Dest': "empty",
        'Referer': "https://recargajogo.com.br/",
        'Accept-Language': "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        'Cookie': "region=BR; mspid2=ff74ba563fee80fa46630241bba36111; _ga=GA1.1.901765623.1736342976; cc=true; _ga_9TMTW7BN3E=GS1.1.1736915569.5.1.1736915613.0.0.0; datadome=_i~AmiCsW7aNYrtzvtbkNnorGt2yOc2GUvqqmPMT9oHP_GLPwvNNzi4Tqui2uQ3OouJYpZMCylUUwlDNtdqMMJpbnZb0BRv78weCxoFXzPbO7MvTEKfzlasjdSVZ0r4u; source=mb; session_key=1tesojh0yxrdpa1xwu4128qshbcaoc7l"
    }

    response = requests.post(url, data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        try:
            player_data = response.json()
            region = player_data.get("region", "N/A")
            nickname = player_data.get("nickname", "N/A")
            return region, nickname
        except json.JSONDecodeError:
            print("Erro ao tentar decodificar a resposta como JSON.")
            return "N/A", "N/A"
    else:
        print(f"Erro {response.status_code}: Não foi possível acessar a API do jogador.")
        return "N/A", "N/A"

def check_ban(uid):
    url = "https://ff.garena.com/api/antihack/check_banned"

    params = {
        'lang': "pt",
        'uid': uid
    }

    headers = {
        'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        'Accept': "application/json, text/plain, */*",
        'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
        'x-requested-with': "B6FksShzIgjfrYImLpTsadjS86sddhFH",
        'sec-ch-ua-mobile': "?1",
        'sec-ch-ua-platform': "\"Android\"",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://ff.garena.com/pt/support/",
        'accept-language': "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        'Cookie': "datadome=GcqVS0UG9NX0WEs804KR2pcR2HgGFFBYVfIglt81QFnIPmA0T1X7mMwrYqwbn85oyho8C9yKVYx71HbcuHii5iT8K8NkUnpHlYz0A8dyf5R1A4S_kRiurPWY8_I3Nvcx; _ga_G8QGMJPWWV=GS1.1.1736773737.1.1.1736774124.0.0.0; _ga_Y1QNJ6ZLV6=GS1.1.1736773729.1.1.1736774160.0.0.0; _gid=GA1.2.1234962202.1736915269; _ga_57E30E1PMN=GS1.2.1736915269.2.1.1736915277.0.0.0; _ga_KE3SY7MRSD=GS1.1.1736915307.3.1.1736915366.0.0.0; _ga_RF9R6YT614=GS1.1.1736915308.3.1.1736915366.0.0.0; _ga=GA1.1.1874756915.1736342926"
    }

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("status") == "success":
                return data["data"]["is_banned"] == 1
            else:
                print("Erro: Não foi possível verificar o banimento.")
        except json.JSONDecodeError:
            print("Erro ao tentar decodificar a resposta como JSON.")
    else:
        print(f"Erro {response.status_code}: Não foi possível acessar a API de banimento.")
    return None  # Return None if there was an error in fetching ban status



# Module Usage Management
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})

    if user.get('role') == 'admin':
        return True  # Admins have unlimited access

    if 'modules' not in user:
        user['modules'] = {m: 0 for m in [
            'cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv',
            'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5', 'visitas', 'teldual'
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


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.before_request
def security_check():
    if request.endpoint not in ['login']:
        if not check_referrer():
            log_access(request.endpoint, "Invalid referrer")
            return redirect('/')
            return jsonify({"error": "503"}), 503

        if not check_user_agent():
            log_access(request.endpoint, "Invalid user agent")
            return redirect('/')
            return jsonify({"error": "503"}), 503

        token_cookie = request.cookies.get('auth_token')
        if not token_cookie:
            log_access(request.endpoint, "Unauthenticated user.")
            return redirect('/')

        try:
            encrypted_token = base64.b64decode(token_cookie)
            token = decrypt_with_rsa(encrypted_token)
            user_id = decode_token(token)
        except Exception as e:
            log_access(request.endpoint, f"Error decoding token: {str(e)}")
            flash('Dados de sessão inválidos. Faça login novamente.', 'error')
            return redirect('/')

        if user_id in [None, "expired"]:
            flash('Sua sessão expirou. Faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        users = load_data('users.json')
        if user_id not in users:
            flash('Sessão inválida. Faça login novamente.', 'error')
            return redirect('/')

        # Check for VPN/Proxy
        try:
            response = requests.get('https://api.ipify.org?format=json')
            response.raise_for_status()
            ip_data = response.json()
            ip_address = ip_data['ip']
            vpn_check = requests.get(f'https://ipinfo.io/{ip_address}/json?token=9db60cdc38ce1f')
            vpn_check.raise_for_status()
            vpn_data = vpn_check.json()
            if 'bogon' in vpn_data and vpn_data['bogon']:
                log_access(request.endpoint, "VPN/Proxy detected for IP: " + ip_address)
                return make_response('Acesso não permitido através de VPN ou Proxy.', 403)
        except requests.RequestException as e:
            log_access(request.endpoint, f"Error checking VPN/Proxy: {str(e)}")

        g.user_id = user_id
    log_access(request.endpoint)


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
        
        return resp
    else:
        return jsonify({"error": "User not authenticated"}), 401

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user')
        password = request.form.get('password')
        users = load_data('users.json')
        user_agent = request.headers.get('User-Agent')

        if user in users and users[user]['password'] == password:
            expiration_date = datetime.strptime(users[user]['expiration'], '%Y-%m-%d')
            if datetime.now() < expiration_date:
                token = generate_token(user)
                user_key, public_key = generate_keys()
                session['user_key'] = user_key
                session['public_key'] = public_key
                
                # Generate new byte and hex cookies
                byte_cookie = generate_byte_cookie()
                hex_cookie = byte_to_hex(byte_cookie)

                # Encrypt token before setting in cookie
                encrypted_token = encrypt_with_rsa(token, app.config['RSA_PUBLIC_KEY'])
                
                # Generate custom cookies
                def generate_custom_cookies():
                    import secrets
                    import time
                    import base64
                    
                    cookies = {
                        "JSESSIONID": secrets.token_urlsafe(16),
                        f"TS{secrets.token_hex(4)}": secrets.token_hex(128),
                        f"TS{secrets.token_hex(4)}": secrets.token_hex(128),
                        "_ga": f"GA1.4.{secrets.token_hex(8)}.{int(time.time())}",
                        f"_ga_{secrets.token_hex(4)}": f"GS1.1.{int(time.time())}.4.1.{int(time.time() + 3600)}.0.0.0",
                        f"_gat_gtag_UA_{secrets.token_hex(4)}_1": "1",
                        "_gid": f"GA.{secrets.randbelow(10)}.{secrets.choice('abcdefghijklmnopqrstuvwxyz')}.{secrets.token_hex(4)}",
                        f"TS{secrets.token_hex(4)}": secrets.token_hex(128),
                        "Mabel": secrets.token_hex(8),
                        f"TS{secrets.token_hex(4)}": secrets.token_hex(128),
                        "Omega": base64.b64encode(secrets.token_bytes(32)).decode()
                    }
                    return cookies

                custom_cookies = generate_custom_cookies()
                
                resp = redirect('/dashboard')
                # Set custom cookies
                for key, value in custom_cookies.items():
                    resp.set_cookie(key, value, httponly=True, secure=True, samesite='Strict')
                
                # Set cookies with encrypted values
                resp.set_cookie('auth_token', base64.b64encode(encrypted_token).decode('ascii'), httponly=True, secure=True, samesite='Strict')
                resp.set_cookie('byte_cookie', base64.b64encode(byte_cookie).decode('ascii'), httponly=True, secure=True, samesite='Strict')
                resp.set_cookie('hex_cookie', hex_cookie, httponly=True, secure=True, samesite='Strict')
                
                # Device management logic
                if 'devices' not in users[user]:
                    # If 'devices' key is not found, allow login with unlimited devices
                    save_data(users, 'users.json')  # Save the user data even if devices is not there
                else:
                    if users[user]['devices'] and user_agent != users[user]['devices'][0]:
                        flash('Dispositivo não autorizado. Login recusado.', 'error')
                        return render_template('login.html')
                    else:
                        users[user]['devices'] = [user_agent]  # Only one device is allowed
                        save_data(users, 'users.json')

                return resp
            else:
                flash('Usuário expirado.', 'error')
        else:
            flash('Usuário ou senha incorretos.', 'error')
    return render_template('login.html')
    

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    users = load_data('users.json')
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))

    is_admin = users.get(g.user_id, {}).get('role') == 'admin'

    if g.user_id in users:
        expiration_date = datetime.strptime(users[g.user_id]['expiration'], '%Y-%m-%d')
        if datetime.now() > expiration_date:
            flash('Sua sessão expirou. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

    if request.method == 'POST':
        action = request.form.get('action')
        user = request.form.get('user')
        module = request.form.get('module')

        if action == 'view_modules':
            if user in users:
                user_modules = users[user].get('modules', {})
                role = users[user].get('role', 'user_semanal')
                max_requests = {
                    'user_semanal': 30,
                    'user_mensal': 250,
                    'user_anual': 500
                }.get(role, 30)  # Default to weekly limit if role not recognized

                if is_admin:
                    # For admin, return all module limits
                    return jsonify({
                        "user": user,
                        "modules": user_modules,
                        "maxRequests": "Admin has unlimited access to all modules."
                    }), 200
                else:
                    return jsonify({
                        "user": user,
                        "modules": {module: user_modules.get(module, 0)},
                        "maxRequests": max_requests
                    }), 200
            else:
                return jsonify({"error": "Parâmetros inválidos ou usuário não encontrado."}), 400

    content = render_template('dashboard.html', admin=is_admin, notifications=notifications, users=users, token=session.get('token'))
    if 'user_key' in session:
        encrypted_content = encrypt_with_aes(content, session['user_key'])
        return make_response(content)
    return jsonify({"error": "Session key missing"}), 403

@app.route('/i/settings/admin', methods=['GET', 'POST'])
def admin_panel():
    users = load_data('users.json')
    notifications = load_notifications()

    user_id = g.user_id  # already set by secure_route
    if users.get(user_id, {}).get('role') != 'admin':
        return jsonify({"error": "Access denied"}), 403

    # User-Agent Check
    user_agent = request.headers.get('User-Agent', '')
    if 'bot' in user_agent.lower() or 'spider' in user_agent.lower():
        return jsonify({"error": "Access denied"}), 403

    if request.method == 'POST':
        action = request.form.get('action')
        user_input = request.form.get('user')
        password = request.form.get('password', '')
        expiration = request.form.get('expiration', '')
        message = request.form.get('message', '')
        role = request.form.get('role', 'user_semanal')  # Default to 'user_semanal'

        if action == "add_user" and user_input and password and expiration:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                new_user = {
                    'password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'modules': {m: 0 for m in ['cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv', 'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5', 'visitas', 'teldual']}
                }
                new_user['devices'] = []

                users[user_input] = new_user
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário adicionado com sucesso!', 'category': 'success', 'user': user_input, 'password': password, 'token': token, 'expiration': expiration, 'role': role})
            else:
                return jsonify({'message': 'Usuário já existe. Insira outro usuário!', 'category': 'error'})

        elif action == "delete_user" and user_input and password:
            if user_input in users and users[user_input]['password'] == password:
                del users[user_input]
                save_data(users, 'users.json')
                if g.user_id == user_input:  # Log out if the deleted user is the one logged in
                    resp = make_response(jsonify({'message': 'Usuário e senha excluídos com sucesso! Você foi deslogado.', 'category': 'success'}))
                    resp.set_cookie('auth_token', '', expires=0)
                    return resp
                return jsonify({'message': 'Usuário e senha excluídos com sucesso!', 'category': 'success'})
            else:
                return jsonify({'message': 'Usuário ou senha incorretos.', 'category': 'error'})

        elif action == "view_users":
            return jsonify({'users': users})

        elif action == "send_message" and user_input and message:
            if user_input == 'all':
                for user in users:
                    if user != user_id:  
                        notifications.setdefault(user, []).append({
                            'message': message,
                            'timestamp': datetime.now().isoformat()
                        })
                save_data(notifications, 'notifications.json')
                return jsonify({'message': 'Mensagem enviada para todos os usuários', 'category': 'success'})
            else:
                if user_input in users:
                    notifications.setdefault(user_input, []).append({
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    })
                    save_data(notifications, 'notifications.json')
                    return jsonify({'message': f'Mensagem enviada para {user_input}', 'category': 'success'})
                else:
                    return jsonify({'message': 'Usuário não encontrado.', 'category': 'error'})

        elif action == "reset_device" and user_input and password:
            if user_input in users and users[user_input]['password'] == password:
                if 'devices' in users[user_input]:
                    users[user_input]['devices'] = []
                save_data(users, 'users.json')
                return jsonify({'message': 'Dispositivos do usuário resetados com sucesso!', 'category': 'success'})
            else:
                return jsonify({'message': 'Usuário ou senha incorretos.', 'category': 'error'})

    content = render_template('admin.html', users=users, token=session.get('token'))
    if 'user_key' in session:
        encrypted_content = encrypt_with_aes(content, session['user_key'])
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=cpf&query={cpf}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=cpf1&query={cpf}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=cpfDatasus&query={cpf}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=cpfSipni&query={cpf}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=cpfLv&query={cpf}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=vacinas&query={cpf}"
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
                url = f"https://api.bygrower.online/core/?token=gustta&base=nome&query={nome}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=placaLv&query={placa}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=telefoneLv&query={telefone}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=teldual&query={telefone}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=telefone&query={tel}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=placa&query={placa}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=placaestadual&query={placa}"
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
                    url = f"https://api.bygrower.online/core/?token=gustta&base=FotoBA&query={documento}"
                elif selected_option == "fotorj":
                    url = f"https://api.bygrower.online/core/?token=gustta&base=FotoRJ&query={documento}"
                elif selected_option == "fotomg":
                    url = f"http://82.29.58.211:2000/mg_cpf_foto/{documento}"
                else:
                    url = f"https://api.bygrower.online/core/?token=gustta&base=FotoSP&query={documento}"

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

                url = f"https://api.bygrower.online/core/?token=gustta&base=nome&query={nome}"
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

                url = f"https://api.bygrower.online/core/?token=gustta&base=nome&query={nome}"
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
