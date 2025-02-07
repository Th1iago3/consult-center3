from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response
import json
import os
import secrets
import requests
from datetime import datetime, timedelta
import jwt
import colorama
from colorama import Fore, Style
import re
import subprocess
import base64

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
colorama.init()

# Ensure JSON files exist
def initialize_json(file_path):
    try:
        with open(file_path, 'r') as file:
            json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(file_path, 'w') as file:
            json.dump({}, file)

def load_data(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def save_data(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def generate_token(user_id):
    users = load_data('users.json')
    if users.get(user_id, {}).get('role') == 'admin':
        payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=3650)}  # Admin token lasts 10 years
    else:
        payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(hours=1)}
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return None

def log_access(endpoint, ip, message=''):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip} - {now} acessou {endpoint}. {message}")

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

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

def is_behind_proxy(ip_address):
    # Simple check for proxy headers
    proxy_headers = ['X-Forwarded-For', 'Via', 'Proxy-Authorization', 'Max-Forwards']
    for header in proxy_headers:
        if header in request.headers:
            return True
    # Check for common proxy IP ranges
    proxy_patterns = [
        r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # Private network
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$',  # Private network
        r'^192\.168\.\d{1,3}\.\d{1,3}$',  # Private network
        r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # Loopback
    ]
    for pattern in proxy_patterns:
        if re.match(pattern, ip_address):
            return True
    return False
    
@app.before_request
def check_user_existence():
    token = request.cookies.get('auth_token')
    if request.endpoint not in ['login', 'planos', 'static']:
        if not token:
            log_access(request.endpoint, request.remote_addr, "Usuário não autenticado.")
            return redirect('/')

        user_id = decode_token(token)
        if user_id is None:
            log_access(request.endpoint, request.remote_addr, "Token inválido.")
            flash('Por favor, faça login novamente.', 'error')
            return redirect('/')

        if user_id == "expired":
            log_access(request.endpoint, request.remote_addr, "Token expirado.")
            flash('Sua sessão expirou. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        users = load_data('users.json')
        if user_id not in users:
            log_access(request.endpoint, request.remote_addr, "Usuário não encontrado no JSON, deslogando.")
            flash('Sua sessão expirou ou foi removida. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        g.user_id = user_id
    log_access(request.endpoint, request.remote_addr)

@app.route('/planos')
def planos():
    return render_template('planos.html')

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
                resp = redirect('/dashboard')
                resp.set_cookie('auth_token', token)

                # Check for device restrictions
                if 'devices' in users[user]:
                    if isinstance(users[user]['devices'], list) and len(users[user]['devices']) > 0:
                        # Check if current User-Agent matches any in the list
                        if user_agent not in users[user]['devices']:
                            flash('Dispositivo não autorizado. Login recusado.', 'error')
                            return render_template('login.html')

                    # Add the new User-Agent to the list if it's not there
                    if user_agent not in users[user].get('devices', []):
                        if 'devices' not in users[user]:
                            users[user]['devices'] = []
                        users[user]['devices'].append(user_agent)
                        save_data(users, 'users.json')
                else:
                    # If 'devices' is not present, it means unlimited logins
                    pass

                return resp
            else:
                flash('Usuário expirado.', 'error')
        else:
            flash('Usuário ou senha incorretos.', 'error')
    return render_template('login.html')
    
@app.route('/dashboard')
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
    return render_template('dashboard.html', admin=is_admin, notifications=notifications, users=users)

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    users = load_data('users.json')
    notifications = load_notifications()

    # Check for authentication token
    token = request.cookies.get('auth_token')
    if not token:
        flash('Acesso negado.', 'error')
        return redirect('/dashboard')

    user_id = decode_token(token)
    if user_id is None or user_id == "expired":
        flash('Sessão inválida ou expirada. Por favor, faça login novamente.', 'error')
        resp = redirect('/')
        resp.set_cookie('auth_token', '', expires=0)
        return resp

    # Check if user is admin
    if users.get(user_id, {}).get('role') != 'admin':
        flash('Acesso negado.', 'error')
        return redirect('/dashboard')

    # User-Agent Check
    user_agent = request.headers.get('User-Agent', '')
    if 'bot' in user_agent.lower() or 'spider' in user_agent.lower():
        abort(403)  # Deny access if User-Agent suggests a bot or spider

    if request.method == 'POST':
        action = request.form.get('action')
        user_input = request.form.get('user')
        password = request.form.get('password', '')
        expiration = request.form.get('expiration', '')
        message = request.form.get('message', '')
        role = request.form.get('role', 'user')  # Default to 'user'

        if action == "add_user" and user_input and password and expiration:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                new_user = {
                    'password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role
                }

                # Add 'devices' key only if the role is 'user'
                if role == 'user':
                    new_user['devices'] = []

                users[user_input] = new_user

                # Collect unique notifications
                unique_notifications = set()
                for user, user_notifications in notifications.items():
                    if user != user_id:  
                        for notification in user_notifications:
                            unique_notifications.add(notification['message'])

                # Add unique notifications to the new user
                if user_input not in notifications:
                    notifications[user_input] = []
                for message in unique_notifications:
                    notifications[user_input].append({
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    })

                save_data(users, 'users.json')
                save_notifications(notifications)  # Save updated notifications
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
                        send_notification(user, message)
                return jsonify({'message': 'Mensagem enviada para todos os usuários', 'category': 'success'})
            else:
                if user_input in users:
                    send_notification(user_input, message)
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

    return render_template('admin.html', users=users)

@app.route('/logout')
def logout():
    resp = redirect('/')
    resp.set_cookie('auth_token', '', expires=0)
    return resp

@app.route('/likes')
def likes():
    return jsonify({'message': '! In Maintenance...[404]'})

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))

    if request.method == 'POST':
        try:
            user_id = request.form.get('id')
            token = request.form.get('token')

            if not is_admin:
                if not user_id or not token:
                    flash('ID ou Token não fornecido.', 'error')
                    return render_template('view_profile.html', is_admin=is_admin, notifications=user_notifications)

                if token != users[g.user_id]['token']:
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('view_profile.html', is_admin=is_admin, notifications=user_notifications)

            api_url = f"https://freefireinfo.vercel.app/profile?region=br&uid={user_id}&key=Starexx"
            response = requests.get(api_url)
            response.raise_for_status()  # Raises HTTPError for bad responses
            profile_data = response.json()
            if profile_data.get('status') == 'success':
                return render_template('view_profile.html', profile=profile_data, is_admin=is_admin, notifications=user_notifications)
            else:
                flash('Falha ao obter dados do perfil.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')
    return render_template('view_profile.html', is_admin=is_admin, notifications=user_notifications)

@app.route('/cpf', methods=['GET', 'POST'])
def cpf():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = ""

    if request.method == 'POST':
        try:
            cpf = request.form.get('cpf', '')
            if not is_admin:
                token = request.form.get('token')

                if not cpf or not token:
                    flash('CPF ou Token não fornecido.', 'error')
                    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=cpf&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado', {}).get('status') == 'OK':
                result = data['resultado']
            else:
                flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/cpfdata', methods=['GET', 'POST'])
def cpf4():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = ""

    if request.method == 'POST':
        try:
            cpf = request.form.get('cpf', '')
            if not is_admin:
                token = request.form.get('token')

                if not cpf or not token:
                    flash('CPF ou Token não fornecido.', 'error')
                    return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=cpfDatasus&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado', {}).get('status') == 'OK':
                result = data['resultado']
            else:
                flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)


@app.route('/cpf2', methods=['GET', 'POST'])
def cpf2():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    is_admin = g.user_id == "admin7k"
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = ""

    if request.method == 'POST':
        try:
            cpf = request.form.get('cpf', '')
            if not is_admin:
                token = request.form.get('token')

                if not cpf or (not is_admin and not token):
                    flash('CPF ou Token não fornecido.', 'error')
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                users = load_data('users.json')
                if not is_admin and token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=cpf1&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            app.logger.info(f"API response status: {response.status_code}")
            try:
                result = response.json()
                app.logger.info(f"API result: {json.dumps(result, indent=2)}")
                if result.get('resultado', {}).get('status') != 200:
                    flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
                    result = None
            except json.JSONDecodeError as e:
                app.logger.error(f"JSON Decoding error: {str(e)}. Response content: {response.text}")
                flash('Resposta da API inválida.', 'error')
        except requests.RequestException as e:
            app.logger.error(f"Request failed for CPF: {str(e)}")
            flash('Erro ao conectar com o servidor da API.', 'error')

    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/nome2', methods=['GET', 'POST'])
def nome2():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    is_admin = g.user_id == "admin7k"
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = ""

    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '')
            if not is_admin:
                token = request.form.get('token')

                if not nome or (not is_admin and not token):
                    flash('Nome ou Token não fornecido.', 'error')
                    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

                users = load_data('users.json')
                if not is_admin and token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

            # API Call for name lookup
            url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=nomeData&query={nome}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado') and 'itens' in data['resultado']:
                results = data['resultado']['itens']
            else:
                flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
        except requests.RequestException as e:
            app.logger.error(f"Request failed for nome: {e}")
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            app.logger.error("JSON decoding error in nome API response")
            flash('Resposta da API inválida.', 'error')

    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)


@app.route('/nome', methods=['GET', 'POST'])
def nome():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    nome = ""

    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '')
            if not is_admin:
                token = request.form.get('token')

                if not nome or not token:
                    flash('Nome ou Token não fornecido.', 'error')
                    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

            # API Call for name lookup
            url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=nome&query={nome}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado') and len(data['resultado']) > 0:
                results = data['resultado']
            else:
                flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome)

@app.route('/tel', methods=['GET', 'POST'])
def tel():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    tel = ""

    if request.method == 'GET':
        tel = request.args.get('tel', '')
        if tel:
            try:
                if not is_admin:
                    token = request.args.get('token')
                    if not token:
                        flash('Token não fornecido.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel)

                # API Call for telephone lookup
                url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=telcredlink&query={tel}"
                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado') and 'msg' in data['resultado'] and len(data['resultado']['msg']) > 0:
                    results = data['resultado']['msg']
                else:
                    flash('Nenhum resultado encontrado. Ou, formato inválido.', 'error')
                    flash('Formato: sem "+", "55", "-", "(", ou ")", EX: 22998300566 ', 'error')
            except requests.RequestException as e:
                app.logger.error(f"Request failed for telefone: {e}")
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                app.logger.error("JSON decoding error in telefone API response")
                flash('Resposta da API inválida.', 'error')

    return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel)

@app.route('/placa', methods=['GET', 'POST'])
def placa():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    placa = ""

    if request.method == 'POST':
        placa = request.form.get('placa', '')
        if placa:
            try:
                if not is_admin:
                    token = request.form.get('token')
                    if not token:
                        flash('Token não fornecido.', 'error')
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

                # API Call for plate lookup
                url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=placa&query={placa}"
                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado'):
                    results = data['resultado']
                else:
                    flash('Nenhum resultado encontrado. Verifique o formato da placa.', 'error')
                    flash('Formato: ABC1234', 'error')
            except requests.RequestException as e:
                app.logger.error(f"Request failed for placa: {e}")
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                app.logger.error("JSON decoding error in placa API response")
                flash('Resposta da API inválida.', 'error')

    return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

@app.route('/ip', methods=['GET', 'POST'])
def ip():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    ip_address = ""

    if request.method == 'POST':
        ip_address = request.form.get('ip', '')
        if ip_address:
            try:
                if not is_admin:
                    token = request.form.get('token')
                    if not token:
                        flash('Token não fornecido.', 'error')
                        return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address)

                # Fetch IP information from ipwho.is
                import requests
                url = f"https://ipwho.is/{ip_address}"
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()

                if data.get('success'):
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
                    flash('IP não encontrado ou inválido.', 'error')
            except requests.RequestException as e:
                app.logger.error(f"Request failed for IP: {e}")
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                app.logger.error("JSON decoding error in IP API response")
                flash('Resposta da API inválida.', 'error')

    return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address)

@app.route('/fotor', methods=['GET', 'POST'])
def foto():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    documento = ""
    selected_option = "fotoba"  # Default option

    if request.method == 'POST':
        documento = request.form.get('documento', '')
        selected_option = request.form.get('estado', 'fotoba')
        if documento:
            try:
                if not is_admin:
                    token = request.form.get('token')
                    if not token:
                        flash('Token não fornecido.', 'error')
                        return render_template('foto.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('foto.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option)

                # API Call for photo lookup based on the selected state
                token = "7e0f52ee17f22ffdd1b10afff1490ttj"
                if selected_option == "fotoba":
                    url = f"https://apibr.lat/painel/api.php?token={token}&base=fotoba&query={documento}"
                else:
                    url = f"https://apibr.lat/painel/api.php?token={token}&base=fotorj&query={documento}"

                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado', {}).get('success'):
                    results = data['resultado']['data']
                else:
                    flash('Nenhum resultado encontrado ou erro na consulta.', 'error')
            except requests.RequestException as e:
                app.logger.error(f"Request failed for foto: {e}")
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                app.logger.error("JSON decoding error in foto API response")
                flash('Resposta da API inválida.', 'error')

    return render_template('foto.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option)


@app.route('/cpf3', methods=['GET', 'POST'])
def cpf3():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if not is_admin:
        token = request.form.get('token', '')
        if not token or token != users.get(g.user_id, {}).get('token'):
            flash('Token inválido ou não corresponde ao usuário logado.', 'error')
            return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

    if not cpf:
        flash('CPF não fornecido.', 'error')
        return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

    try:
        # API Call for CPF lookup
        url = f"https://apibr.lat/painel/api.php?token=7e0f52ee17f22ffdd1b10afff1490ttj&base=cpfSipni&query={cpf}"
        response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
        response.raise_for_status()  # Raises HTTPError for bad responses
        data = response.json()

        if data.get('resultado'):
            result = data['resultado']
        else:
            flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
    except requests.RequestException:
        flash('Erro ao conectar com o servidor da API.', 'error')
    except json.JSONDecodeError:
        flash('Resposta da API inválida.', 'error')

    return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)


if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
