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

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
colorama.init()

# Ensure JSON files exist
# Função para garantir que arquivos JSON existam
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

# Gerenciamento de Tokens
def generate_token(user_id):
    users = load_data('users.json')
    exp_time = timedelta(days=3650) if users.get(user_id, {}).get('role') == 'admin' else timedelta(hours=1)
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + exp_time}
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return None

# Gerenciamento de Logs
def log_access(endpoint, ip, message=''):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[ INFO ]{Style.RESET_ALL} {ip} - {now} acessou {endpoint}. {message}")

# Notificações
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

# Gestão de uso dos módulos
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})

    if user.get('role') == 'admin':
        return True  # Admins têm acesso ilimitado

    if 'modules' not in user:
        user['modules'] = {m: 0 for m in [
            'cpf', 'cpf2', 'cpf3', 'cpfdata', 'cpflv', 'datanome', 'placalv', 'tellv',
            'placa', 'tel', 'ip', 'fotor', 'nome', 'nome2', 'nomelv', 'cpf5'
        ]}

    if increment:
        user['modules'][module] += 1

    today = datetime.now().date()
    if 'last_reset' not in user or user['last_reset'] != today.isoformat():
        user['last_reset'] = today.isoformat()
        for module_key in user['modules']:
            user['modules'][module_key] = 0

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
def check_user_existence():
    token = request.cookies.get('auth_token')
    if request.endpoint not in ['login', 'planos', 'api_cpf', 'api', 'static']:
        if not token:
            log_access(request.endpoint, request.remote_addr, "Usuário não autenticado.")
            return redirect('/')

        user_id = decode_token(token)
        if user_id in [None, "expired"]:
            flash('Sua sessão expirou. Faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        users = load_data('users.json')
        if user_id not in users:
            flash('Sessão inválida. Faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        g.user_id = user_id
    log_access(request.endpoint, request.remote_addr)

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

                if 'devices' in users[user]:
                    if isinstance(users[user]['devices'], list) and len(users[user]['devices']) > 0:
                        if user_agent not in users[user]['devices']:
                            flash('Dispositivo não autorizado. Login recusado.', 'error')
                            return render_template('login.html')

                    if user_agent not in users[user].get('devices', []):
                        users[user].setdefault('devices', []).append(user_agent)
                        save_data(users, 'users.json')

                return resp
            else:
                flash('Usuário expirado.', 'error')
        else:
            flash('Usuário ou senha incorretos.', 'error')
    return render_template('login.html')


@app.route('/planos', methods=['GET'])
def planos():
    return render_template('planos.html')
    
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
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

    return render_template('dashboard.html', admin=is_admin, notifications=notifications, users=users, token=session.get('token'))
    
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    users = load_data('users.json')
    notifications = load_data('notifications.json')

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
        role = request.form.get('role', 'user_semanal')  # Default to 'user_semanal'

        if action == "add_user" and user_input and password and expiration:
            if user_input not in users:
                token = f"{user_input}-KEY{secrets.token_hex(13)}.center"
                new_user = {
                    'password': password,
                    'token': token,
                    'expiration': expiration,
                    'role': role,
                    'modules': {
                        'cpf': 0,
                        'cpf2': 0,
                        'cpf3': 0,
                        'cpfdata': 0,
                        'cpflv': 0,
                        'datanome': 0,
                        'placalv': 0,
                        'tellv': 0,
                        'placa': 0,
                        'tel': 0,
                        'ip': 0,
                        'fotor': 0,
                        'nome': 0,
                        'nome2': 0
                    }
                }

                if role != 'admin':
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

    return render_template('admin.html', users=users, token=session.get('token'))

@app.route('/logout')
def logout():
    session.pop('token', None)  # Remove token from session
    resp = make_response(redirect('/'))
    resp.set_cookie('auth_token', '', expires=0)
    resp.set_cookie('user-agent', '', expires=0)
    resp.set_cookie('connect.sid', '', expires=0)
    return resp

# Module Routes (implement each with manage_module_usage)
@app.route('/modulos/cpf', methods=['GET', 'POST'])
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
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpf&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado', {}).get('status') == 'OK':
                # Increment module usage on success
                if manage_module_usage(g.user_id, 'cpf'):
                    result = data['resultado']
                else:
                    flash('Limite de uso atingido para CPF.', 'error')
            else:
                flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/cpf2', methods=['GET', 'POST'])
def cpf2():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

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

                if not cpf or (not is_admin and not token):
                    flash('CPF ou Token não fornecido.', 'error')
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

                users = load_data('users.json')
                if not is_admin and token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpf1&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            app.logger.info(f"API response status: {response.status_code}")
            try:
                result = response.json()
                app.logger.info(f"API result: {json.dumps(result, indent=2)}")
                if result.get('resultado'):
                    # Increment module usage on success
                    if manage_module_usage(g.user_id, 'cpf2'):
                        result = result['resultado']
                    else:
                        flash('Limite de uso atingido para CPF2.', 'error')
                        result = None
                else:
                    flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
                    result = None
            except json.JSONDecodeError as e:
                app.logger.error(f"JSON Decoding error: {str(e)}. Response content: {response.text}")
                flash('Resposta da API inválida.', 'error')
        except requests.RequestException as e:
            app.logger.error(f"Request failed for CPF: {str(e)}")
            flash('Erro ao conectar com o servidor da API.', 'error')

    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
def cpfdata():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not is_admin:
            token = request.form.get('token', '')
            if not token or token != users.get(g.user_id, {}).get('token'):
                flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

        if not cpf:
            flash('CPF não fornecido.', 'error')
            return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

        try:
            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpfDatasus&query={cpf}"
            response = requests.get(url, verify=False)  
            response.raise_for_status()  
            data = response.json()

            if data.get('resultado'):
                # Increment module usage on success
                if manage_module_usage(g.user_id, 'cpfdata'):
                    result = data['resultado']
                else:
                    flash('Limite de uso atingido para CPFDATA.', 'error')
            else:
                flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
        except requests.RequestException as e:
            flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida. Erro ao decodificar JSON.', 'error')
        except KeyError:
            flash('Resposta da API não contém a chave esperada.', 'error')

    # Prepare data for rendering in the template
    if result:
        formatted_result = {
            'nome': result.get('nome', 'SEM INFORMAÇÃO'),
            'cpf': result.get('cpf', 'SEM INFORMAÇÃO'),
            'sexo': result.get('sexo', 'SEM INFORMAÇÃO'),
            'dataNascimento': {
                'nascimento': result['dataNascimento'].get('nascimento', 'SEM INFORMAÇÃO'),
                'idade': result['dataNascimento'].get('idade', 'SEM INFORMAÇÃO'),
                'signo': result['dataNascimento'].get('signo', 'SEM INFORMAÇÃO')
            },
            'nomeMae': result.get('nomeMae', 'SEM INFORMAÇÃO').strip() or 'SEM INFORMAÇÃO',
            'nomePai': result.get('nomePai', 'SEM INFORMAÇÃO').strip() or 'SEM INFORMAÇÃO',
            'telefone': [
                {
                    'ddi': phone['ddi'],
                    'ddd': phone['ddd'],
                    'numero': phone['numero']
                }
                for phone in result.get('telefone', [])
            ] if result.get('telefone') else [{'ddi': 'SEM INFORMAÇÃO', 'ddd': 'SEM INFORMAÇÃO', 'numero': 'SEM INFORMAÇÃO'}],
            'nacionalidade': {
                'municipioNascimento': result['nacionalidade'].get('municipioNascimento', 'SEM INFORMAÇÃO'),
                'paisNascimento': result['nacionalidade'].get('paisNascimento', 'SEM INFORMAÇÃO')
            },
            'enderecos': result.get('enderecos', []),
            'cnsDefinitivo': result.get('cnsDefinitivo', 'SEM INFORMAÇÃO')
        }
    else:
        formatted_result = None

    return render_template('cpf4.html', is_admin=is_admin, notifications=user_notifications, result=formatted_result, cpf=cpf)
    
@app.route('/modulos/cpf3', methods=['GET', 'POST'])
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
            return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

    if not cpf:
        flash('CPF não fornecido.', 'error')
        return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

    try:
        # API Call for CPF lookup
        url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpfSipni&query={cpf}"
        response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
        response.raise_for_status()  # Raises HTTPError for bad responses
        data = response.json()

        if data.get('resultado'):
            # Increment module usage on success
            if manage_module_usage(g.user_id, 'cpf3'):
                result = data['resultado']
            else:
                flash('Limite de uso atingido para CPF3.', 'error')
        else:
            flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
    except requests.RequestException:
        flash('Erro ao conectar com o servidor da API.', 'error')
    except json.JSONDecodeError:
        flash('Resposta da API inválida.', 'error')

    return render_template('cpf3.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=session.get('token'))

@app.route('/modulos/cpflv', methods=['GET', 'POST'])
def cpflv():
    if 'user_id' not in g:
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
                    return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpfLv&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado'):
                if manage_module_usage(g.user_id, 'cpflv'):
                    result = data['resultado']
                else:
                    flash('Limite de uso atingido para CPFLV.', 'error')
            else:
                flash('Nenhum resultado encontrado para o CPF fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('cpflv.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=session.get('token'))

@app.route('/modulos/cpf5', methods=['GET', 'POST'])
def cpf5():
    if 'user_id' not in g:  # Ensure user is logged in
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    cpf = request.form.get('cpf', '')

    if request.method == 'POST':
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            token = request.form.get('token', '')
            if not is_admin and (not token or token != users.get(g.user_id, {}).get('token', '')):
                flash('Token inválido ou não corresponde ao usuário logado.', 'error')
            else:
                try:
                    # URL para a API interna
                    url = f'https://consult-center3.onrender.com/api?cpf={cpf}'
                    response = requests.get(url)
                    response.raise_for_status()
                    result = response.text  # Assumindo que o retorno é HTML formatado
                    if manage_module_usage(g.user_id, 'cpf5'):
                        result = response.text
                    else:
                        flash('Limite de uso atingido para CPF5.', 'error')
                        result = None
                except requests.RequestException as e:
                    flash(f'Erro ao conectar com a API.', 'error')

    return render_template('cpf5.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf)

    
@app.route('/modulos/datanome', methods=['GET', 'POST'])
def datanome():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    nome = request.form.get('nome', '')
    datanasc = request.form.get('datanasc', '')
    result = []

    if request.method == 'POST':
        if not nome or not datanasc:
            flash('Nome e data de nascimento são obrigatórios.', 'error')
        else:
            try:
                # API Call for name lookup
                url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=nome&query={nome}"
                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado') and len(data['resultado']) > 0:
                    # Filter results by birth date
                    for item in data['resultado']:
                        if 'nascimento' in item:
                            # Convert the birth date string to a datetime object for comparison
                            api_date = datetime.strptime(item['nascimento'].strip(), '%d/%m/%Y')
                            user_date = datetime.strptime(datanasc, '%Y-%m-%d')  # Date from form is in ISO format
                            if api_date == user_date:
                                result.append(item)
                    
                    if result:
                        if manage_module_usage(g.user_id, 'datanome'):
                            pass  # Usage has been incremented
                        else:
                            flash('Limite de uso atingido para DATANOME.', 'error')
                            result = []
                    else:
                        flash('Nenhum resultado encontrado para o nome e data de nascimento fornecidos.', 'error')
                else:
                    flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
            except requests.RequestException:
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida.', 'error')
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
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    placa = ""

    if request.method == 'POST':
        try:
            placa = request.form.get('placa', '')
            if not is_admin:
                token = request.form.get('token')

                if not placa or not token:
                    flash('PLACA ou Token não fornecido.', 'error')
                    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

            # API Call for plate lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=placaLv&query={placa}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado'):
                if manage_module_usage(g.user_id, 'placalv'):
                    result = data['resultado']
                else:
                    flash('Limite de uso atingido para PLACALV.', 'error')
            else:
                flash('Nenhum resultado encontrado para a PLACA fornecida.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa)

@app.route('/modulos/telLv', methods=['GET', 'POST'])
def tellv():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    result = None
    telefone = ""

    if request.method == 'POST':
        try:
            telefone = request.form.get('telefone', '')
            if not is_admin:
                token = request.form.get('token')

                if not telefone or (not is_admin and not token):
                    flash('TELEFONE ou Token não fornecido.', 'error')
                    return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, telefone=telefone, token=token)

                if not is_admin and token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, telefone=telefone, token=token)

            # API Call for telephone lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=telefoneLv&query={telefone}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()
            
            if 'resultado' in data and data['resultado']:
                if manage_module_usage(g.user_id, 'tellv'):
                    result = data['resultado']
                else:
                    flash('Limite de uso atingido para TELLV.', 'error')
            else:
                # If no result or 'resultado' key does not exist or is empty
                if 'error' in data:
                    flash(data['error'], 'error')  # Assuming the API returns an error message
                else:
                    flash('Nenhum resultado encontrado para o TELEFONE fornecido.', 'error')
                    flash('Formato: sem "+", "55", "-", "(", ou ")", EX: 22998300566', 'error')
                
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('tellv.html', is_admin=is_admin, notifications=user_notifications, result=result, telefone=telefone, token=session.get('token'))

@app.route('/modulos/placa', methods=['GET', 'POST'])
def placa():
    if 'user_id' not in g:
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
                url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=placa&query={placa}"
                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'placa'):
                        results = data['resultado']
                    else:
                        flash('Limite de uso atingido para PLACA.', 'error')
                else:
                    flash('Nenhum resultado encontrado. Verifique o formato da placa.', 'error')
                    flash('Formato: ABC1234', 'error')
            except requests.RequestException:
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida.', 'error')

    return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa)

@app.route('/modulos/tel', methods=['GET', 'POST'])
def tel():
    if 'user_id' not in g:
        flash('Você precisa estar logado para acessar esta página.', 'error')
        return redirect('/')

    users = load_data('users.json')
    is_admin = users.get(g.user_id, {}).get('role') == 'admin'
    notifications = load_notifications()
    user_notifications = len(notifications.get(g.user_id, []))
    results = None
    tel = ""

    if request.method == 'POST':
        tel = request.args.get('tel', '')
        if tel:
            try:
                if not is_admin:
                    token = request.args.get('token')
                    if not token:
                        flash('Token não fornecido.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel, token=token)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel, token=token)

                # API Call for telephone lookup
                url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=telcredlink&query={tel}"
                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado') and 'msg' in data['resultado'] and len(data['resultado']['msg']) > 0:
                    if manage_module_usage(g.user_id, 'tel'):
                        results = data['resultado']['msg']
                    else:
                        flash('Limite de uso atingido para TEL.', 'error')
                else:
                    flash('Nenhum resultado encontrado. Ou, formato inválido.', 'error')
                    flash('Formato: sem "+", "55", "-", "(", ou ")", EX: 22998300566 ', 'error')
            except requests.RequestException:
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida.', 'error')

    return render_template('tel.html', is_admin=is_admin, notifications=user_notifications, results=results, tel=tel, token=session.get('token'))

@app.route('/modulos/fotor', methods=['GET', 'POST'])
def fotor():
    if 'user_id' not in g:
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
                        return render_template('fotor.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option, token=token)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('fotor.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option, token=token)

                # API Call for photo lookup based on the selected state
                token = "a72566c8fac76174cb917c1501d94856"
                if selected_option == "fotoba":
                    url = f"https://apibr.lat/painel/api.php?token={token}&base=fotoba&query={documento}"
                elif selected_option == "fotorj":
                    url = f"https://apibr.lat/painel/api.php?token={token}&base=fotorj&query={documento}"
                else: 
                    url = f"https://apibr.lat/painel/api.php?token={token}&base=fotosp&query={documento}"

                response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
                response.raise_for_status()  # Raises HTTPError for bad responses
                data = response.json()

                if data.get('resultado', {}).get('success'):
                    if manage_module_usage(g.user_id, 'fotor'):
                        results = data['resultado']['data']
                    else:
                        flash('Limite de uso atingido para FOTOR.', 'error')
                else:
                    flash('Nenhum resultado encontrado ou erro na consulta.', 'error')
            except requests.RequestException:
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida.', 'error')

    return render_template('fotor.html', is_admin=is_admin, notifications=user_notifications, results=results, documento=documento, selected_option=selected_option, token=session.get('token'))

@app.route('/modulos/nomelv', methods=['GET', 'POST'])
def nomelv():
    if 'user_id' not in g:
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
                    return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

            # API Call for name lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=nomeLv&query={nome}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado') and len(data['resultado']) > 0:
                if manage_module_usage(g.user_id, 'nomelv'):
                    results = data['resultado']
                else:
                    flash('Limite de uso atingido para NOME.', 'error')
            else:
                flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('nomelv.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))
    
@app.route('/modulos/nome', methods=['GET', 'POST'])
def nome():
    if 'user_id' not in g:
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
                    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

            # API Call for name lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=nome&query={nome}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado') and len(data['resultado']) > 0:
                if manage_module_usage(g.user_id, 'nome'):
                    results = data['resultado']
                else:
                    flash('Limite de uso atingido para NOME.', 'error')
            else:
                flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('nome.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))

@app.route('/modulos/ip', methods=['GET', 'POST'])
def ip():
    if 'user_id' not in g:
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
                        return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address, token=token)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address, token=token)

                # Fetch IP information from ipwho.is
                import requests
                url = f"https://ipwho.is/{ip_address}"
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()

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
                        flash('Limite de uso atingido para IP.', 'error')
                else:
                    flash('IP não encontrado ou inválido.', 'error')
            except requests.RequestException:
                flash('Erro ao conectar com o servidor da API.', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida.', 'error')

    return render_template('ip.html', is_admin=is_admin, notifications=user_notifications, results=results, ip_address=ip_address, token=session.get('token'))

@app.route('/modulos/nome2', methods=['GET', 'POST'])
def nome2():
    if 'user_id' not in g:
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
                    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=token)

            # API Call for name lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=nomeData&query={nome}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()

            if data.get('resultado') and 'itens' in data['resultado']:
                if manage_module_usage(g.user_id, 'nome2'):
                    results = data['resultado']['itens']
                else:
                    flash('Limite de uso atingido para NOME2.', 'error')
            else:
                flash('Nenhum resultado encontrado para o nome fornecido.', 'error')
        except requests.RequestException:
            flash('Erro ao conectar com o servidor da API.', 'error')
        except json.JSONDecodeError:
            flash('Resposta da API inválida.', 'error')

    return render_template('nome2.html', is_admin=is_admin, notifications=user_notifications, results=results, nome=nome, token=session.get('token'))

credentials = 'carlinhos.edu.10@hotmail.com:#Esp210400'
credentials_base64 = credentials.encode().decode('utf-8')  # Encode to base64
url_login = 'https://servicos-cloud.saude.gov.br/pni-bff/v1/autenticacao/tokenAcesso'
url_pesquisa_base = 'https://servicos-cloud.saude.gov.br/pni-bff/v1/cidadao/cpf/'

headers_login = {
    "Host": "servicos-cloud.saude.gov.br",
    "Connection": "keep-alive",
    "Content-Length": "0",
    "sec-ch-ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    "accept": "application/json",
    "X-Authorization": f"Basic {credentials_base64}",
    "sec-ch-ua-mobile": "?0",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "sec-ch-ua-platform": "Windows",
    "Origin": "https://si-pni.saude.gov.br",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://si-pni.saude.gov.br/",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"
}

def processar_cpf(cpf):
    max_retries = 7
    retry_delay = 2

    for _ in range(max_retries):
        # Autenticação
        try:
            response_login = requests.post(url_login, headers=headers_login, verify=False)
            response_login.raise_for_status()
            login_data = response_login.json()
            if 'accessToken' in login_data:
                token_acesso = login_data['accessToken']
                headers_pesquisa = {
                    'Host': "servicos-cloud.saude.gov.br",
                    "Authorization": f"Bearer {token_acesso}",
                    'Accept': "application/json, text/plain, */*",
                    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                    'Origin': "https://si-pni.saude.gov.br",
                    'Sec-Fetch-Site': "same-site",
                    'Sec-Fetch-Mode': "cors",
                    'Sec-Fetch-Dest': "empty",
                    'Referer': "https://si-pni.saude.gov.br/",
                    'Accept-Encoding': "gzip, deflate, br",
                    'Accept-Language': "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"
                }
                
                url_pesquisa = f"{url_pesquisa_base}{cpf}"
                for _ in range(max_retries):
                    try:
                        response_pesquisa = requests.get(url_pesquisa, headers=headers_pesquisa, verify=False)
                        response_pesquisa.raise_for_status()
                        dados_pessoais = response_pesquisa.json()
                        if 'records' in dados_pessoais:
                            return formatar_informacoes(dados_pessoais['records'][0])
                        else:
                            return {"error": "Erro na pesquisa", "details": str(dados_pessoais)}
                    except requests.RequestException:
                        time.sleep(retry_delay)
                return {"error": "Falha na requisição de pesquisa após várias tentativas"}
            else:
                return {"error": "Erro no login", "details": str(login_data)}
        except requests.RequestException:
            time.sleep(retry_delay)
    return {"error": "Falha na requisição de login após várias tentativas"}

def formatar_informacoes(dados_pessoais):
    data_nascimento = dados_pessoais.get('dataNascimento', 'SEM INFORMAÇÃO')
    idade = 'SEM INFORMAÇÃO'
    if data_nascimento != 'SEM INFORMAÇÃO':
        try:
            from datetime import datetime
            data_nascimento_obj = datetime.strptime(data_nascimento, '%Y-%m-%d')  # Ajuste o formato conforme necessário
            hoje = datetime.now()
            idade = f"{hoje.year - data_nascimento_obj.year} anos"
        except ValueError:
            idade = 'DATA INVÁLIDA'

    endereco = dados_pessoais.get('endereco', {})
    logradouro = endereco.get('logradouro', 'SEM INFORMAÇÃO')
    cidade = endereco.get('cidade', 'SEM INFORMAÇÃO')
    bairro = endereco.get('bairro', 'SEM INFORMAÇÃO')
    cep = endereco.get('cep', 'SEM INFORMAÇÃO')

    resultado = f"""
    <div class='profile-info'>
    <p><strong>NOME:</strong> {dados_pessoais.get('nome', 'SEM INFORMAÇÃO')}</p>
    <p><strong>CPF:</strong> {dados_pessoais.get('cpf', 'SEM INFORMAÇÃO')}</p>
    <p><strong>NOME DA MÃE:</strong> {dados_pessoais.get('nomeMae', 'SEM INFORMAÇÃO')}</p>
    <p><strong>NOME DO PAI:</strong> {dados_pessoais.get('nomePai', 'SEM INFORMAÇÃO')}</p>
    <p><strong>CNS:</strong> {dados_pessoais.get('cns', 'SEM INFORMAÇÃO')}</p>
    <p><strong>Nascimento:</strong> {data_nascimento} ({idade})</p>
    <p><strong>EMAIL:</strong> {dados_pessoais.get('email', 'SEM INFORMAÇÃO')}</p>
    <p><strong>Sexo:</strong> {dados_pessoais.get('sexo', 'SEM INFORMAÇÃO')} 
    <strong>Cor:</strong> {dados_pessoais.get('racaCor', 'SEM INFORMAÇÃO')} 
    <strong>Grau de Qualidade:</strong> {dados_pessoais.get('grauQualidade', 'SEM INFORMAÇÃO')}</p>
    <p><strong>Endereço:</strong><br>
    Logradouro: {logradouro}<br>
    Cidade: {cidade}<br>
    Bairro: {bairro}<br>
    CEP: {cep}<br>
    Número: ( manutenção )</p>
    <p><strong>DADOS USADOS:</strong><br>
    CPF: {dados_pessoais.get('cpf', 'SEM INFORMAÇÃO')}<br>
    </div>
    """
    return resultado

@app.route('/api', methods=['GET'])
def api_cpf():
    cpf = request.args.get('cpf')
    if not cpf:
        return jsonify({"error": "Por favor, forneça o CPF na URL como ?cpf=seu_cpf"}), 400

    resultado = processar_cpf(cpf)
    if isinstance(resultado, dict) and 'error' in resultado:
        return jsonify(resultado), 400
    else:
        return resultado, 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
