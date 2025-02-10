from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session
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

# Function to manage module usage
def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})
    
    if user.get('role') == 'admin':
        return True  # Admins have no limits

    # Initialize module counts if not present
    if 'modules' not in user:
        user['modules'] = {
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
    
    if module in user['modules']:
        if increment:
            user['modules'][module] += 1
        if user['modules'][module] >= 10:
            flash(f'Limite de uso atingido para o módulo {module}.', 'error')
            return False
        
    # Check daily limits based on user role
    today = datetime.now().date()
    if 'last_reset' not in user or user['last_reset'] != today:
        user['last_reset'] = today.isoformat()
        for module_key in user['modules']:
            user['modules'][module_key] = 0
    
    usage_limit = {
        'user_semanal': 10,
        'user_mensal': 250,
        'user_anual': 150
    }.get(user.get('role', 'user_semanal'), 10)  # Default to weekly limit if role not recognized
    
    if user['modules'][module] > usage_limit:
        flash(f'Você excedeu o limite diário de {usage_limit} requisições para o módulo {module}.', 'error')
        return False
    
    users[user_id] = user
    save_data(users, 'users.json')
    return True

@app.before_request
def manage_session():
    token = request.cookies.get('auth_token')
    if request.endpoint not in ['login', 'planos', 'static']:
        if not token:
            flash('Você precisa estar logado para acessar esta página.', 'error')
            return redirect('/')

        user_id = decode_token(token)
        if user_id is None:
            flash('Por favor, faça login novamente.', 'error')
            return redirect('/')

        if user_id == "expired":
            flash('Sua sessão expirou. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        users = load_data('users.json')
        if user_id not in users:
            flash('Sua sessão expirou ou foi removida. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

        g.user_id = user_id
        if 'token' not in session:
            session['token'] = users[user_id]['token']  # Store the user's token in the session if not already there

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
                session['token'] = users[user]['token']  # Store token in session
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('auth_token', token)
                resp.set_cookie('user-agent', user_agent)  # Store user-agent in a cookie
                resp.set_cookie('connect.sid', secrets.token_hex(16))  # Generate and set connect.sid cookie

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

@app.route('/dashboard', methods=['GET')
def dashboard():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    user_notifications = len(notifications.get(g.user_id, []))

    is_admin = users.get(g.user_id, {}).get('role') == 'admin'

    if g.user_id in users:
        expiration_date = datetime.strptime(users[g.user_id]['expiration'], '%Y-%m-%d')
        if datetime.datetime.now() > expiration_date:
            flash('Sua sessão expirou. Por favor, faça login novamente.', 'error')
            resp = redirect('/')
            resp.set_cookie('auth_token', '', expires=0)
            return resp

    if request.method == 'POST':
        action = request.form.get('action')
        user = request.form.get('user')
        token = request.form.get('token')
        module = request.form.get('module')
        module_type = request.form.get('module_type')

        if action == 'view_modules':
            if user in users and token == users[user]['token']:
                user_modules = users[user].get('modules', {})
                role = users[user].get('role', 'user_semanal')
                max_requests = {
                    'user_semanal': 10,
                    'user_mensal': 250,
                    'user_anual': 150
                }.get(role, 10)  # Default to weekly limit if role not recognized

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
                    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

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

    return render_template('cpf.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

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
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=token)

                users = load_data('users.json')
                if not is_admin and token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=session.get('token'))

            # API Call for CPF lookup
            url = f"https://apibr.lat/painel/api.php?token=a72566c8fac76174cb917c1501d94856&base=cpf1&query={cpf}"
            response = requests.get(url, verify=False)  # Note: verify=False to disable SSL verification, use with caution!
            response.raise_for_status()  # Raises HTTPError for bad responses
            app.logger.info(f"API response status: {response.status_code}")
            try:
                result = response.json()
                app.logger.info(f"API result: {json.dumps(result, indent=2)}")
                if result.get('resultado', {}).get('status') == 200:
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

    return render_template('cpf2.html', is_admin=is_admin, notifications=user_notifications, result=result, cpf=cpf, token=session.get('token'))

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

@app.route('/cpflv', methods=['GET', 'POST'])
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

@app.route('/datanome', methods=['GET', 'POST'])
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


@app.route('/placalv', methods=['GET', 'POST'])
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
                    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa, token=token)

                if token != users.get(g.user_id, {}).get('token'):
                    flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa, token=token)

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

    return render_template('placalv.html', is_admin=is_admin, notifications=user_notifications, result=result, placa=placa, token=session.get('token'))

@app.route('/tellv', methods=['GET', 'POST'])
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

@app.route('/placa', methods=['GET', 'POST'])
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
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa, token=token)

                    if token != users.get(g.user_id, {}).get('token'):
                        flash('Token inválido ou não corresponde ao usuário logado.', 'error')
                        return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa, token=token)

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

    return render_template('placa.html', is_admin=is_admin, notifications=user_notifications, results=results, placa=placa, token=session.get('token'))

@app.route('/tel', methods=['GET', 'POST'])
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

    if request.method == 'GET':
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

@app.route('/fotor', methods=['GET', 'POST'])
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

@app.route('/nome', methods=['GET', 'POST'])
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

@app.route('/ip', methods=['GET', 'POST'])
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

@app.route('/nome2', methods=['GET', 'POST'])
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



if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
