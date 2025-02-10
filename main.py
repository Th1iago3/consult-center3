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

@app.route('/dashboard')
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

@app.route('/cpf', methods=['POST'])
def cpf():
    if not manage_module_usage(g.user_id, 'cpf'):
        return jsonify({"message": "Limite de uso atingido para CPF."}), 403
    # CPF module logic here
    return jsonify({"message": "CPF module accessed."})

@app.route('/cpf2', methods=['POST'])
def cpf2():
    if not manage_module_usage(g.user_id, 'cpf2'):
        return jsonify({"message": "Limite de uso atingido para CPF2."}), 403
    # CPF2 module logic here
    return jsonify({"message": "CPF2 module accessed."})

# Add similar routes for each module (cpf3, cpfdata, cpflv, datanome, placalv, tellv, placa, tel, ip, fotor, nome, nome2) with the same structure

if __name__ == '__main__':
    initialize_json('users.json')
    initialize_json('notifications.json')
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
