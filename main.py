from flask import Flask, jsonify, request, render_template, redirect, flash, g, make_response, session, send_from_directory, url_for, abort
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

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'novidades')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()

# Rate limiting storage
login_attempts = {}

# Module status (can be toggled by admins)
module_status = {
    'cpfdata': 'ON',
    'cpflv': 'OFF',
    'cpf': 'ON',
    'cpf2': 'OFF',
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
    'likeff': 'OFF',
    'mae': 'ON',
    'pai': 'ON',
    'cnpjcompleto': 'ON'
}

chave = "vmb1"  # API key for some external services

# JSON File Management
def initialize_json(file_path, default_data={}):
    try:
        with open(file_path, 'r') as file:
            json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(file_path, 'w') as file:
            json.dump(default_data, file)

def load_data(file_path):
    with open(file_path, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return {}

def save_data(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4, default=str)  # Handle datetime serialization

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

# Module Usage Management
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
    if attempts['count'] > 5:
        return False, "Muitas tentativas de login. Tente novamente em 5 minutos."
    login_attempts[user_id] = attempts
    return True, ""

# Before Request Security Check
@app.before_request
def security_check():
    if request.endpoint not in ['login_or_register', 'creditos', 'preview']:
        if 'user_id' not in session:
            flash('Você precisa estar logado para acessar esta página.', 'error')
            return redirect('/')
        g.user_id = session['user_id']
        users = load_data('users.json')
        user = users.get(g.user_id, {})
        if not user:
            session.clear()
            return redirect('/')
        # Check expiration
        if user['role'] != 'admin' and user['role'] != 'guest':
            expiration_date = datetime.strptime(user['expiration'], '%Y-%m-%d')
            if datetime.now() > expiration_date:
                flash('Sua conta expirou. Contate o suporte.', 'error')
                session.clear()
                return redirect('/')

# Login
@app.route('/', methods=['GET', 'POST'])
def login_or_register():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'login':
            # Lógica de login
            username = request.form.get('user')
            password = request.form.get('password')
            users = load_data('users.json')
            can_login, message = check_login_attempts(username)
            if not can_login:
                flash(message, 'error')
                return render_template('login.html')
            if username in users and users[username]['password'] == password:
                if users[username]['role'] != 'guest':
                    expiration_date = datetime.strptime(users[username]['expiration'], '%Y-%m-%d')
                    if datetime.now() > expiration_date:
                        flash('Conta expirada. Contate o suporte.', 'error')
                        return render_template('login.html')
                session['user_id'] = username
                login_attempts[username] = {'count': 0, 'last_attempt': time.time()}
                return redirect('/dashboard')
            else:
                flash('Usuário ou senha incorretos.', 'error')
                return render_template('login.html')
        elif action == 'register':
            # Lógica de registro
            username = request.form.get('user')
            password = request.form.get('password')
            if not username or not password:
                flash('Usuário e senha são obrigatórios.', 'error')
                return render_template('login.html')
            users = load_data('users.json')
            if username in users:
                flash('Usuário já existe.', 'error')
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
                'password': password,
                'role': 'guest',
                'expiration': '2099-12-31',  # Permanent for guests
                'permissions': {},  # No modules
                'modules': {m: 0 for m in module_status.keys()},
                'read_notifications': [],
                'referred_by': referred_by,
                'affiliate_code': secrets.token_urlsafe(8) if referred_by else None
            }
            save_data(users, 'users.json')
            flash('Registro concluído com sucesso! Faça login.', 'success')
            return redirect('/')
        else:
            flash('Ação inválida.', 'error')
            return render_template('login.html')
    # Para GET, renderiza o template unificado
    return render_template('login.html')
    

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    users = load_data('users.json')
    user = users[g.user_id]
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    is_admin = user['role'] == 'admin'
    is_guest = user['role'] == 'guest'
    affiliate_link = None if is_guest else url_for('login_or_register', aff=user.get('affiliate_code'), _external=True)
    
    if user['role'] != 'guest':
        if datetime.now() > datetime.strptime(user['expiration'], '%Y-%m-%d'):
            flash('Sua sessão expirou. Faça login novamente.', 'error')
            return redirect('/')

    if request.method == 'POST':
        if is_admin:
            action = request.form.get('action')
            target_user = request.form.get('user')
            module = request.form.get('module')

            if action == 'view_modules' and target_user in users:
                user_modules = users[target_user].get('modules', {})
                role = users[target_user].get('role', 'user_semanal')
                max_requests = {'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(role, 30)
                if is_admin:
                    return jsonify({"user": target_user, "modules": user_modules, "maxRequests": "Unlimited for admin"})
                return jsonify({"user": target_user, "modules": {module: user_modules.get(module, 0)}, "maxRequests": max_requests})
        # Handle module usage view or other admin actions
        if is_admin:
            action = request.form.get('action')
            if action == 'view_modules':
                target_user = request.form.get('user')
                if target_user in users:
                    return jsonify(users[target_user].get('modules', {}))

    return render_template('dashboard.html', users=users, admin=is_admin, guest=is_guest, unread_notifications=unread_count, affiliate_link=affiliate_link, notifications=notifications, module_status=module_status)

# Admin Panel
@app.route('/i/settings/admin', methods=['GET', 'POST'])
def admin_panel():
    users = load_data('users.json')
    if users[g.user_id]['role'] != 'admin':
        return jsonify({"error": "Access denied"}), 403
    gifts = load_data('gifts.json')
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_user':
            username = request.form.get('user')
            password = request.form.get('password')
            expiration = request.form.get('expiration')
            role = request.form.get('role', 'user_semanal')
            if username not in users:
                users[username] = {
                    'password': password,
                    'expiration': expiration,
                    'role': role,
                    'permissions': {m: None for m in module_status.keys()} if role != 'guest' else {},
                    'modules': {m: 0 for m in module_status.keys()},
                    'read_notifications': [],
                    'affiliate_code': secrets.token_urlsafe(8) if role != 'guest' else None
                }
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário adicionado com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Usuário já existe!', 'category': 'error'})
        elif action == 'delete_user':
            username = request.form.get('user')
            if username in users and username != g.user_id:
                del users[username]
                save_data(users, 'users.json')
                return jsonify({'message': 'Usuário excluído com sucesso!', 'category': 'success'})
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
        elif action == 'toggle_module':
            module = request.form.get('module')
            status = request.form.get('status')
            if module in module_status:
                module_status[module] = status
                return jsonify({'success': True})
        elif action == 'send_notification':
            message = request.form.get('message')
            notif_id = str(uuid.uuid4())
            notifications = load_data('notifications.json')
            notifications.append({
                'id': notif_id,
                'message': message,
                'timestamp': datetime.now().isoformat()
            })
            save_data(notifications, 'notifications.json')
            return jsonify({'message': 'Notificação enviada para todos!', 'category': 'success'})
    return render_template('admin.html', users=users, gifts=gifts, modules_state=module_status)

# Redeem Gift
@app.route('/redeem', methods=['GET', 'POST'])
def redeem():
    if request.method == 'POST':
        code = request.form.get('code')
        gifts = load_data('gifts.json')
        if code in gifts and gifts[code]['uses_left'] > 0:
            users = load_data('users.json')
            user = users[g.user_id]
            gift = gifts[code]
            exp_date = (datetime.now() + timedelta(days=gift['expiration_days'])).date().isoformat()
            if gift['modules'] == 'all':
                for m in module_status.keys():
                    user['permissions'][m] = exp_date
            else:
                for m in gift['modules']:
                    if m in module_status:
                        user['permissions'][m] = exp_date
            gifts[code]['uses_left'] -= 1
            if gifts[code]['uses_left'] == 0:
                del gifts[code]
            save_data(users, 'users.json')
            save_data(gifts, 'gifts.json')
            flash('Gift resgatado com sucesso!', 'success')
        else:
            flash('Código inválido ou expirado.', 'error')
    return render_template('redeem.html')

# Notifications Page
@app.route('/notifications', methods=['GET', 'POST'])
def notifications_page():
    users = load_data('users.json')
    user = users[g.user_id]
    if user['role'] == 'guest':
        abort(403)
    notifications = load_data('notifications.json')
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
    return render_template('notifications.html', unread=unread, read=read)

# Novidades Page
@app.route('/novidades', methods=['GET'])
def novidades():
    users = load_data('users.json')
    if users[g.user_id]['role'] == 'guest':
        abort(403)
    news = load_data('news.json')
    return render_template('novidades.html', news=news)

# Create Novidade
@app.route('/novidades/new', methods=['GET', 'POST'])
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
                # Salva no mesmo diretório do script
                image_filename = f'{news_id}{ext}'
                image_path_full = os.path.join(os.path.dirname(__file__), image_filename)
                image.save(image_path_full)
                # Caminho relativo para usar no HTML (raiz do site)
                image_path = f'/{image_filename}'

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

    return render_template('new_novidade.html')

# Edit Novidade
@app.route('/novidades/edit/<news_id>', methods=['GET', 'POST'])
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
            ext = os.path.splitext(image.filename)[1]
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{news_id}{ext}')
            image.save(image_path)
            item['image'] = f'/static/novidades/{news_id}{ext}'
        save_data(news, 'news.json')
        flash('Novidade editada com sucesso!', 'success')
        return redirect('/novidades')
    return render_template('edit_novidade.html', item=item)

# Delete Novidade
@app.route('/novidades/delete/<news_id>', methods=['POST'])
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

# Dynamic Module Handler
@app.before_request
def generate_module_uuid():
    if 'module_uuid' not in session:
        session['module_uuid'] = str(uuid.uuid4())

def module_decorator(f):
    @wraps(f)
    def decorated(uuid_str, *args, **kwargs):
        if uuid_str != session.get('module_uuid'):
            abort(403)
        return f(*args, **kwargs)
    return decorated

# Module Routes

@app.route('/modulos/<uuid_str>/mae', methods=['GET', 'POST'])
@module_decorator
def mae():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('NOME não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=mae"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('status') and data.get('response'):
                    valid_results = [r for r in data['response'] if r.get('CPF') and r.get('NOME')]
                    if valid_results:
                        if manage_module_usage(g.user_id, 'mae'):
                            result = valid_results
                        else:
                            flash('Limite de uso atingido para MÃE.', 'error')
                    else:
                        flash('Nenhum resultado válido encontrado.', 'error')
                else:
                    flash('Nenhum resultado encontrado para o nome informado.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')
            except Exception as e:
                flash(f'Erro inesperado: {str(e)}', 'error')
    return render_template('mae.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/<uuid_str>/pai', methods=['GET', 'POST'])
@module_decorator
def pai():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('NOME não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=pai"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('status') and data.get('response'):
                    valid_results = [r for r in data['response'] if r.get('CPF') and r.get('NOME') and r.get('PAI')]
                    if valid_results:
                        if manage_module_usage(g.user_id, 'pai'):
                            result = valid_results
                        else:
                            flash('Limite de uso atingido para PAI.', 'error')
                    else:
                        flash('Nenhum resultado válido encontrado.', 'error')
                else:
                    flash('Nenhum resultado encontrado para o nome do pai informado.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')
            except Exception as e:
                flash(f'Erro inesperado: {str(e)}', 'error')
    return render_template('pai.html', is_admin=is_admin, notifications=unread_count, result=result, nome=nome)

@app.route('/modulos/<uuid_str>/cnpjcompleto', methods=['GET', 'POST'])
@module_decorator
def cnpjcompleto():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cnpj_input = ""
    if request.method == 'POST':
        cnpj_input = request.form.get('cnpj', '').strip()
        if len(cnpj_input) != 14:
            flash('CNPJ inválido. Digite 14 números.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cnpj_input}&tipo=cnpjcompleto"
                response = requests.get(url, verify=False, timeout=15)
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
                    flash('Limite de uso atingido para CNPJ Completo.', 'error')
                    result = None
            except requests.Timeout:
                flash('Tempo de requisição esgotado.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro de conexão: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta inválida da API.', 'error')
            except Exception as e:
                flash(f'Erro inesperado: {str(e)}', 'error')
    return render_template('cnpjcompleto.html', is_admin=is_admin, notifications=unread_count, result=result, cnpj_input=cnpj_input)

@app.route('/modulos/<uuid_str>/cpf', methods=['GET', 'POST'])
@module_decorator
def cpf():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv1"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'CPF' in data and data['CPF'] and data.get('NOME'):
                    if manage_module_usage(g.user_id, 'cpf'):
                        result = data
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
    return render_template('cpf.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/<uuid_str>/cpf2', methods=['GET', 'POST'])
@module_decorator
def cpf2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=cpf1&query={cpf}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado'):
                    if manage_module_usage(g.user_id, 'cpf2'):
                        result = data['resultado']
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
    return render_template('cpf2.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/<uuid_str>/cpfdata', methods=['GET', 'POST'])
@module_decorator
def cpfdata():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpfv3"
                response = requests.get(url, verify=False, timeout=10)
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
    return render_template('cpf4.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/<uuid_str>/cpf3', methods=['GET', 'POST'])
@module_decorator
def cpf3():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=cpffull"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'CPF' in data and data['CPF']:
                    if manage_module_usage(g.user_id, 'cpf3'):
                        result = data
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
            except json.JSONDecodeError as e:
                flash(f'Resposta da API inválida: {response.text if "response" in locals() else str(e)}', 'error')
    return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/<uuid_str>/cpflv', methods=['GET', 'POST'])
@module_decorator
def cpflv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip()
        if not cpf:
            flash('CPF não fornecido.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=cpfLv&query={cpf}"
                response = requests.get(url, verify=False, timeout=10)
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
    return render_template('cpflv.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)

@app.route('/modulos/<uuid_str>/vacinas', methods=['GET', 'POST'])
@module_decorator
def vacinas():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = []
    cpf = ""
    if request.method == 'POST':
        cpf = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            flash('Por favor, insira um CPF válido com 11 dígitos.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={cpf}&tipo=vacina"
                response = requests.get(url, verify=False, timeout=10)
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
                        flash('Limite de uso atingido para VACINAS.', 'error')
                        results = []
                else:
                    flash('Nenhum registro de vacinação encontrado para este CPF.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')
    return render_template('vacinas.html', is_admin=is_admin, notifications=unread_count, results=results, cpf=cpf)

@app.route('/modulos/<uuid_str>/datanome', methods=['GET', 'POST'])
@module_decorator
def datanome():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = []
    nome = ""
    datanasc = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        datanasc = request.form.get('datanasc', '').strip()
        if not nome or not datanasc:
            flash('Nome e data de nascimento são obrigatórios.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
                response = requests.get(url, verify=False, timeout=10)
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
                    flash('Formato de data inválido. Use o seletor de data.', 'error')
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
                        flash('Limite de uso atingido para DATANOME.', 'error')
                        results = []
                else:
                    flash('Nenhum resultado encontrado com essa data de nascimento.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')
            except Exception as e:
                flash(f'Erro inesperado: {str(e)}', 'error')
    return render_template('datanome.html', is_admin=is_admin, notifications=unread_count,
                           results=results, nome=nome, datanasc=datanasc)

@app.route('/modulos/<uuid_str>/placalv', methods=['GET', 'POST'])
@module_decorator
def placalv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or not (len(placa) == 7 and placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Por favor, insira uma placa válida no formato AAA0000.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placacompleta"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('status') and 'response' in data and 'dados' in data['response']:
                    veiculo = data['response']['dados'].get('veiculo', {})
                    if veiculo and veiculo.get('placa'):
                        if manage_module_usage(g.user_id, 'placalv'):
                            result = data['response']['dados']
                        else:
                            flash('Limite de uso atingido para PLACALV.', 'error')
                            result = None
                    else:
                        flash('Nenhum veículo encontrado para esta placa.', 'error')
                else:
                    flash('Nenhum resultado encontrado para a placa informada.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')
    return render_template('placalv.html', is_admin=is_admin, notifications=unread_count,
                           result=result, placa=placa)

@app.route('/modulos/<uuid_str>/telLv', methods=['GET', 'POST'])
@module_decorator
def tellv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    telefone = ""
    if request.method == 'POST':
        telefone = ''.join(c for c in request.form.get('telefone', '').strip() if c.isdigit())
        if not telefone or len(telefone) < 10 or len(telefone) > 11:
            flash('Por favor, insira um telefone válido (10 ou 11 dígitos).', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={telefone}&tipo=telefonev2"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('status') and 'response' in data:
                    response_data = data['response']
                    if response_data.get('CPF') and response_data['CPF'] != 'SEM RESULTADO':
                        if manage_module_usage(g.user_id, 'telLv'):
                            result = response_data
                        else:
                            flash('Limite de uso atingido para TELLV.', 'error')
                            result = None
                    else:
                        flash('Nenhum registro encontrado para este telefone.', 'error')
                else:
                    flash('Nenhum resultado encontrado para o telefone fornecido.', 'error')
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com a API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash('Resposta da API inválida (JSON malformado).', 'error')
    return render_template('tellv.html', is_admin=is_admin, notifications=unread_count,
                           result=result, telefone=telefone)

@app.route('/modulos/<uuid_str>/teldual', methods=['GET', 'POST'])
@module_decorator
def teldual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    telefone = ""
    if request.method == 'POST':
        telefone = request.form.get('telefone', '').strip()
        if not telefone:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=teldual&query={telefone}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and data['resultado'] and any('cpf' in item for item in data['resultado']):
                    if manage_module_usage(g.user_id, 'teldual'):
                        results = data['resultado']
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
    return render_template('teldual.html', is_admin=is_admin, notifications=unread_count, results=results, telefone=telefone)

@app.route('/modulos/<uuid_str>/tel', methods=['GET', 'POST'])
@module_decorator
def tel():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    tel_input = ""
    if request.method == 'POST':
        tel_input = request.form.get('tel', '').strip()
        if not tel_input:
            flash('Telefone não fornecido.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=telefone&query={tel_input}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and 'cpf' in data['resultado']:
                    if manage_module_usage(g.user_id, 'tel'):
                        results = data['resultado']['msg']
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
    return render_template('tel.html', is_admin=is_admin, notifications=unread_count, results=results, tel=tel_input)

@app.route('/modulos/<uuid_str>/placa', methods=['GET', 'POST'])
@module_decorator
def placa():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper().replace(' ', '')
        if not placa or len(placa) != 7 or not (placa[:3].isalpha() and placa[3:].isdigit()):
            flash('Por favor, insira uma placa válida no formato AAA1234.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={placa}&tipo=placanormal"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('PLACA') == placa:
                    if manage_module_usage(g.user_id, 'placa'):
                        result = data
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
    return render_template('placa.html', is_admin=is_admin, notifications=unread_count,
                           result=result, placa=placa)

@app.route('/modulos/<uuid_str>/placaestadual', methods=['GET', 'POST'])
@module_decorator
def placaestadual():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    placa = ""
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper()
        if not placa:
            flash('Placa não fornecida.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=placaestadual&query={placa}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if 'resultado' in data and isinstance(data['resultado'], list) and len(data['resultado']) > 0 and data['resultado'][0].get('retorno') == 'ok':
                    if manage_module_usage(g.user_id, 'placaestadual'):
                        results = data['resultado']
                    else:
                        flash('Limite de uso atingido para PLACAESTADUAL.', 'error')
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
    return render_template('placaestadual.html', is_admin=is_admin, notifications=unread_count, results=results, placa=placa)

@app.route('/modulos/<uuid_str>/pix', methods=['GET', 'POST'])
@module_decorator
def pix():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    chave = ""
    if request.method == 'POST':
        chave = request.form.get('chave', '').strip()
        if not chave or len(chave) < 11:
            flash('Por favor, insira uma chave válida (CPF, telefone ou e-mail).', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={chave}&tipo=pix"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if isinstance(data, dict) and data.get('Status') == 'Sucesso' and 'nome' in data:
                    if manage_module_usage(g.user_id, 'pix'):
                        result = data
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
    return render_template('pix.html', is_admin=is_admin, notifications=unread_count,
                           result=result, chave=chave)

@app.route('/modulos/<uuid_str>/fotor', methods=['GET', 'POST'])
@module_decorator
def fotor():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
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
                    return render_template(
                        'fotor.html',
                        is_admin=is_admin,
                        notifications=unread_count,
                        results=results,
                        documento=documento,
                        selected_option=selected_option
                    )
                url = f"{base_url}?dado={documento}&tipo={tipo}"
                response = requests.get(url, verify=False, timeout=12)
                response.raise_for_status()
                raw = response.text.strip()
                data = json.loads(raw.lstrip('\ufeff'))
                inner = data.get("response", {}).get("response", [])
                if not inner or not isinstance(inner, list) or not inner[0].get("fotob64"):
                    flash('Nenhum resultado encontrado para o documento fornecido.', 'error')
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
                        flash('Limite de uso atingido para FOTOR.', 'error')
                        results = None
            except requests.Timeout:
                flash('A requisição excedeu o tempo limite.', 'error')
            except requests.HTTPError as e:
                flash(f'Erro na resposta da API: {e.response.status_code} - {e.response.text[:200]}', 'error')
            except requests.RequestException as e:
                flash(f'Erro ao conectar com o servidor da API: {str(e)}', 'error')
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida (JSON malformado).', 'error')
            except Exception as e:
                flash(f'Erro inesperado: {str(e)}', 'error')
    return render_template(
        'fotor.html',
        is_admin=is_admin,
        notifications=unread_count,
        results=results,
        documento=documento,
        selected_option=selected_option
    )

@app.route('/modulos/<uuid_str>/nomelv', methods=['GET', 'POST'])
@module_decorator
def nomelv():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}&tipo=nomev2"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                results_list = []
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
    return render_template('nomelv.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/<uuid_str>/nome', methods=['GET', 'POST'])
@module_decorator
def nome():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                url = f"http://br1.stormhost.online:10004/api/token=@signficativo/consulta?dado={nome}S&tipo=nomev1"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado') and len(data['resultado']) > 0:
                    if manage_module_usage(g.user_id, 'nome'):
                        results = data['resultado']
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
    return render_template('nome.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/<uuid_str>/ip', methods=['GET', 'POST'])
@module_decorator
def ip():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    ip_address = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip', '').strip()
        if not ip_address:
            flash('IP não fornecido.', 'error')
        else:
            try:
                url = f"https://ipwho.is/{ip_address}"
                response = requests.get(url, timeout=10)
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
    return render_template('ip.html', is_admin=is_admin, notifications=unread_count, results=results, ip_address=ip_address)

@app.route('/modulos/<uuid_str>/nome2', methods=['GET', 'POST'])
@module_decorator
def nome2():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    results = None
    nome = ""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash('Nome não fornecido.', 'error')
        else:
            try:
                url = f"https://api.bygrower.online/core/?token={chave}&base=nomeData&query={nome}"
                response = requests.get(url, verify=False, timeout=10)
                response.raise_for_status()
                data = json.loads(response.text.lstrip('\ufeff'))
                if data.get('resultado') and 'itens' in data['resultado']:
                    if manage_module_usage(g.user_id, 'nome2'):
                        results = data['resultado']['itens']
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
    return render_template('nome2.html', is_admin=is_admin, notifications=unread_count, results=results, nome=nome)

@app.route('/modulos/<uuid_str>/likeff', methods=['GET', 'POST'])
@module_decorator
def likeff():
    users = load_data('users.json')
    user = users[g.user_id]
    is_admin = user['role'] == 'admin'
    notifications = load_data('notifications.json')
    unread_count = len([n for n in notifications if n['id'] not in user.get('read_notifications', [])])
    result = None
    uid = ""
    if request.method == 'POST':
        uid = request.form.get('uid', '').strip()
        server_name = 'br'
        if not uid:
            flash('UID não fornecido.', 'error')
        else:
            try:
                token_url = "http://teamxcutehack.serv00.net/like/token_ind.json"
                ffinfo_url = f"https://lk-team-ffinfo-five.vercel.app/ffinfo?id={uid}"
                like_api_url = f"https://likeapiff.thory.in/like?uid={uid}&server_name={server_name}&token_url={requests.utils.quote(token_url)}"
                ffinfo_response = requests.get(ffinfo_url, timeout=10)
                ffinfo_response.raise_for_status()
                ffinfo_data = json.loads(ffinfo_response.text.lstrip('\ufeff'))
                if not ffinfo_data:
                    flash('Resposta vazia da API ffinfo.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                if "account_info" not in ffinfo_data or "├ Likes" not in ffinfo_data["account_info"]:
                    flash('Chave de likes ausente na resposta da API ffinfo.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                likes_before = int(str(ffinfo_data["account_info"]["├ Likes"]).replace(',', ''))
                like_response = requests.get(like_api_url, timeout=10)
                if like_response.status_code != 200:
                    flash(f'Falha na API de likes com código {like_response.status_code}.', 'error')
                    return render_template('likeff.html', is_admin=is_admin,
                                        notifications=unread_count,
                                        result=result, uid=uid)
                like_data = json.loads(like_response.text.lstrip('\ufeff'))
                if not like_data or "LikesafterCommand" not in like_data:
                    flash('JSON inválido da API de likes.', 'error')
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
                         notifications=unread_count,
                         result=result, uid=uid)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

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
    initialize_json('notifications.json', default_data=[])
    initialize_json('gifts.json')
    initialize_json('news.json', default_data=[])
    from waitress import serve
    serve(app, host='0.0.0.0', port=8855)
