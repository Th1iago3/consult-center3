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
from flask_socketio import SocketIO, join_room, leave_room, emit
import urllib3

# Desativar aviso SSL (para APIs que usam HTTP)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'novidades')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
colorama.init()

socketio = SocketIO(app, cors_allowed_origins="*")

# === ARQUIVOS JSON ===
POLLS_FILE = 'polls.json'
USER_VOTES_FILE = 'user_votes.json'
NEWS_FILE = 'news.json'

# === DADOS GLOBAIS ===
users_online = {}
login_attempts = {}

# === MÓDULOS ===
module_status = {
    'cpfdata': 'ON', 'cpflv': 'OFF', 'cpf': 'ON', 'cpf2': 'OFF', 'vacinas': 'ON',
    'cpf3': 'ON', 'nomelv': 'ON', 'nome': 'ON', 'nome2': 'ON', 'tel': 'OFF',
    'telLv': 'ON', 'teldual': 'OFF', 'datanome': 'ON', 'placa': 'ON',
    'placaestadual': 'OFF', 'fotor': 'ON', 'pix': 'ON', 'placalv': 'ON',
    'ip': 'ON', 'likeff': 'OFF', 'mae': 'ON', 'pai': 'ON', 'cnpjcompleto': 'ON'
}

chave = "vmb1"

# === FUNÇÕES DE ARQUIVO ===
def initialize_json(file_path, default_data=None):
    if default_data is None:
        default_data = {} if 'news.json' not in file_path else []
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(default_data, f, ensure_ascii=False, indent=4)

def load_data(file_path):
    initialize_json(file_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4, default=str)

# === CARREGAR DADOS ===
polls = load_data(POLLS_FILE)
user_votes = load_data(USER_VOTES_FILE)

# === INICIALIZAÇÃO ===
initialize_json('users.json')
initialize_json('notifications.json', {})
initialize_json('gifts.json')
initialize_json(NEWS_FILE, [])

# === FUNÇÕES AUXILIARES ===
def log_access(endpoint, message=''):
    try:
        ip = requests.get('https://ipinfo.io/json', timeout=3).json().get('ip', request.remote_addr)
    except:
        ip = request.remote_addr
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {ip} - {now} → {endpoint} {message}")

def manage_module_usage(user_id, module, increment=True):
    users = load_data('users.json')
    user = users.get(user_id, {})
    if user.get('role') == 'admin': return True
    permissions = user.get('permissions', {})
    if module not in permissions or datetime.now() > datetime.strptime(permissions[module], '%Y-%m-%d'):
        flash(f'Sem permissão para {module}.', 'error')
        return False
    if 'modules' not in user:
        user['modules'] = {m: 0 for m in module_status}
    if increment:
        user['modules'][module] += 1
    today = datetime.now().date().isoformat()
    if user.get('last_reset') != today:
        user['modules'] = {k: 0 for k in user['modules']}
        user['last_reset'] = today
    limit = {'guest': 0, 'user_semanal': 30, 'user_mensal': 250, 'user_anual': 500}.get(user.get('role'), 0)
    if user['modules'][module] > limit:
        flash(f'Limite diário excedido para {module}.', 'error')
        return False
    users[user_id] = user
    save_data(users, 'users.json')
    return True

def check_login_attempts(user_id):
    now = time.time()
    login_attempts[user_id] = login_attempts.get(user_id, {'count': 0, 'last_attempt': now})
    if now - login_attempts[user_id]['last_attempt'] > 300:
        login_attempts[user_id] = {'count': 0, 'last_attempt': now}
    login_attempts[user_id]['count'] += 1
    if login_attempts[user_id]['count'] > 5:
        return False, "Muitas tentativas. Aguarde 5 min."
    return True, ""

# === SEGURANÇA ===
@app.before_request
def security_check():
    if request.endpoint in ['login_or_register', 'creditos', 'preview', 'static']:
        return
    if 'user_id' not in session:
        flash('Faça login.', 'error')
        return redirect('/')
    g.user_id = session['user_id']
    users = load_data('users.json')
    user = users.get(g.user_id)
    if not user:
        session.clear()
        return redirect('/')
    if user['role'] not in ['admin', 'guest']:
        exp = datetime.strptime(user['expiration'], '%Y-%m-%d')
        if datetime.now() > exp:
            flash('Conta expirada.', 'error')
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
              
                user_agent = request.headers.get('User-Agent')
              
                # Device management logic: if 'devices' key is absent, allow unlimited devices
                if 'devices' not in users[username]:
                    # User supports unlimited devices, no restriction applied
                    pass
                else:
                    # User has device restriction
                    if users[username]['devices'] and user_agent not in users[username]['devices']:
                        flash('Dispositivo não autorizado. Login recusado.', 'error')
                        return render_template('login.html')
                    else:
                        users[username]['devices'] = [user_agent]
              
                save_data(users, 'users.json')
              
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
                'expiration': '2099-12-31', # Permanent for guests
                'permissions': {}, # No modules
                'modules': {m: 0 for m in module_status.keys()},
                'read_notifications': [],
                'referred_by': referred_by,
                'affiliate_code': secrets.token_urlsafe(8) if referred_by else None,
                'devices': []
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
        max_limit = 999999 # Large number for unlimited
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
def admin_panel():
    users = load_data('users.json')
    notifications = load_data('notifications.json')
    gifts = load_data('gifts.json')
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
                    'permissions': {m: None for m in module_status.keys()} if role != 'guest' else {},
                    'modules': {m: 0 for m in module_status.keys()},
                    'read_notifications': [],
                    'affiliate_code': secrets.token_urlsafe(8) if role != 'guest' else None,
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
                    return resp
                return jsonify({'message': 'Usuário excluído com sucesso!', 'category': 'success'})
            return jsonify({'message': 'Usuário ou senha incorretos.', 'category': 'error'})
        elif action == "view_users":
            return jsonify({'users': users})
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
                    return jsonify({'message': 'Usuário não encontrado.', 'category': 'error'})
            save_data(notifications, 'notifications.json')
            return jsonify({'message': 'Mensagem enviada com sucesso!', 'category': 'success'})
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
        elif action == 'create_gift':
            modules = request.form.get('modules') # comma separated or 'all'
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
    return render_template('admin.html', users=users, gifts=gifts, modules_state=module_status)
# Notifications Page
@app.route('/notifications', methods=['GET', 'POST'])
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
@app.route('/novidades')
def novidades():
    news = load_data(NEWS_FILE)
    for item in news:
        if item.get('type') == 'poll':
            poll_id = item['id']
            item['votes'] = polls.get(poll_id, {}).get('votes', {})
            item['user_votes'] = user_votes
    news.sort(key=lambda x: x['date'], reverse=True)
    return render_template('novidades.html', news=news)

@app.route('/novidades/new', methods=['GET', 'POST'])
def new_novidade():
    if load_data('users.json')[g.user_id]['role'] == 'guest':
        abort(403)
    if request.method == 'POST':
        title = request.form['title'].strip()
        desc = request.form['desc'].strip()
        ntype = request.form['type']
        if not title or not desc:
            flash('Preencha título e descrição.', 'error')
            return redirect('/novidades/new')
        news_id = str(uuid.uuid4())
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename:
                ext = os.path.splitext(file.filename)[1].lower()
                if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                    filename = f"{news_id}{ext}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    image_path = f"/static/novidades/{filename}"
        new_item = {
            'id': news_id,
            'type': ntype,
            'title': title,
            'desc': desc,
            'date': datetime.now().isoformat(),
            'sender': g.user_id,
            'image': image_path
        }
        if ntype == 'poll':
            options_str = request.form.get('options', '')
            options = [o.strip() for o in options_str.split('\n') if o.strip()]
            if len(options) < 2:
                flash('Mínimo 2 opções.', 'error')
                return redirect('/novidades/new')
            new_item.update({
                'options': options,
                'settings': {
                    'single_choice': 'single_choice' in request.form,
                    'allow_change': 'allow_change' in request.form
                }
            })
            polls[news_id] = {
                'votes': {opt: 0 for opt in options},
                'options': options,
                'settings': new_item['settings']
            }
            save_data(polls, POLLS_FILE)
        news = load_data(NEWS_FILE)
        news.append(new_item)
        save_data(news, NEWS_FILE)
        flash('Novidade criada!', 'success')
        return redirect('/novidades')
    return render_template('new_novidade.html')

@app.route('/novidades/edit/<news_id>', methods=['GET', 'POST'])
def edit_novidade(news_id):
    news = load_data(NEWS_FILE)
    item = next((n for n in news if n['id'] == news_id), None)
    if not item or (item['sender'] != g.user_id and load_data('users.json')[g.user_id]['role'] != 'admin'):
        abort(403)
    if request.method == 'POST':
        item['title'] = request.form['title']
        item['desc'] = request.form['desc']
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            ext = os.path.splitext(file.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                filename = f"{news_id}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                item['image'] = f"/static/novidades/{filename}"
        if item['type'] == 'poll':
            options_str = request.form.get('options', '')
            options = [o.strip() for o in options_str.split('\n') if o.strip()]
            if len(options) < 2:
                flash('Mínimo 2 opções.', 'error')
                return redirect(url_for('edit_novidade', news_id=news_id))
            item['options'] = options
            item['settings'] = {
                'single_choice': 'single_choice' in request.form,
                'allow_change': 'allow_change' in request.form
            }
            polls[news_id]['options'] = options
            polls[news_id]['settings'] = item['settings']
            polls[news_id]['votes'] = {opt: polls[news_id]['votes'].get(opt, 0) for opt in options}
            save_data(polls, POLLS_FILE)
        save_data(news, NEWS_FILE)
        flash('Editado!', 'success')
        return redirect('/novidades')
    return render_template('edit_novidade.html', item=item)

@app.route('/novidades/delete/<news_id>', methods=['POST'])
def delete_novidade(news_id):
    news = load_data(NEWS_FILE)
    item = next((n for n in news if n['id'] == news_id), None)
    if not item or (item['sender'] != g.user_id and load_data('users.json')[g.user_id]['role'] != 'admin'):
        abort(403)
    news.remove(item)
    if item.get('image'):
        try:
            os.remove(os.path.join(app.root_path, item['image'][1:]))
        except:
            pass
    if item['type'] == 'poll':
        polls.pop(news_id, None)
        save_data(polls, POLLS_FILE)
    save_data(news, NEWS_FILE)
    flash('Excluído!', 'success')
    return redirect('/novidades')

# === SOCKET.IO - ENQUETES EM TEMPO REAL ===
@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        users_online[request.sid] = session['user_id']

@socketio.on('disconnect')
def on_disconnect():
    users_online.pop(request.sid, None)

@socketio.on('join_poll')
def handle_join(data):
    poll_id = data.get('poll_id')
    if poll_id in polls:
        join_room(poll_id)
        emit('update_poll', {
            'poll_id': poll_id,
            'votes': polls[poll_id].get('votes', {}),
            'user_votes': user_votes
        }, room=poll_id)

@socketio.on('vote')
def handle_vote(data):
    poll_id = data.get('poll_id')
    option = data.get('option')
    user_id = session.get('user_id')
    if poll_id not in polls or not user_id:
        emit('vote_error', {'msg': 'Erro.'})
        return
    poll = polls[poll_id]
    single = poll['settings'].get('single_choice', True)
    allow_change = poll['settings'].get('allow_change', False)
    user_votes.setdefault(user_id, {})
    current = user_votes[user_id].get(poll_id)

    if single:
        if current and not allow_change:
            emit('vote_error', {'msg': 'Não pode mudar.'})
            return
        if current and current in poll['votes']:
            poll['votes'][current] -= 1
        if option:
            poll['votes'][option] = poll['votes'].get(option, 0) + 1
            user_votes[user_id][poll_id] = option
        else:
            user_votes[user_id].pop(poll_id, None)
    else:
        current = user_votes[user_id][poll_id] = current or []
        if option in current and not allow_change:
            emit('vote_error', {'msg': 'Já votou.'})
            return
        if option and option not in current:
            current.append(option)
            poll['votes'][option] = poll['votes'].get(option, 0) + 1
        elif option in current:
            current.remove(option)
            poll['votes'][option] -= 1
            if poll['votes'][option] <= 0:
                del poll['votes'][option]
        if not current:
            user_votes[user_id].pop(poll_id, None)

    save_data(polls, POLLS_FILE)
    save_data(user_votes, USER_VOTES_FILE)
    emit('update_poll', {
        'poll_id': poll_id,
        'votes': poll['votes'],
        'user_votes': user_votes
    }, room=poll_id)
    emit('vote_success', {'msg': 'Voto registrado!'})

# Module Routes
@app.route('/modulos/mae', methods=['GET', 'POST'])
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
@app.route('/modulos/pai', methods=['GET', 'POST'])
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
@app.route('/modulos/cnpjcompleto', methods=['GET', 'POST'])
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
@app.route('/modulos/cpf', methods=['GET', 'POST'])
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
@app.route('/modulos/cpf2', methods=['GET', 'POST'])
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
@app.route('/modulos/cpfdata', methods=['GET', 'POST'])
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
@app.route('/modulos/cpf3', methods=['GET', 'POST'])
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
            except json.JSONDecodeError:
                flash(f'Resposta da API inválida: {response.text}', 'error')
    return render_template('cpf3.html', is_admin=is_admin, notifications=unread_count, result=result, cpf=cpf)
@app.route('/modulos/cpflv', methods=['GET', 'POST'])
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
@app.route('/modulos/vacinas', methods=['GET', 'POST'])
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
@app.route('/modulos/datanome', methods=['GET', 'POST'])
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
@app.route('/modulos/placalv', methods=['GET', 'POST'])
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
            flash('Por favor, insira uma placa válida no formato AAA1234.', 'error')
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
@app.route('/modulos/telLv', methods=['GET', 'POST'])
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
@app.route('/modulos/teldual', methods=['GET', 'POST'])
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
@app.route('/modulos/tel', methods=['GET', 'POST'])
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
@app.route('/modulos/placa', methods=['GET', 'POST'])
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
@app.route('/modulos/placaestadual', methods=['GET', 'POST'])
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
@app.route('/modulos/pix', methods=['GET', 'POST'])
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
@app.route('/modulos/fotor', methods=['GET', 'POST'])
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
@app.route('/modulos/nomelv', methods=['GET', 'POST'])
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
@app.route('/modulos/nome', methods=['GET', 'POST'])
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
@app.route('/modulos/ip', methods=['GET', 'POST'])
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
@app.route('/modulos/nome2', methods=['GET', 'POST'])
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
@app.route('/modulos/likeff', methods=['GET', 'POST'])
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
    initialize_json('notifications.json', default_data={})
    initialize_json('gifts.json')
    initialize_json('news.json', default_data=[])
    socketio.run(app, host='0.0.0.0', port=8855, allow_unsafe_werkzeug=True)
