from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import random
import secrets
from datetime import datetime
import csv
import io
from functools import wraps
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = '840392751093847562910384756291038475629103847562917'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
print("🔑 [CONFIG] SECRET_KEY configured successfully")

# ==================== ШИФРОВАНИЕ ПЕРСОНАЛЬНЫХ ДАННЫХ (152-ФЗ) ====================
def get_fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(app.config['SECRET_KEY'].encode()).digest())
    return Fernet(key)

def encrypt_data(text):
    if not text:
        return None
    f = get_fernet()
    return f.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    if not encrypted_text:
        return ''
    f = get_fernet()
    return f.decrypt(encrypted_text.encode()).decode()

db = SQLAlchemy(app)

# ==================== НАСТРОЙКИ БЕЗОПАСНОСТИ ====================
# Имена, которые нельзя использовать при регистрации
RESERVED_NAMES = ['admin', 'админ', 'root', 'administrator', 'support']

# ==================== МОДЕЛЬ БАЗЫ ДАННЫХ ====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    group = db.Column(db.String(50), nullable=True)
    current_station = db.Column(db.Integer, default=1)
    answers = db.Column(db.Text, default='{}')
    station_2_progress = db.Column(db.Integer, default=0)
    station_3_progress = db.Column(db.Text, default='{}')
    is_finished = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200), nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name_enc = db.Column(db.String(500), nullable=True)
    phone_enc = db.Column(db.String(500), nullable=True)
    consent = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def set_full_name(self, name):
        self.full_name_enc = encrypt_data(name)
    
    def get_full_name(self):
        return decrypt_data(self.full_name_enc)
    
    def set_phone(self, phone):
        self.phone_enc = encrypt_data(phone)
    
    def get_phone(self):
        return decrypt_data(self.phone_enc)

# ==================== ДЕКОРАТОРЫ ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user:
            session.pop('user_id', None)
            session.pop('username', None)
            flash('Пользователь не найден. Пожалуйста, войдите снова', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs, user=user)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('У вас нет доступа к админ-панели', 'error')
            return redirect(url_for('profile'))
        
        return f(*args, **kwargs, user=user)
    return decorated_function

# ==================== ЗАГРУЗКА КОНТЕНТА ====================
def load_content():
    try:
        with open('content.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# ==================== МАРШРУТЫ АВТОРИЗАЦИИ ====================

# Главная страница с упрощённым входом
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return redirect(url_for('dashboard'))
        else:
            session.pop('user_id', None)
    return render_template('index.html')

# Быстрый старт по никнейму
@app.route('/quick_start', methods=['POST'])
def quick_start():
    try:
        print("🔍 [DEBUG] quick_start called")
        
        username = request.form.get('username', '').strip()
        print(f"🔍 [DEBUG] username received: '{username}'")
        
        if not username or len(username) < 3:
            flash('Никнейм должен содержать минимум 3 символа', 'error')
            print("❌ [ERROR] Username too short")
            return redirect(url_for('index'))
        
        # Проверка на зарезервированные имена
        if username.lower() in RESERVED_NAMES:
            flash('Это имя занято (системное имя). Пожалуйста, выберите другое.', 'error')
            print(f"❌ [ERROR] Reserved name: {username}")
            return redirect(url_for('index'))
        
        # Ищем пользователя в базе
        print("🔍 [DEBUG] Searching for user in database...")
        user = User.query.filter_by(username=username).first()
        
        if user:
            print(f"✅ [DEBUG] User found: {user.username}, is_admin: {user.is_admin}")
            # Если пользователь существует, проверяем, не админ ли это
            if user.is_admin:
                flash('Вход под этим именем через быстрый старт запрещен. Используйте пароль.', 'error')
                return redirect(url_for('index'))
            
            # Если обычный пользователь — просто входим в систему
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            print(f"✅ [DEBUG] User logged in: {user.username}")
            flash(f'С возвращением, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        
        # Если пользователя нет — создаем нового
        print(f"🔍 [DEBUG] Creating new user: {username}")
        user = User(username=username, email=None, group=None)
        
        # Генерируем пароль
        temp_password = 'temp_' + secrets.token_urlsafe(16)
        print(f"🔍 [DEBUG] Setting password...")
        user.set_password(temp_password)
        
        print("🔍 [DEBUG] Adding to database...")
        db.session.add(user)
        db.session.commit()
        print(f"✅ [DEBUG] User created with ID: {user.id}")
        
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        
        flash(f'Добро пожаловать, {user.username}!', 'success')
        print(f"✅ [DEBUG] Redirecting to dashboard...")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"❌ [CRITICAL ERROR] in quick_start: {str(e)}")
        import traceback
        print(traceback.format_exc())
        flash('Произошла ошибка при входе. Попробуйте позже.', 'error')
        return redirect(url_for('index'))

# Страница входа для админа
@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

# Обработка входа админа
@app.route('/admin_auth', methods=['POST'])
def admin_auth():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.is_admin and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        user.last_login = datetime.utcnow()
        db.session.commit()
        flash(f'С возвращением, {user.username}!', 'success')
        return redirect(url_for('admin'))
    else:
        flash('Неверное имя пользователя или пароль', 'error')
        return redirect(url_for('admin_login'))

# Выход из системы
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# ==================== РЕГИСТРАЦИЯ И ВХОД (оставлены для совместимости) ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') or None
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        group = request.form.get('group', '')
        
        # ... (проверка согласия с политикой) ...
        if not request.form.get('privacy_consent'):
            flash('Необходимо согласиться с Политикой конфиденциальности', 'error')
            return render_template('register.html')
        
        if not username or not password:
            flash('Имя пользователя и пароль обязательны', 'error')
            return render_template('register.html')
        
        # 🔒 НОВОЕ: Проверка на зарезервированные имена
        if username.lower() in RESERVED_NAMES:
            flash('Это имя занято (системное имя). Пожалуйста, выберите другое.', 'error')
            return render_template('register.html')

        if password != password_confirm:
            flash('Пароли не совпадают', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Пароль должен быть не менее 6 символов', 'error')
            return render_template('register.html')
        
        # 🔒 ПРОВЕРКА: Существует ли пользователь с таким именем
        if User.query.filter_by(username=username).first():
            flash('Это имя уже занято. Попробуйте другое.', 'error')
            return render_template('register.html')
        
        if email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'error')
            return render_template('register.html')
        
        user = User(username=username, email=email, group=group)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь войдите в систему', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f'С возвращением, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

# ==================== ГЛАВНАЯ СТРАНИЦА (ДАШБОРД) ====================
@app.route('/dashboard')
@login_required
def dashboard(user):
    content = load_content()
    stations_status = []
    answers = json.loads(user.answers) if user.answers else {}
    
    for i in range(1, 7):
        station_key = f"station_{i}"
        station_data = content.get(station_key, {})
        is_completed = False
        
        if i == 1:
            if station_key in answers:
                answer = answers[station_key]
                if answer.get('total', 0) == 8000 and answer.get('savings', 0) >= 800:
                    is_completed = True
        elif i == 2:
            completed_count = 0
            questions = station_data.get('questions', [])
            for q in range(len(questions)):
                if f"{station_key}_q{q}" in answers:
                    if answers[f"{station_key}_q{q}"].get('is_correct', False):
                        completed_count += 1
            if completed_count == len(questions) and len(questions) > 0:
                is_completed = True
        elif i == 3:
            correct_count = 0
            total_questions = 0
            rounds = station_data.get('rounds', [])
            for round_idx, round_data in enumerate(rounds):
                questions = round_data.get('questions', [])
                total_questions += len(questions)
                for q_idx in range(len(questions)):
                    key = f"{station_key}_r{round_idx}_q{q_idx}"
                    if key in answers and answers[key].get('is_correct', False):
                        correct_count += 1
            if correct_count == total_questions and total_questions > 0:
                is_completed = True
        elif i == 4:
            questions = station_data.get('questions', [])
            if f"{station_key}_progress" in answers:
                if answers[f"{station_key}_progress"] >= len(questions):
                    correct_count = 0
                    for q in range(len(questions)):
                        if f"{station_key}_q{q}" in answers:
                            if answers[f"{station_key}_q{q}"].get('is_correct', False):
                                correct_count += 1
                    if correct_count == len(questions):
                        is_completed = True
        elif i == 5:
            if f"{station_key}_completed" in answers and answers[f"{station_key}_completed"] == True:
                is_completed = True
            else:
                terms = station_data.get('terms', [])
                term_ids = [t['id'] for t in terms]
                if all(f"{station_key}_{tid}" in answers for tid in term_ids):
                    correct_count = 0
                    for term in terms:
                        key = f"{station_key}_{term['id']}"
                        if key in answers and answers[key] == term['correct_definition']:
                            correct_count += 1
                    if correct_count == len(terms):
                        is_completed = True
        elif i == 6:
            correct_count = 0
            questions = station_data.get('questions', [])
            for q in range(len(questions)):
                key = f"{station_key}_q{q}"
                if key in answers:
                    if answers[key].get('is_correct', False):
                        correct_count += 1
            if correct_count == len(questions):
                is_completed = True
        
        if is_completed:
            status = 'completed'
        elif i == 1 or (i > 1 and stations_status[i-2]['status'] == 'completed'):
            status = 'available'
        else:
            status = 'locked'
        
        stations_status.append({
            'id': i,
            'title': station_data.get('title', f'Станция {i}'),
            'description': station_data.get('description', ''),
            'status': status
        })
    
    return render_template('dashboard.html', user=user, stations=stations_status)

# ==================== ДОСТУП К СТАНЦИИ ====================
@app.route('/station/<int:station_num>')
@login_required
def access_station(user, station_num):
    if station_num < 1 or station_num > 6:
        flash('Неверный номер станции', 'error')
        return redirect(url_for('dashboard'))
    
    answers = json.loads(user.answers) if user.answers else {}
    content = load_content()  # Загружаем контент для проверок
    
    # ==================== СБРОС ПРОГРЕССА ПРИ ПОВТОРНОМ ПРОХОЖДЕНИИ ====================
    station_key = f"station_{station_num}"
    station_data = content.get(station_key, {})
    
    if station_num == 2:
        questions = station_data.get('questions', [])
        completed_count = sum(1 for q in range(len(questions))
                            if f"{station_key}_q{q}" in answers
                            and answers[f"{station_key}_q{q}"].get('is_correct', False))
        if completed_count == len(questions) and len(questions) > 0:
            user.station_2_progress = 0
    
    elif station_num == 3:
        rounds = station_data.get('rounds', [])
        correct_count = 0
        total_questions = 0
        for round_idx, round_data in enumerate(rounds):
            questions = round_data.get('questions', [])
            total_questions += len(questions)
            for q_idx in range(len(questions)):
                key = f"{station_key}_r{round_idx}_q{q_idx}"
                if key in answers and answers[key].get('is_correct', False):
                    correct_count += 1
        if correct_count == total_questions and total_questions > 0:
            user.station_3_progress = json.dumps({'round': 0, 'question': 0})
    
    # ==================== ПРОВЕРКА ДОСТУПА К СТАНЦИИ ====================
    prev_station = f"station_{station_num - 1}"
    prev_data = content.get(prev_station, {})
    is_prev_completed = False
    
    if station_num == 1:
        is_prev_completed = True
        
    elif station_num == 2:
        if prev_station in answers:
            answer = answers[prev_station]
            if answer.get('total', 0) == 8000 and answer.get('savings', 0) >= 800:
                is_prev_completed = True
                
    elif station_num == 3:
        questions = prev_data.get('questions', [])
        completed_count = 0
        for q in range(len(questions)):
            if f"{prev_station}_q{q}" in answers:
                if answers[f"{prev_station}_q{q}"].get('is_correct', False):
                    completed_count += 1
        if completed_count == len(questions) and len(questions) > 0:
            is_prev_completed = True
            
    elif station_num == 4:
        prev_rounds = prev_data.get('rounds', [])
        correct_count = 0
        total = 0
        for round_idx, round_data in enumerate(prev_rounds):
            questions = round_data.get('questions', [])
            total += len(questions)
            for q_idx in range(len(questions)):
                key = f"{prev_station}_r{round_idx}_q{q_idx}"
                if key in answers and answers[key].get('is_correct', False):
                    correct_count += 1
        if correct_count == total and total > 0:
            is_prev_completed = True
            
    elif station_num == 5:
        if f"{prev_station}_completed" in answers and answers[f"{prev_station}_completed"] == True:
            is_prev_completed = True
        else:
            terms = prev_data.get('terms', [])
            term_ids = [t['id'] for t in terms]
            if all(f"{prev_station}_{tid}" in answers for tid in term_ids):
                correct_count = 0
                for term in terms:
                    key = f"{prev_station}_{term['id']}"
                    if key in answers and answers[key] == term['correct_definition']:
                        correct_count += 1
                if correct_count == len(terms):
                    is_prev_completed = True
                
    elif station_num == 6:
        if f"{prev_station}_completed" in answers and answers[f"{prev_station}_completed"] == True:
            is_prev_completed = True
        else:
            terms = prev_data.get('terms', [])
            term_ids = [t['id'] for t in terms]
            if all(f"{prev_station}_{tid}" in answers for tid in term_ids):
                correct_count = 0
                for term in terms:
                    key = f"{prev_station}_{term['id']}"
                    if key in answers and answers[key] == term['correct_definition']:
                        correct_count += 1
                if correct_count == len(terms):
                    is_prev_completed = True
    
    if not is_prev_completed:
        flash(f'Сначала пройдите Станцию {station_num - 1} полностью', 'warning')
        return redirect(url_for('dashboard'))
    
    user.current_station = station_num
    db.session.commit()
    
    return redirect(url_for('station'))

# ==================== РЕЗУЛЬТАТЫ СТАНЦИИ ====================
@app.route('/station_results/<int:station_num>')
@login_required
def station_results(user, station_num):
    if station_num < 1 or station_num > 6:
        flash('Неверный номер станции', 'error')
        return redirect(url_for('dashboard'))
    
    content = load_content()
    station_key = f"station_{station_num}"
    station_data = content.get(station_key, {})
    answers = json.loads(user.answers) if user.answers else {}
    
    question_results = []
    total_questions = 0
    correct_questions = 0
    
    if station_num == 1:
        total_questions = 1
        if station_key in answers:
            answer = answers[station_key]
            is_correct = answer.get('total', 0) == 8000 and answer.get('savings', 0) >= 800
            if is_correct:
                correct_questions = 1
            question_results.append({
                'question': 'Распределение бюджета',
                'user_answer': f'Всего: {answer.get("total", 0)} ИК, Сбережения: {answer.get("savings", 0)} ИК',
                'correct_answer': 'Всего: 8000 ИК, Сбережения: >= 800 ИК',
                'is_correct': is_correct
            })
    elif station_num == 2:
        questions = station_data.get('questions', [])
        total_questions = len(questions)
        for i, question in enumerate(questions):
            key = f"{station_key}_q{i}"
            if key in answers:
                answer_data = answers[key]
                is_correct = answer_data.get('is_correct', False)
                if is_correct:
                    correct_questions += 1
                question_results.append({
                    'question': question.get('text', f'Вопрос {i+1}'),
                    'user_answer': ', '.join(answer_data.get('selected', [])) or 'Не выбрано',
                    'correct_answer': ', '.join(answer_data.get('correct', [])),
                    'is_correct': is_correct
                })
    elif station_num == 3:
        rounds = station_data.get('rounds', [])
        total_questions = sum(len(r.get('questions', [])) for r in rounds)
        for round_idx, round_data in enumerate(rounds):
            for q_idx, question in enumerate(round_data.get('questions', [])):
                key = f"{station_key}_r{round_idx}_q{q_idx}"
                answer_data = answers.get(key, {'answer': 'Не отвечено', 'is_correct': False})
                is_correct = answer_data.get('is_correct', False)
                if is_correct:
                    correct_questions += 1
                correct_answer = ', '.join(question.get('correct_answers', [])) if round_idx == 2 else question.get('correct_answer', '')
                question_results.append({
                    'question': question.get('text', f'Вопрос {q_idx+1}'),
                    'user_answer': answer_data.get('answer', 'Не отвечено'),
                    'correct_answer': correct_answer,
                    'is_correct': is_correct
                })
    elif station_num == 4:
        questions = station_data.get('questions', [])
        total_questions = len(questions)
        for i, question in enumerate(questions):
            key = f"{station_key}_q{i}"
            if key in answers:
                answer_data = answers[key]
                is_correct = answer_data.get('is_correct', False)
                if is_correct:
                    correct_questions += 1
                question_results.append({
                    'question': question.get('text', f'Вопрос {i+1}'),
                    'user_answer': answer_data.get('selected', 'Не выбрано'),
                    'correct_answer': answer_data.get('correct', ''),
                    'is_correct': is_correct
                })
    elif station_num == 5:
        terms = station_data.get('terms', [])
        total_questions = len(terms)
        for term in terms:
            key = f"{station_key}_{term['id']}"
            if key in answers:
                user_answer = answers[key]
                is_correct = user_answer == term['correct_definition']
                if is_correct:
                    correct_questions += 1
                question_results.append({
                    'question': term['name'],
                    'user_answer': user_answer or 'Не выбрано',
                    'correct_answer': term['correct_definition'],
                    'is_correct': is_correct
                })
    elif station_num == 6:
        questions = station_data.get('questions', [])
        total_questions = len(questions)
        for i, question in enumerate(questions):
            key = f"{station_key}_q{i}"
            if key in answers:
                answer_data = answers[key]
                is_correct = answer_data.get('is_correct', False)
                if is_correct:
                    correct_questions += 1
                question_results.append({
                    'question': question.get('text', f'Вопрос {i+1}'),
                    'user_answer': answer_data.get('answer', 'Не выбрано'),
                    'correct_answer': question.get('correct_answer', '') or ', '.join(question.get('keywords', [])),
                    'is_correct': is_correct
                })
    
    accuracy = round((correct_questions / total_questions * 100)) if total_questions > 0 else 0
    
    # ✅ НОВОЕ: Проверяем, пройдена ли станция 6 полностью
    is_station_completed = (correct_questions == total_questions)
    
    return render_template('station_results.html', 
                         user=user, 
                         station_num=station_num, 
                         station_title=station_data.get('title', f'Станция {station_num}'), 
                         total_questions=total_questions, 
                         correct_questions=correct_questions, 
                         accuracy=accuracy, 
                         question_results=question_results,
                         is_station_completed=is_station_completed)  # ✅ Передаем флаг

# ==================== ОСНОВНОЙ ФУНКЦИОНАЛ ИГРЫ ====================
@app.route('/station', methods=['GET', 'POST'])
@login_required
def station(user):
    content = load_content()
    if user.is_finished:
        return redirect(url_for('result'))
    
    if request.method == 'POST':
        station_key = f"station_{user.current_station}"
        if station_key not in content:
            flash('Станция не найдена', 'error')
            return redirect(url_for('dashboard'))
        
        station_data = content[station_key]
        is_correct = False
        answers = json.loads(user.answers) if user.answers else {}
        
        if station_data['type'] == 'budget':
            if station_key in answers:
                flash('Вы уже прошли эту станцию', 'warning')
                return redirect(url_for('station_results', station_num=user.current_station))
            try:
                food = float(request.form.get('food', 0))
                transport = float(request.form.get('transport', 0))
                phone = float(request.form.get('phone', 0))
                entertainment = float(request.form.get('entertainment', 0))
                education = float(request.form.get('education', 0))
                savings = float(request.form.get('savings', 0))
                total = food + transport + phone + entertainment + education + savings
                min_savings = station_data.get('min_savings', 800)
                max_income = station_data.get('max_income', 8000)
                if abs(total - max_income) <= 1 and savings >= min_savings:
                    is_correct = True
                answer_data = {'food': food, 'transport': transport, 'phone': phone, 'entertainment': entertainment, 'education': education, 'savings': savings, 'total': total}
            except:
                answer_data = {'error': 'invalid_input'}
            answers[station_key] = answer_data
            user.answers = json.dumps(answers, ensure_ascii=False)
            db.session.commit()
            return redirect(url_for('station_results', station_num=user.current_station))
        
        elif station_data['type'] == 'choice_multiple':
            questions = station_data.get('questions', [])
            current_q_index = user.station_2_progress
            if current_q_index < len(questions):
                question = questions[current_q_index]
                selected_answers = request.form.getlist('answer')
                correct_answers = question.get('correct_answers', [])
                if sorted(selected_answers) == sorted(correct_answers):
                    is_correct = True
                answer_data = {'question_id': question.get('id'), 'selected': selected_answers, 'correct': correct_answers, 'is_correct': is_correct}
                answers[f"{station_key}_q{current_q_index}"] = answer_data
                user.answers = json.dumps(answers, ensure_ascii=False)
                user.station_2_progress += 1
                db.session.commit()
                if user.station_2_progress >= len(questions):
                    user.station_2_progress = 0
                    return redirect(url_for('station_results', station_num=user.current_station))
                return redirect(url_for('station'))
        
        elif station_data['type'] == 'quiz':
            rounds = station_data.get('rounds', [])
            quiz_progress = json.loads(user.station_3_progress) if user.station_3_progress else {'round': 0, 'question': 0}
            current_round_idx = quiz_progress.get('round', 0)
            current_question_idx = quiz_progress.get('question', 0)
            if current_round_idx < len(rounds):
                current_round = rounds[current_round_idx]
                questions = current_round.get('questions', [])
                if current_question_idx < len(questions):
                    question = questions[current_question_idx]
                    answer = request.form.get('answer', '')
                    is_correct = False
                    if current_round['id'] == 3:
                        correct_answers = question.get('correct_answers', [])
                        answer_lower = answer.lower().strip()
                        is_correct = any(correct.lower() in answer_lower or answer_lower in correct.lower() for correct in correct_answers)
                    else:
                        is_correct = answer == question.get('correct_answer', '')
                    answer_data = {'round': current_round_idx + 1, 'question': current_question_idx + 1, 'text': question['text'], 'answer': answer, 'is_correct': is_correct}
                    answers[f"{station_key}_r{current_round_idx}_q{current_question_idx}"] = answer_data
                    user.answers = json.dumps(answers, ensure_ascii=False)
                    if current_question_idx + 1 >= len(questions):
                        if current_round_idx + 1 >= len(rounds):
                            user.station_3_progress = json.dumps({'round': 0, 'question': 0})
                            db.session.commit()
                            return redirect(url_for('station_results', station_num=user.current_station))
                        quiz_progress['round'] = current_round_idx + 1
                        quiz_progress['question'] = 0
                    else:
                        quiz_progress['question'] = current_question_idx + 1
                    user.station_3_progress = json.dumps(quiz_progress)
                    db.session.commit()
                    return redirect(url_for('station'))
        
        elif station_data['type'] == 'scammer_quiz':
            questions = station_data.get('questions', [])
            answers_dict = json.loads(user.answers) if user.answers else {}
            station_4_progress = answers_dict.get(f"{station_key}_progress", 0)
            
            if station_4_progress < len(questions):
                question = questions[station_4_progress]
                answer = request.form.get('answer', '')
                is_correct = answer == question.get('correct_answer', '')
                answer_data = {
                    'question_id': question.get('id'), 
                    'selected': answer, 
                    'correct': question.get('correct_answer', ''), 
                    'is_correct': is_correct
                }
                answers_dict[f"{station_key}_q{station_4_progress}"] = answer_data
                answers_dict[f"{station_key}_progress"] = station_4_progress + 1
                
                # ИСПРАВЛЕНИЕ: Проверяем, все ли вопросы правильные
                if station_4_progress + 1 >= len(questions):
                    # Проверяем все ответы
                    all_correct = all(
                        answers_dict.get(f"{station_key}_q{i}", {}).get('is_correct', False)
                        for i in range(len(questions))
                    )
                    if all_correct:
                        answers_dict[f"{station_key}_completed"] = True  # ✅ Устанавливаем флаг!
                
                user.answers = json.dumps(answers_dict, ensure_ascii=False)
                db.session.commit()
                
                if station_4_progress + 1 >= len(questions):
                    return redirect(url_for('station_results', station_num=user.current_station))
                return redirect(url_for('station'))
        
        elif station_data['type'] == 'matching_puzzle':
            answers_dict = json.loads(user.answers) if user.answers else {}
            terms = station_data.get('terms', [])
            all_matched = True
            wrong_terms = []
            for term in terms:
                term_id = term['id']
                user_answer = request.form.get(f"term_{term_id}", "")
                if not user_answer:
                    all_matched = False
                    wrong_terms.append(term_id)
                elif user_answer != term['correct_definition']:
                    all_matched = False
                    wrong_terms.append(term_id)
                answers_dict[f"{station_key}_{term_id}"] = user_answer
            user.answers = json.dumps(answers_dict, ensure_ascii=False)
            if all_matched:
                answers_dict[f"{station_key}_completed"] = True
                user.answers = json.dumps(answers_dict, ensure_ascii=False)
                db.session.commit()
                return redirect(url_for('station_results', station_num=user.current_station))
            else:
                if wrong_terms:
                    term_names = [term['name'] for term in terms if term['id'] in wrong_terms]
                    flash(f"Неправильно: {', '.join(term_names)}. Попробуйте ещё раз!", 'error')
                else:
                    flash('Не все термины сопоставлены. Заполните все поля!', 'warning')
                db.session.commit()
                return redirect(url_for('station'))
        
        elif station_data['type'] == 'text':
            questions = station_data.get('questions', [])
            answers_dict = json.loads(user.answers) if user.answers else {}
            
            # ИСПРАВЛЕНИЕ: Очищаем старые ответы этой станции перед новой попыткой
            for i in range(len(questions)):
                key = f"{station_key}_q{i}"
                if key in answers_dict:
                    del answers_dict[key]
            
            correct_count = 0
            for i, question in enumerate(questions):
                user_answer = request.form.get(f'question_{i}', '').lower().strip()
                is_correct = False
                
                if question['type'] == 'text':
                    is_correct = any(kw.lower() in user_answer for kw in question.get('keywords', []))
                elif question['type'] == 'choice':
                    is_correct = user_answer == question.get('correct_answer', '').lower().strip()
                
                if is_correct:
                    correct_count += 1
                    
                answers_dict[f"{station_key}_q{i}"] = {
                    'question': question['text'], 
                    'answer': user_answer, 
                    'is_correct': is_correct
                }
            
            user.answers = json.dumps(answers_dict, ensure_ascii=False)
            if correct_count == len(questions):
                user.is_finished = True
            db.session.commit()
            return redirect(url_for('station_results', station_num=6))
    
    # ==================== GET-ЗАПРОС: ПОЛУЧЕНИЕ ВОПРОСОВ ====================
    if user.is_finished:
        return redirect(url_for('result'))
    
    station_key = f"station_{user.current_station}"
    station_data = content.get(station_key, {})
    question_index = 0
    current_question = None
    current_round = None
    station_4_index = 0
    shuffled_definitions = []
    
    # Станция 2: Кредиты
    if user.current_station == 2 and station_data.get('type') == 'choice_multiple':
        questions = station_data.get('questions', [])
        question_index = user.station_2_progress
        # ИСПРАВЛЕНИЕ: Если прогресс за пределами вопросов — сбрасываем
        if question_index >= len(questions):
            question_index = 0
            user.station_2_progress = 0
            db.session.commit()
        if question_index < len(questions):
            current_question = questions[question_index]
    
    # Станция 3: Квиз
    if user.current_station == 3 and station_data.get('type') == 'quiz':
        rounds = station_data.get('rounds', [])
        quiz_progress = json.loads(user.station_3_progress) if user.station_3_progress else {'round': 0, 'question': 0}
        current_round_idx = quiz_progress.get('round', 0)
        current_question_idx = quiz_progress.get('question', 0)
        if current_round_idx < len(rounds):
            current_round = rounds[current_round_idx]
            questions = current_round.get('questions', [])
            if current_question_idx < len(questions):
                current_question = questions[current_question_idx]
    
    # Станция 4: Мошенники
    if user.current_station == 4 and station_data.get('type') == 'scammer_quiz':
        questions = station_data.get('questions', [])
        answers_dict = json.loads(user.answers) if user.answers else {}
        station_4_index = answers_dict.get(f"{station_key}_progress", 0)
        
        # ИСПРАВЛЕНИЕ: Если прогресс за пределами вопросов — сбрасываем
        if station_4_index >= len(questions):
            station_4_index = 0
            answers_dict[f"{station_key}_progress"] = 0
            user.answers = json.dumps(answers_dict, ensure_ascii=False)
            db.session.commit()
        
        if station_4_index < len(questions):
            current_question = questions[station_4_index]
    
    # Станция 5: Пазл
    if user.current_station == 5 and station_data.get('type') == 'matching_puzzle':
        definitions = station_data.get('definitions', [])
        shuffled_definitions = definitions.copy()
        random.shuffle(shuffled_definitions)
    
    # ✅ ОБЯЗАТЕЛЬНЫЙ RETURN В КОНЦЕ ФУНКЦИИ
    return render_template('station.html', 
                         station=station_data, 
                         station_num=user.current_station, 
                         user=user,
                         question_index=question_index, 
                         current_question=current_question, 
                         current_round=current_round, 
                         station_4_index=station_4_index, 
                         shuffled_definitions=shuffled_definitions)

@app.route('/result')
@login_required
def result(user):
    all_users = User.query.filter_by(is_finished=True).order_by(User.created_at.asc()).all()
    user_rank = next((i+1 for i, u in enumerate(all_users) if u.id == user.id), len(all_users)+1)
    return render_template('result.html', user=user, user_rank=user_rank)

@app.route('/profile')
@login_required
def profile(user):
    answers = json.loads(user.answers) if user.answers else {}
    stations_completed = len([k for k in answers.keys() if answers[k]])
    all_users = User.query.filter_by(is_finished=True).order_by(User.created_at.asc()).all()
    user_rank = next((i+1 for i, u in enumerate(all_users) if u.id == user.id), len(all_users)+1)
    return render_template('profile.html', user=user, stations_completed=stations_completed, user_rank=user_rank)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings(user):
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_profile':
            email = request.form.get('email', '')
            group = request.form.get('group', '')
            if email and email != user.email:
                if User.query.filter_by(email=email).first():
                    flash('Этот email уже используется', 'error')
                    return render_template('settings.html', user=user)
                user.email = email
            user.group = group
            db.session.commit()
            flash('Профиль обновлен', 'success')
        elif action == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            new_password_confirm = request.form.get('new_password_confirm')
            if not user.check_password(old_password):
                flash('Старый пароль неверный', 'error')
                return render_template('settings.html', user=user)
            if len(new_password) < 6:
                flash('Новый пароль должен быть не менее 6 символов', 'error')
                return render_template('settings.html', user=user)
            if new_password != new_password_confirm:
                flash('Новые пароли не совпадают', 'error')
                return render_template('settings.html', user=user)
            user.set_password(new_password)
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
        elif action == 'reset_game':
            user.current_station = 1
            user.answers = '{}'
            user.is_finished = False
            user.station_2_progress = 0
            user.station_3_progress = '{}'
            db.session.commit()
            flash('Прогресс игры сброшен', 'success')
            return redirect(url_for('dashboard'))
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

@app.route('/reset', methods=['POST'])
@login_required
def reset(user):
    user.current_station = 1
    user.answers = '{}'
    user.is_finished = False
    user.station_2_progress = 0
    user.station_3_progress = '{}'
    db.session.commit()
    flash('Прогресс сброшен. Начинайте игру заново!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/privacy')
def privacy():
    from datetime import datetime
    return render_template('privacy.html', current_date=datetime.now().strftime('%d.%m.%Y'), admin_email='support@financial-reid.ru', contact_phone='+7 (XXX) XXX-XX-XX', contact_address='г. Москва, Россия')

# ==================== АДМИН-ПАНЕЛЬ ====================

# ИСПРАВЛЕНИЕ 2: Удалён дублирующий маршрут /admin (оставлен только расширенный вариант ниже)

# ИСПРАВЛЕНИЕ 3: Удалён дублирующий маршрут /admin/export (оставлен только вариант ниже)

# ==================== АДМИН-ПАНЕЛЬ: УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ====================

# Оставлена только ОДНА функция admin() с @admin_required
@app.route('/admin')
@admin_required
def admin(user):
    users = User.query.all()
    total_users = len(users)
    finished_users = sum(1 for u in users if u.is_finished)
    banned_users = sum(1 for u in users if u.is_banned)
    return render_template('admin.html', 
                         users=users, 
                         total_users=total_users,
                         finished_users=finished_users,
                         banned_users=banned_users,
                         current_user=user)

@app.route('/admin/users')
@admin_required
def admin_users(user):
    users = User.query.all()
    return render_template('admin_users.html', users=users, current_user=user)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user, user_id):
    target_user = User.query.get_or_404(user_id)
    answers = json.loads(target_user.answers) if target_user.answers else {}
    content = load_content()
    
    # Вычисляем статус каждой станции в Python (вместо сложной логики в шаблоне)
    stations_progress = []
    for i in range(1, 7):
        station_key = f"station_{i}"
        station_data = content.get(station_key, {})
        is_completed = False
        
        if i == 1:
            if station_key in answers:
                answer = answers[station_key]
                if answer.get('total', 0) == 8000 and answer.get('savings', 0) >= 800:
                    is_completed = True
        elif i == 2:
            questions = station_data.get('questions', [])
            completed_count = sum(1 for q in range(len(questions))
                                if f"{station_key}_q{q}" in answers
                                and answers[f"{station_key}_q{q}"].get('is_correct', False))
            if completed_count == len(questions) and len(questions) > 0:
                is_completed = True
        elif i == 3:
            correct_count = 0
            total_questions = 0
            rounds = station_data.get('rounds', [])
            for round_idx, round_data in enumerate(rounds):
                questions = round_data.get('questions', [])
                total_questions += len(questions)
                for q_idx in range(len(questions)):
                    key = f"{station_key}_r{round_idx}_q{q_idx}"
                    if key in answers and answers[key].get('is_correct', False):
                        correct_count += 1
            if correct_count == total_questions and total_questions > 0:
                is_completed = True
        elif i == 4:
            questions = station_data.get('questions', [])
            if f"{station_key}_progress" in answers and answers[f"{station_key}_progress"] >= len(questions):
                correct_count = sum(1 for q in range(len(questions))
                                  if f"{station_key}_q{q}" in answers
                                  and answers[f"{station_key}_q{q}"].get('is_correct', False))
                if correct_count == len(questions):
                    is_completed = True
        elif i == 5:
            if answers.get(f"{station_key}_completed") == True:
                is_completed = True
            else:
                terms = station_data.get('terms', [])
                term_ids = [t['id'] for t in terms]
                if all(f"{station_key}_{tid}" in answers for tid in term_ids):
                    matched = sum(1 for t in terms
                                if answers.get(f"{station_key}_{t['id']}") == t['correct_definition'])
                    if matched == len(terms):
                        is_completed = True
        elif i == 6:
            questions = station_data.get('questions', [])
            correct_count = sum(1 for q in range(len(questions))
                              if f"{station_key}_q{q}" in answers
                              and answers[f"{station_key}_q{q}"].get('is_correct', False))
            if correct_count == len(questions):
                is_completed = True
        
        stations_progress.append({
            'id': i,
            'title': content.get(station_key, {}).get('title', f'Станция {i}'),
            'is_completed': is_completed
        })
    
    return render_template('admin_user_detail.html', 
                         target_user=target_user, 
                         stations_progress=stations_progress,  # Передаём готовый список
                         current_user=user)

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@admin_required
def admin_ban_user(user, user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.id == user.id:
        flash('Нельзя заблокировать самого себя!', 'error')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    target_user.is_banned = True
    target_user.ban_reason = request.form.get('ban_reason', 'Нарушение правил')
    db.session.commit()
    flash(f'Пользователь {target_user.username} заблокирован', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@admin_required
def admin_unban_user(user, user_id):
    target_user = User.query.get_or_404(user_id)
    target_user.is_banned = False
    target_user.ban_reason = None
    db.session.commit()
    flash(f'Пользователь {target_user.username} разблокирован', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/reset_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_reset_user(user, user_id):
    target_user = User.query.get_or_404(user_id)
    target_user.current_station = 1
    target_user.answers = '{}'
    target_user.is_finished = False
    target_user.station_2_progress = 0
    target_user.station_3_progress = '{}'
    target_user.score = 0
    db.session.commit()
    flash(f'Прогресс пользователя {target_user.username} сброшен', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user, user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.id == user.id:
        flash('Нельзя удалить самого себя!', 'error')
        return redirect(url_for('admin_users'))
    if target_user.is_admin:
        flash('Для удаления администратора используйте раздел управления администраторами', 'error')
        return redirect(url_for('admin_users'))
    username = target_user.username
    db.session.delete(target_user)
    db.session.commit()
    flash(f'Пользователь {username} удалён', 'success')
    return redirect(url_for('admin_users'))

# ==================== АДМИН-ПАНЕЛЬ: УПРАВЛЕНИЕ АДМИНИСТРАТОРАМИ ====================

@app.route('/admin/admins')
@admin_required
def admin_admins(user):
    admins = User.query.filter(User.is_admin == True).all()
    return render_template('admin_admins.html', admins=admins, current_user=user)

@app.route('/admin/create_admin', methods=['GET', 'POST'])
@admin_required
def admin_create_admin(user):
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'junior')
        
        if not username or len(password) < 6:
            flash('Имя и пароль (мин. 6 символов) обязательны', 'error')
            return redirect(url_for('admin_create_admin'))
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('admin_create_admin'))
        
        if role == 'senior' and not user.is_super_admin:
            flash('Только старший администратор может создавать других старших администраторов', 'error')
            return redirect(url_for('admin_create_admin'))
        
        new_admin = User(username=username, group='Administrator')
        new_admin.set_password(password)
        new_admin.is_admin = True
        new_admin.is_super_admin = (role == 'senior')
        new_admin.email_verified = True
        db.session.add(new_admin)
        db.session.commit()
        
        role_name = 'старший' if role == 'senior' else 'младший'
        flash(f'{role_name.capitalize()} администратор {username} создан', 'success')
        return redirect(url_for('admin_admins'))
    
    return render_template('admin_create_admin.html', current_user=user)

@app.route('/admin/delete_admin/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_admin(user, user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.id == user.id:
        flash('Нельзя удалить самого себя!', 'error')
        return redirect(url_for('admin_admins'))
    if not user.is_super_admin:
        flash('Только старший администратор может удалять администраторов', 'error')
        return redirect(url_for('admin_admins'))
    if target_user.is_super_admin:
        flash('Нельзя удалить старшего администратора', 'error')
        return redirect(url_for('admin_admins'))
    username = target_user.username
    db.session.delete(target_user)
    db.session.commit()
    flash(f'Администратор {username} удалён', 'success')
    return redirect(url_for('admin_admins'))

# ==================== АДМИН-ПАНЕЛЬ: РЕДАКТОР СТАНЦИЙ ====================

@app.route('/admin/edit_stations')
@admin_required
def admin_edit_stations(user):
    content = load_content()
    stations_list = []
    for key, data in content.items():
        station_id = int(key.split('_')[1])
        stations_list.append({
            'key': key,
            'id': station_id,
            'data': data
        })
    stations_list.sort(key=lambda x: x['id'])
    return render_template('admin_edit_stations.html', stations=stations_list, current_user=user)


@app.route('/admin/edit_station/<station_key>', methods=['GET', 'POST'])
@admin_required
def admin_edit_station(user, station_key):
    content = load_content()
    station = content.get(station_key)
    if not station:
        flash('Станция не найдена', 'error')
        return redirect(url_for('admin_edit_stations'))

    if request.method == 'POST':
        action = request.form.get('action', '')

        # ==================== ОБЩИЕ НАСТРОЙКИ СТАНЦИИ ====================
        if action == 'save_settings':
            station['title'] = request.form.get('title', '').strip()
            station['description'] = request.form.get('description', '').strip()
            if 'points' in station:
                station['points'] = int(request.form.get('points', station.get('points', 0)))
            if station.get('type') == 'budget':
                station['min_savings'] = int(request.form.get('min_savings', station.get('min_savings', 800)))
                station['max_income'] = int(request.form.get('max_income', station.get('max_income', 8000)))

        # ==================== СТАНЦИИ С ВОПРОСАМИ (choice_multiple, scammer_quiz, text) ====================
        elif station.get('type') in ('choice_multiple', 'scammer_quiz', 'text'):
            if action == 'add_question':
                if 'questions' not in station:
                    station['questions'] = []
                if station['type'] == 'text':
                    station['questions'].append({
                        'id': len(station['questions']) + 1,
                        'text': 'Новый вопрос',
                        'type': 'text',
                        'keywords': ['ключевое_слово']
                    })
                else:
                    station['questions'].append({
                        'id': len(station['questions']) + 1,
                        'text': 'Новый вопрос',
                        'options': ['Вариант 1', 'Вариант 2'],
                        'correct_answers': ['Вариант 1']
                    })

            elif action == 'save_question':
                q_index = int(request.form.get('question_index'))
                if q_index < len(station['questions']):
                    question = station['questions'][q_index]
                    question['text'] = request.form.get('question_text', '').strip()

                    if station['type'] == 'text':
                        q_type = request.form.get('question_type', 'text')
                        question['type'] = q_type
                        if q_type == 'text':
                            keywords_raw = request.form.get('keywords', '')
                            question['keywords'] = [k.strip() for k in keywords_raw.split(',') if k.strip()]
                        elif q_type == 'choice':
                            options = []
                            opts_count = int(request.form.get('options_count', 0))
                            for i in range(opts_count):
                                opt = request.form.get(f'option_{i}', '').strip()
                                if opt:
                                    options.append(opt)
                            question['options'] = options
                            correct_opt = request.form.get('correct_option', '')
                            if correct_opt and '_' in correct_opt:
                                idx = int(correct_opt.split('_')[1])
                                question['correct_answer'] = options[idx] if idx < len(options) else ''
                            else:
                                question['correct_answer'] = ''
                            question['correct_answers'] = [question['correct_answer']] if question['correct_answer'] else []
                    else:
                        options = []
                        correct_answers = []
                        explanation = request.form.get('explanation', '').strip()
                        opts_count = int(request.form.get('options_count', 0))
                        for i in range(opts_count):
                            opt = request.form.get(f'option_{i}', '').strip()
                            if opt:
                                options.append(opt)
                                if station['type'] == 'choice_multiple':
                                    if request.form.get(f'correct_{i}') == 'on':
                                        correct_answers.append(opt)
                                else:
                                    if request.form.get(f'correct_{i}') == 'on':
                                        correct_answers.append(opt)

                        question['options'] = options

                        if station['type'] == 'choice_multiple':
                            question['correct_answers'] = correct_answers
                            question['max_selections'] = max(1, len(correct_answers))
                        elif station['type'] == 'scammer_quiz':
                            correct_opt = request.form.get('correct_option', '')
                            if correct_opt and '_' in correct_opt:
                                idx = int(correct_opt.split('_')[1])
                                question['correct_answer'] = options[idx] if idx < len(options) else ''
                            else:
                                question['correct_answer'] = ''
                            question['correct_answers'] = [question['correct_answer']] if question['correct_answer'] else []
                            if explanation:
                                question['explanation'] = explanation

            elif action == 'delete_question':
                q_index = int(request.form.get('question_index'))
                if q_index < len(station['questions']):
                    station['questions'].pop(q_index)
                    for i, q in enumerate(station['questions']):
                        q['id'] = i + 1

        # ==================== СТАНЦИЯ 3 QUIZ ====================
        elif station.get('type') == 'quiz':
            if action == 'add_round':
                if 'rounds' not in station:
                    station['rounds'] = []
                station['rounds'].append({
                    'id': len(station['rounds']) + 1,
                    'name': f'Раунд {len(station["rounds"]) + 1}',
                    'description': '',
                    'questions': []
                })

            elif action == 'delete_round':
                round_index = int(request.form.get('round_index'))
                if round_index < len(station['rounds']):
                    station['rounds'].pop(round_index)
                    for i, r in enumerate(station['rounds']):
                        r['id'] = i + 1

            elif action == 'save_round':
                round_index = int(request.form.get('round_index'))
                if round_index < len(station['rounds']):
                    station['rounds'][round_index]['name'] = request.form.get('round_name', '').strip()
                    station['rounds'][round_index]['description'] = request.form.get('round_description', '').strip()

            elif action == 'add_round_question':
                round_index = int(request.form.get('round_index'))
                if round_index < len(station['rounds']):
                    round_data = station['rounds'][round_index]
                    if round_data.get('id') == 3:
                        round_data['questions'].append({
                            'id': len(round_data['questions']) + 1,
                            'text': 'Новый ребус',
                            'image': '',
                            'hint': '',
                            'correct_answers': ['ответ']
                        })
                    else:
                        round_data['questions'].append({
                            'id': len(round_data['questions']) + 1,
                            'text': 'Новый вопрос',
                            'options': ['Вариант 1', 'Вариант 2'],
                            'correct_answer': 'Вариант 1'
                        })

            elif action == 'save_round_question':
                round_index = int(request.form.get('round_index'))
                question_index = int(request.form.get('question_index'))
                if round_index < len(station['rounds']):
                    round_data = station['rounds'][round_index]
                    if question_index < len(round_data['questions']):
                        question = round_data['questions'][question_index]
                        question['text'] = request.form.get('question_text', '').strip()
                        if round_data.get('id') == 3:
                            question['image'] = request.form.get('image', '').strip()
                            question['hint'] = request.form.get('hint', '').strip()
                            answers_raw = request.form.get('correct_answers', '')
                            question['correct_answers'] = [a.strip() for a in answers_raw.split(',') if a.strip()]
                        else:
                            options = []
                            opts_count = int(request.form.get('options_count', 0))
                            for i in range(opts_count):
                                opt = request.form.get(f'option_{i}', '').strip()
                                if opt:
                                    options.append(opt)
                            question['options'] = options
                            correct_opt = request.form.get('correct_option', '')
                            if correct_opt and '_' in correct_opt:
                                idx = int(correct_opt.split('_')[1])
                                question['correct_answer'] = options[idx] if idx < len(options) else ''
                            else:
                                question['correct_answer'] = ''

            elif action == 'delete_round_question':
                round_index = int(request.form.get('round_index'))
                question_index = int(request.form.get('question_index'))
                if round_index < len(station['rounds']):
                    round_data = station['rounds'][round_index]
                    if question_index < len(round_data['questions']):
                        round_data['questions'].pop(question_index)
                        for i, q in enumerate(round_data['questions']):
                            q['id'] = i + 1

        # ==================== СТАНЦИЯ 5 MATCHING_PUZZLE ====================
        elif station.get('type') == 'matching_puzzle':
            if action == 'add_term':
                if 'terms' not in station:
                    station['terms'] = []
                import secrets
                new_id = secrets.token_hex(4)
                station['terms'].append({
                    'id': new_id,
                    'name': 'Новый термин',
                    'correct_definition': 'Новое определение'
                })
                if 'definitions' not in station:
                    station['definitions'] = []
                station['definitions'].append('Новое определение')

            elif action == 'save_term':
                term_index = int(request.form.get('term_index'))
                if term_index < len(station['terms']):
                    term = station['terms'][term_index]
                    old_def = term.get('correct_definition', '')
                    term['name'] = request.form.get('term_name', '').strip()
                    term['correct_definition'] = request.form.get('term_definition', '').strip()
                    new_def = term['correct_definition']
                    if 'definitions' in station:
                        for i, d in enumerate(station['definitions']):
                            if d == old_def:
                                station['definitions'][i] = new_def
                                break

            elif action == 'delete_term':
                term_index = int(request.form.get('term_index'))
                if term_index < len(station['terms']):
                    term = station['terms'].pop(term_index)
                    if 'definitions' in station and term.get('correct_definition') in station['definitions']:
                        station['definitions'].remove(term['correct_definition'])

        # ==================== СТАНЦИЯ 1 BUDGET: ПОЛЯ ====================
        elif station.get('type') == 'budget':
            if action == 'add_field':
                if 'fields' not in station:
                    station['fields'] = []
                station['fields'].append({
                    'name': f'field_{len(station["fields"]) + 1}',
                    'label': 'Новое поле'
                })
            elif action == 'save_field':
                field_index = int(request.form.get('field_index'))
                if field_index < len(station['fields']):
                    station['fields'][field_index]['name'] = request.form.get('field_name', '').strip()
                    station['fields'][field_index]['label'] = request.form.get('field_label', '').strip()
                    station['fields'][field_index]['min'] = int(request.form.get('field_min', 0))
                    station['fields'][field_index]['max'] = int(request.form.get('field_max', 8000))
            elif action == 'delete_field':
                field_index = int(request.form.get('field_index'))
                if field_index < len(station['fields']):
                    station['fields'].pop(field_index)

        # Сохраняем content.json
        with open('content.json', 'w', encoding='utf-8') as f:
            json.dump(content, f, ensure_ascii=False, indent=2)

        flash('Изменения сохранены', 'success')
        return redirect(url_for('admin_edit_station', station_key=station_key))

    return render_template('admin_edit_station.html',
                         station_key=station_key,
                         station=station,
                         current_user=user)

# ==================== АДМИН-ПАНЕЛЬ: ЭКСПОРТ ====================

@app.route('/admin/export_answers/<int:user_id>')
@admin_required
def admin_export_answers(user, user_id):
    """Экспорт ответов конкретного пользователя"""
    target_user = User.query.get_or_404(user_id)
    answers = json.loads(target_user.answers) if target_user.answers else {}
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Ключ', 'Ответ', 'Правильно', 'Детали'])
    
    for key, value in answers.items():
        if isinstance(value, dict):
            writer.writerow([
                key, 
                value.get('answer', ''), 
                'Да' if value.get('is_correct', False) else 'Нет',
                value.get('question', '')
            ])
        else:
            writer.writerow([key, str(value), '-', '-'])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'answers_{target_user.username}.csv'
    )

# Оставлена только ОДНА функция export_csv()
@app.route('/admin/export')
@admin_required
def export_csv(user):
    if not user.is_super_admin:
        flash('У вас нет доступа к экспорту', 'error')
        return redirect(url_for('profile'))
    
    users = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Имя', 'Email', 'Группа', 'Станция', 'Статус', 'Создан', 'Последний вход'])
    
    for u in users:
        writer.writerow([
            u.id, u.username, u.email or '', u.group or '',
            u.current_station, 'Завершено' if u.is_finished else 'В процессе',
            u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else '',
            u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else ''
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='results.csv'
    )

# ==================== АДМИН-ПАНЕЛЬ: ПРИНУДИТЕЛЬНОЕ ПРОХОЖДЕНИЕ СТАНЦИИ ====================

@app.route('/admin/force_complete/<int:user_id>/<int:station_num>', methods=['POST'])
@admin_required
def admin_force_complete(user, user_id, station_num):
    if station_num < 1 or station_num > 6:
        flash('Неверный номер станции', 'error')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    
    target_user = User.query.get_or_404(user_id)
    content = load_content()
    station_key = f"station_{station_num}"
    station_data = content.get(station_key, {})
    answers = json.loads(target_user.answers) if target_user.answers else {}
    
    if station_num == 1:
        answers[station_key] = {
            'food': 2000, 'transport': 1000, 'phone': 500,
            'entertainment': 1000, 'education': 2700, 'savings': 800,
            'total': 8000
        }
    elif station_num == 2:
        questions = station_data.get('questions', [])
        for i, q in enumerate(questions):
            answers[f"{station_key}_q{i}"] = {
                'selected': q.get('correct_answers', []),
                'correct': q.get('correct_answers', []),
                'is_correct': True
            }
    elif station_num == 3:
        rounds = station_data.get('rounds', [])
        for ri, r in enumerate(rounds):
            for qi, q in enumerate(r.get('questions', [])):
                ans = q.get('correct_answer', '') or q.get('correct_answers', [''])[0]
                answers[f"{station_key}_r{ri}_q{qi}"] = {
                    'answer': ans,
                    'is_correct': True
                }
        target_user.station_3_progress = json.dumps({'round': 0, 'question': 0})
    elif station_num == 4:
        questions = station_data.get('questions', [])
        for i, q in enumerate(questions):
            answers[f"{station_key}_q{i}"] = {
                'selected': q.get('correct_answer', ''),
                'correct': q.get('correct_answer', ''),
                'is_correct': True
            }
        answers[f"{station_key}_progress"] = len(questions)
        answers[f"{station_key}_completed"] = True
    elif station_num == 5:
        terms = station_data.get('terms', [])
        for t in terms:
            answers[f"{station_key}_{t['id']}"] = t['correct_definition']
        answers[f"{station_key}_completed"] = True
    elif station_num == 6:
        questions = station_data.get('questions', [])
        for i, q in enumerate(questions):
            kw = q.get('keywords', ['правильно'])
            answers[f"{station_key}_q{i}"] = {
                'question': q['text'],
                'answer': kw[0],
                'is_correct': True
            }
        target_user.is_finished = True
    
    if station_num > target_user.current_station:
        target_user.current_station = station_num
    
    target_user.answers = json.dumps(answers, ensure_ascii=False)
    db.session.commit()
    
    flash(f'Станция {station_num} принудительно пройдена для {target_user.username}', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))


# ==================== ФОРМА ЛИДОВ ====================

@app.route('/submit_lead', methods=['POST'])
@login_required
def submit_lead(user):
    if not user.is_finished:
        flash('Форма доступна только после завершения игры', 'warning')
        return redirect(url_for('dashboard'))
    
    full_name = request.form.get('full_name', '').strip()
    phone = request.form.get('phone', '').strip()
    consent = request.form.get('consent') == 'on'
    
    if not consent:
        flash('Необходимо согласие на обработку персональных данных', 'error')
        return redirect(url_for('result'))
    
    if not full_name or len(full_name) < 2:
        flash('Введите ФИО', 'error')
        return redirect(url_for('result'))
    
    if not phone:
        flash('Введите номер телефона', 'error')
        return redirect(url_for('result'))
    
    digits_only = ''.join(c for c in phone if c.isdigit())
    if len(digits_only) > 11 or len(digits_only) < 10:
        flash('Номер телефона должен содержать 10-11 цифр (с кодом страны)', 'error')
        return redirect(url_for('result'))
    
    existing = Lead.query.filter_by(user_id=user.id).first()
    if existing:
        flash('Вы уже оставляли заявку', 'info')
        return redirect(url_for('result'))
    
    lead = Lead(user_id=user.id)
    lead.set_full_name(full_name)
    lead.set_phone(digits_only)
    lead.consent = True
    db.session.add(lead)
    db.session.commit()
    
    flash('Спасибо! Ваша заявка принята. Мы свяжемся с вами в ближайшее время.', 'success')
    return redirect(url_for('profile'))


# ==================== АДМИН-ПАНЕЛЬ: УПРАВЛЕНИЕ ЛИДАМИ ====================

@app.route('/admin/leads')
@admin_required
def admin_leads(user):
    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    decrypted = []
    for lead in leads:
        u = User.query.get(lead.user_id)
        decrypted.append({
            'id': lead.id,
            'full_name': lead.get_full_name(),
            'phone': lead.get_phone(),
            'consent': lead.consent,
            'created_at': lead.created_at,
            'username': u.username if u else '—'
        })
    return render_template('admin_leads.html', leads=decrypted, current_user=user)


@app.route('/admin/leads/export')
@admin_required
def admin_leads_export(user):
    if not user.is_super_admin:
        flash('Только старший администратор может экспортировать данные', 'error')
        return redirect(url_for('admin_leads'))
    
    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'ФИО', 'Телефон', 'Согласие на обработку', 'Игрок', 'Дата создания'])
    
    for lead in leads:
        u = User.query.get(lead.user_id)
        writer.writerow([
            lead.id,
            lead.get_full_name(),
            lead.get_phone(),
            'Да' if lead.consent else 'Нет',
            u.username if u else '—',
            lead.created_at.strftime('%Y-%m-%d %H:%M') if lead.created_at else ''
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='leads.csv'
    )


def init_admin_account():
    """Автоматически создает администратора при первом запуске.
    Пароль берется из переменных окружения, чтобы не хранить его в коде."""
    with app.app_context():
        # Проверяем, есть ли уже пользователь с именем admin
        existing_admin = User.query.filter_by(username='admin').first()
        
        if not existing_admin:
            # 🔐 БЕЗОПАСНОСТЬ: Пароль читается из переменных окружения ОС
            admin_password = os.environ.get('FINANCIAL_RAID_ADMIN_PASSWORD')
            
            if not admin_password:
                print("⚠️ ОШИБКА: Переменная окружения FINANCIAL_RAID_ADMIN_PASSWORD не установлена.")
                print("   В целях безопасности пароль не должен быть в коде.")
                print("   Установите переменную перед запуском.")
                return

            # Создаем главного администратора
            new_admin = User(
                username='admin',
                email='admin@financial-raid.local',
                group='Administrator'
            )
            new_admin.set_password(admin_password)
            new_admin.is_admin = True
            new_admin.is_super_admin = True
            new_admin.email_verified = True
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Аккаунт главного администратора 'admin' успешно создан!")
        else:
            # Миграция: обновляем флаги для существующих администраторов
            if not existing_admin.is_admin:
                existing_admin.is_admin = True
                existing_admin.is_super_admin = True
                db.session.commit()
                print("✅ Флаги администратора обновлены")
            print("ℹ️ Аккаунт администратора уже существует.")

# ==================== СБРОС КОНКРЕТНОЙ СТАНЦИИ ====================
@app.route('/reset_station/<int:station_num>', methods=['POST'])
@login_required
def reset_station(user, station_num):
    if station_num < 1 or station_num > 6:
        flash('Неверный номер станции', 'error')
        return redirect(url_for('dashboard'))
    
    station_key = f"station_{station_num}"
    answers = json.loads(user.answers) if user.answers else {}
    
    # Удаляем все ответы этой станции
    keys_to_delete = [k for k in list(answers.keys()) if k.startswith(station_key)]
    for key in keys_to_delete:
        del answers[key]
    
    user.answers = json.dumps(answers, ensure_ascii=False)
    
    # Сбрасываем специальный прогресс
    if station_num == 2:
        user.station_2_progress = 0
    elif station_num == 3:
        user.station_3_progress = '{}'
    
    # ИСПРАВЛЕНИЕ: Сбрасываем флаг завершения игры при сбросе ЛЮБОЙ станции
    # Если пользователь сбрасывает любую станцию, игра больше не считается завершённой
    user.is_finished = False
    
    # Устанавливаем текущую станцию
    user.current_station = station_num
    db.session.commit()
    
    flash(f'Прогресс Станции {station_num} сброшен. Можно пройти заново!', 'success')
    return redirect(url_for('station'))  # Важно: redirect на /station, не на /station/{num}

# ==================== ЗАПУСК ПРИЛОЖЕНИЯ ====================
if __name__ == '__main__':
    with app.app_context():
        print("🗄️ [INIT] Creating database tables...")
        db.create_all()
        print("✅ [INIT] Database tables created")
        
        print("🔐 [INIT] Initializing admin account...")
        init_admin_account()
        print("✅ [INIT] Admin account initialized")
    
    import os
    port = int(os.environ.get('PORT', 5000))
    
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print(f"🚀 [START] Starting server on port {port}, debug={debug_mode}")
    app.run(debug=debug_mode, host='0.0.0.0', port=port)