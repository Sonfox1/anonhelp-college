from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'anonhelp_college_secret_key_change_me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///anonhelp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif','pdf','doc','docx','txt'}

db = SQLAlchemy(app)

CATEGORIES = [
    'Психологическая поддержка','Буллинг','Конфликт с преподавателем',
    'Конфликт с одногруппниками','Учебные трудности','Семейные проблемы',
    'Предложение по улучшению колледжа','Взаимопомощь','Другое'
]
STATUSES = ['Новое','В обработке','Ожидает ответа','Решено','Закрыто']
PRIORITIES = ['Обычная','Важная','Срочная']


# Privacy helper: the project stores the account only for login and for showing a student
# their own history. Admin screens never display full name, email, group or username of authors.
def anonymous_label(user_id=None, role='student'):
    if role == 'admin':
        return 'Модератор AnonHelp'
    if not user_id:
        return 'Анонимный студент'
    return f'Анонимный участник #{1000 + int(user_id)}'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=True, unique=True)
    group_name = db.Column(db.String(80), nullable=True)
    about = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    rating = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    appeals = db.relationship('Appeal', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(180), nullable=True)
    is_anonymous = db.Column(db.Boolean, default=True)
    is_public = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(30), default='Новое')
    priority = db.Column(db.String(30), default='Обычная')
    admin_comment = db.Column(db.Text, nullable=True)
    support_count = db.Column(db.Integer, default=0)
    reports_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    comments = db.relationship('Comment', backref='appeal', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    is_anonymous = db.Column(db.Boolean, default=True)
    is_best = db.Column(db.Boolean, default=False)
    helpful_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeal.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    text = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.String(180), nullable=False)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeal.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    appeal_id = db.Column(db.Integer, db.ForeignKey('appeal.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

Appeal.attachments = db.relationship('Attachment', backref='appeal', lazy=True, cascade='all, delete-orphan')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_request_text(text):
    t = (text or '').lower()
    rules = [
        (['буллинг','травл','издева','угрожа','насмеш','унижа'], 'Буллинг', 'Срочная', 'Сохраните доказательства, не отвечайте агрессией, обратитесь к куратору или психологу. Если есть угроза безопасности — сообщите администрации сразу.'),
        (['стресс','паник','депресс','тревог','психолог','страх','устал'], 'Психологическая поддержка', 'Важная', 'Опишите состояние спокойно, укажите, когда началось и какая поддержка нужна. Можно оставить обращение закрытым и анонимным.'),
        (['преподавател','учител','оценк','зачет','экзамен'], 'Конфликт с преподавателем', 'Важная', 'Опишите факты без эмоций: предмет, дата, ситуация, что уже предпринимали.'),
        (['python','код','лаба','домаш','учеб','предмет','практик'], 'Учебные трудности', 'Обычная', 'Укажите предмет, тему и что именно не получается. В сообществе студенты смогут подсказать материалы.'),
        (['группа','одногрупп','конфликт','спор'], 'Конфликт с одногруппниками', 'Важная', 'Опишите ситуацию нейтрально, без фамилий в публичной ленте. При необходимости сделайте обращение закрытым.'),
        (['идея','предлож','улучш','кружок','мероприят'], 'Предложение по улучшению колледжа', 'Обычная', 'Сформулируйте проблему, идею решения и пользу для студентов.'),
    ]
    for keys, cat, pr, plan in rules:
        if any(k in t for k in keys):
            return {'category': cat, 'priority': pr, 'plan': plan}
    return {'category': 'Другое', 'priority': 'Обычная', 'plan': 'Опишите ситуацию подробнее: что произошло, кому нужна помощь, какой результат вы ожидаете.'}

def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None

@app.context_processor
def inject_globals():
    user = current_user()
    unread = Notification.query.filter_by(user_id=user.id, is_read=False).count() if user else 0
    return {'current_user': user, 'categories': CATEGORIES, 'statuses': STATUSES, 'priorities': PRIORITIES, 'unread_count': unread, 'anonymous_label': anonymous_label}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Сначала войдите в систему.', 'error')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Сначала войдите в систему.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('У вас нет доступа к этой странице.', 'error')
            return redirect(url_for('dashboard'))
        return fn(*args, **kwargs)
    return wrapper

def notify(user_id, title, text=''):
    if user_id:
        db.session.add(Notification(user_id=user_id, title=title, text=text))

@app.route('/')
def index():
    stats = {'users': User.query.count(), 'appeals': Appeal.query.count(), 'resolved': Appeal.query.filter_by(status='Решено').count(), 'comments': Comment.query.count()}
    latest = Appeal.query.filter_by(is_public=True).order_by(Appeal.created_at.desc()).limit(5).all()
    return render_template('index.html', stats=stats, latest=latest)

@app.route('/help_center')
def help_center(): return render_template('help_center.html')

@app.route('/route_helper', methods=['GET','POST'])
def route_helper():
    result = None
    text = ''
    if request.method == 'POST':
        text = request.form.get('situation','').strip()
        result = analyze_request_text(text)
    return render_template('route_helper.html', result=result, text=text)

@app.route('/privacy_protocol')
def privacy_protocol():
    return render_template('privacy_protocol.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name','').strip(); username = request.form.get('username','').strip()
        email = request.form.get('email','').strip(); group_name = request.form.get('group_name','').strip()
        password = request.form.get('password',''); confirm = request.form.get('confirm_password','')
        if not full_name or not username or not password:
            flash('Заполните ФИО, логин и пароль.', 'error'); return redirect(url_for('register'))
        if len(password) < 6:
            flash('Пароль должен быть не короче 6 символов.', 'error'); return redirect(url_for('register'))
        if password != confirm:
            flash('Пароли не совпадают.', 'error'); return redirect(url_for('register'))
        q = User.query.filter(User.username == username)
        if email: q = User.query.filter((User.username == username) | (User.email == email))
        if q.first():
            flash('Пользователь с таким логином или почтой уже существует.', 'error'); return redirect(url_for('register'))
        user = User(full_name=full_name, username=username, email=email or None, group_name=group_name or None); user.set_password(password)
        db.session.add(user); db.session.commit()
        flash('Аккаунт создан. Теперь войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip(); password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            session['user_id']=user.id; session['user_name']=user.full_name; session['role']=user.role
            flash('Вы успешно вошли в аккаунт.', 'success')
            return redirect(url_for('admin_panel' if user.role == 'admin' else 'dashboard'))
        flash('Неверный логин или пароль.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); flash('Вы вышли из аккаунта.', 'success'); return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user(); base = Appeal.query.filter_by(user_id=user.id)
    data = {'total': base.count(), 'new': base.filter_by(status='Новое').count(), 'progress': base.filter_by(status='В обработке').count(), 'done': base.filter_by(status='Решено').count(), 'comments': Comment.query.filter_by(user_id=user.id).count()}
    latest_appeals = Appeal.query.filter_by(is_public=True).order_by(Appeal.created_at.desc()).limit(4).all()
    notes = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(4).all()
    return render_template('dashboard.html', data=data, latest_appeals=latest_appeals, notes=notes)

@app.route('/feed')
@login_required
def feed():
    category=request.args.get('category',''); status=request.args.get('status',''); q=request.args.get('q','').strip(); sort=request.args.get('sort','new')
    query=Appeal.query.filter_by(is_public=True)
    if category: query=query.filter_by(category=category)
    if status: query=query.filter_by(status=status)
    if q: query=query.filter((Appeal.title.contains(q)) | (Appeal.message.contains(q)) | (Appeal.tags.contains(q)))
    if sort == 'popular': query=query.order_by(Appeal.support_count.desc(), Appeal.created_at.desc())
    elif sort == 'urgent': query=query.order_by(Appeal.priority.desc(), Appeal.created_at.desc())
    else: query=query.order_by(Appeal.created_at.desc())
    return render_template('feed.html', appeals=query.all(), selected_category=category, selected_status=status, q=q, sort=sort)

@app.route('/new_appeal', methods=['GET','POST'])
@login_required
def new_appeal():
    if request.method == 'POST':
        title=request.form.get('title','').strip(); category=request.form.get('category','').strip(); priority=request.form.get('priority','Обычная')
        message=request.form.get('message','').strip(); tags=request.form.get('tags','').strip(); is_anonymous=True; is_public=request.form.get('is_public')=='on'
        if not title or not category or not message:
            flash('Заполните тему, категорию и текст обращения.', 'error'); return redirect(url_for('new_appeal'))
        appeal=Appeal(title=title, category=category, priority=priority, message=message, tags=tags or None, is_anonymous=True, is_public=is_public, user_id=session['user_id'])
        db.session.add(appeal); db.session.commit()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        for f in request.files.getlist('attachments'):
            if f and f.filename and allowed_file(f.filename):
                safe = secure_filename(f.filename)
                stored = f"appeal_{appeal.id}_{int(datetime.utcnow().timestamp())}_{safe}"
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], stored))
                db.session.add(Attachment(filename=stored, original_name=f.filename, appeal_id=appeal.id))
        notify(session['user_id'], 'Обращение создано', f'Ваше обращение «{title}» принято системой.')
        db.session.commit(); flash('Обращение отправлено. Теперь его можно отслеживать.', 'success')
        return redirect(url_for('appeal_detail', appeal_id=appeal.id))
    return render_template('new_appeal.html')

@app.route('/my_appeals')
@login_required
def my_appeals():
    appeals=Appeal.query.filter_by(user_id=session['user_id']).order_by(Appeal.created_at.desc()).all()
    return render_template('my_appeals.html', appeals=appeals)

@app.route('/appeal/<int:appeal_id>')
@login_required
def appeal_detail(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id)
    if session.get('role')!='admin' and appeal.user_id != session.get('user_id') and not appeal.is_public:
        flash('У вас нет доступа к этому обращению.', 'error'); return redirect(url_for('dashboard'))
    return render_template('appeal_detail.html', appeal=appeal)

@app.route('/appeal/<int:appeal_id>/comment', methods=['POST'])
@login_required
def add_comment(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id); text=request.form.get('text','').strip()
    if not text:
        flash('Комментарий не может быть пустым.', 'error'); return redirect(url_for('appeal_detail', appeal_id=appeal.id))
    c=Comment(text=text, is_anonymous=True, appeal_id=appeal.id, user_id=session['user_id'])
    db.session.add(c)
    if appeal.user_id != session['user_id']:
        notify(appeal.user_id, 'Новый ответ', f'К вашему обращению «{appeal.title}» добавили ответ.')
    db.session.commit(); flash('Комментарий добавлен.', 'success')
    return redirect(url_for('appeal_detail', appeal_id=appeal.id))

@app.route('/appeal/<int:appeal_id>/support', methods=['POST'])
@login_required
def support_appeal(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id); appeal.support_count=(appeal.support_count or 0)+1
    db.session.commit(); flash('Вы поддержали обращение.', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/appeal/<int:appeal_id>/report', methods=['POST'])
@login_required
def report_appeal(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id); reason=request.form.get('reason','Требует проверки')
    appeal.reports_count=(appeal.reports_count or 0)+1
    db.session.add(Report(reason=reason, appeal_id=appeal.id, user_id=session.get('user_id'))); db.session.commit()
    flash('Жалоба отправлена модератору.', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/comment/<int:comment_id>/best', methods=['POST'])
@login_required
def mark_best(comment_id):
    c=Comment.query.get_or_404(comment_id); appeal=c.appeal
    if session.get('role')!='admin' and appeal.user_id != session.get('user_id'):
        abort(403)
    for item in appeal.comments: item.is_best=False
    c.is_best=True
    if c.author:
        c.author.rating=(c.author.rating or 0)+5
        notify(c.author.id, 'Ваш ответ отмечен лучшим', f'По обращению «{appeal.title}».')
    db.session.commit(); flash('Лучший ответ отмечен.', 'success')
    return redirect(url_for('appeal_detail', appeal_id=appeal.id))

@app.route('/comment/<int:comment_id>/helpful', methods=['POST'])
@login_required
def helpful_comment(comment_id):
    c=Comment.query.get_or_404(comment_id); c.helpful_count=(c.helpful_count or 0)+1
    if c.author: c.author.rating=(c.author.rating or 0)+1
    db.session.commit(); flash('Спасибо за оценку ответа.', 'success')
    return redirect(url_for('appeal_detail', appeal_id=c.appeal_id))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user=current_user()
    if request.method == 'POST':
        user.full_name=request.form.get('full_name', user.full_name).strip() or user.full_name
        user.email=request.form.get('email','').strip() or None; user.group_name=request.form.get('group_name','').strip() or None; user.about=request.form.get('about','').strip() or None
        db.session.commit(); flash('Профиль обновлён.', 'success'); return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/notifications')
@login_required
def notifications():
    notes=Notification.query.filter_by(user_id=session['user_id']).order_by(Notification.created_at.desc()).all()
    for n in notes: n.is_read=True
    db.session.commit()
    return render_template('notifications.html', notes=notes)

@app.route('/stats')
@login_required
def stats():
    category_stats=[(c, Appeal.query.filter_by(category=c).count()) for c in CATEGORIES]
    status_stats=[(s, Appeal.query.filter_by(status=s).count()) for s in STATUSES]
    max_cat=max([x[1] for x in category_stats]+[1]); max_status=max([x[1] for x in status_stats]+[1])
    leaders=User.query.filter_by(role='student').order_by(User.rating.desc()).limit(8).all()
    return render_template('stats.html', category_stats=category_stats, status_stats=status_stats, max_cat=max_cat, max_status=max_status, leaders=leaders)

@app.route('/appeal/<int:appeal_id>/solve', methods=['POST'])
@login_required
def solve_appeal(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id)
    if session.get('role')!='admin' and appeal.user_id != session.get('user_id'):
        abort(403)
    appeal.status='Решено'
    notify(appeal.user_id, 'Обращение отмечено решённым', f'«{appeal.title}» закрыто как решённое.')
    db.session.commit(); flash('Обращение отмечено как решённое.', 'success')
    return redirect(url_for('appeal_detail', appeal_id=appeal.id))

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
@admin_required
def admin_panel():
    category=request.args.get('category',''); status=request.args.get('status',''); q=request.args.get('q','').strip()
    query=Appeal.query
    if category: query=query.filter_by(category=category)
    if status: query=query.filter_by(status=status)
    if q: query=query.filter((Appeal.title.contains(q)) | (Appeal.message.contains(q)))
    appeals=query.order_by(Appeal.created_at.desc()).all(); users=User.query.order_by(User.created_at.desc()).all(); reports=Report.query.order_by(Report.created_at.desc()).limit(10).all()
    category_stats=[(c, Appeal.query.filter_by(category=c).count()) for c in CATEGORIES]; status_stats=[(s, Appeal.query.filter_by(status=s).count()) for s in STATUSES]
    max_cat=max([x[1] for x in category_stats]+[1])
    return render_template('admin.html', appeals=appeals, users=users, reports=reports, category_stats=category_stats, status_stats=status_stats, max_cat=max_cat, selected_category=category, selected_status=status, q=q)

@app.route('/admin/update/<int:appeal_id>', methods=['POST'])
@admin_required
def update_appeal(appeal_id):
    appeal=Appeal.query.get_or_404(appeal_id); old=appeal.status
    appeal.status=request.form.get('status', appeal.status); appeal.priority=request.form.get('priority', appeal.priority); appeal.admin_comment=request.form.get('admin_comment','').strip()
    if old != appeal.status:
        notify(appeal.user_id, 'Статус обращения изменён', f'«{appeal.title}»: {old} → {appeal.status}')
    db.session.commit(); flash('Обращение обновлено.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    user=User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Главного администратора нельзя отключить.', 'error')
    else:
        user.is_active=not user.is_active; db.session.commit(); flash('Статус пользователя обновлён.', 'success')
    return redirect(url_for('admin_panel'))

def seed():
    if not User.query.filter_by(username='admin').first():
        admin=User(full_name='Администратор системы', username='admin', email='admin@anonhelp.local', role='admin', group_name='Администрация'); admin.set_password('admin123'); db.session.add(admin)
    if not User.query.filter_by(username='student').first():
        student=User(full_name='Демо Студент', username='student', email='student@anonhelp.local', group_name='ИС-22'); student.set_password('student123'); db.session.add(student); db.session.commit()
        a=Appeal(title='Нужна помощь с подготовкой к экзамену', category='Учебные трудности', message='Не понимаю несколько тем по программированию. Буду благодарен за советы и материалы.', tags='python, экзамен', is_anonymous=True, is_public=True, user_id=student.id)
        db.session.add(a); db.session.commit()
    db.session.commit()

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all(); seed()
    app.run(debug=True)
