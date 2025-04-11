import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, send_file, g, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, validate_csrf, CSRFError
from urllib.parse import urlparse, urlunparse, unquote
from contextlib import closing
import sqlite3
import secrets
import datetime
import io
import sys
import pandas as pd
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
csrf = CSRFProtect(app)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_prefix=1
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

WEBHOOK_SECRET = b'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4'

class Config:
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance', 'project_files')
    DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'supervision.db')
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'  # 使用固定密钥或确保环境变量设置

    @classmethod
    def init(cls):
        os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
        db_dir = os.path.dirname(cls.DATABASE_PATH)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, mode=0o755, exist_ok=True)

Config.init()

app.config.update(
    SECRET_KEY=Config.SECRET_KEY,
    DATABASE=Config.DATABASE_PATH,
    UPLOAD_FOLDER=Config.UPLOAD_FOLDER,
    WTF_CSRF_TIME_LIMIT=7200,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    WTF_CSRF_SSL_STRICT=False,
    MAX_CONTENT_LENGTH=100 * 1024 * 1024
)

def get_db():
    if not hasattr(g, '_database'):
        try:
            g._database = sqlite3.connect(app.config['DATABASE'])
            g._database.row_factory = sqlite3.Row
            init_sqlite_schema(g._database)
        except sqlite3.Error as e:
            print(f"数据库连接失败: {str(e)}")
            raise
    return g._database

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def init_sqlite_schema(conn):
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                phone TEXT,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS unfinished_projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                project_name TEXT NOT NULL,
                main_work TEXT NOT NULL,
                work_goal TEXT NOT NULL,
                completion_time DATE NOT NULL,
                responsible_person_id INTEGER REFERENCES users(id),
                responsible_department TEXT NOT NULL,
                collaborator TEXT,
                collaborating_department TEXT,
                responsible_leader_id INTEGER REFERENCES users(id),
                is_finished INTEGER DEFAULT 0 CHECK(is_finished IN (0, 1)),
                completion_status_1 TEXT,
                completion_status_2 TEXT,
                completion_status_3 TEXT,
                completion_status_4 TEXT,
                completion_status_5 TEXT,
                completion_status_6 TEXT,
                completion_status_7 TEXT,
                completion_status_8 TEXT,
                completion_status_9 TEXT,
                completion_status_10 TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS finished_projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_id INTEGER,
                category TEXT NOT NULL,
                project_name TEXT NOT NULL,
                main_work TEXT NOT NULL,
                work_goal TEXT NOT NULL,
                completion_time DATE NOT NULL,
                responsible_person_id INTEGER REFERENCES users(id),
                responsible_department TEXT NOT NULL,
                collaborator TEXT,
                collaborating_department TEXT,
                responsible_leader_id INTEGER REFERENCES users(id),
                completion_status_1 TEXT,
                completion_status_2 TEXT,
                completion_status_3 TEXT,
                completion_status_4 TEXT,
                completion_status_5 TEXT,
                completion_status_6 TEXT,
                completion_status_7 TEXT,
                completion_status_8 TEXT,
                completion_status_9 TEXT,
                completion_status_10 TEXT,
                completion_time_finished DATE,
                final_summary TEXT,
                summary_status TEXT CHECK(summary_status IN ('pending', 'approved', 'rejected')),
                summary_submitted_at TIMESTAMP,
                summary_reviewed_at TIMESTAMP,
                review_comment TEXT
            )
        ''')

        admin_exists = conn.execute(
            "SELECT id FROM users WHERE username = 'admin'"
        ).fetchone()

        if not admin_exists:
            hashed_pw = generate_password_hash('admin123gg')
            conn.execute(
                '''
                INSERT INTO users (username, password, phone, is_admin)
                VALUES (?, ?, ?, 1)
                ''',
                ('admin', hashed_pw, '13800138000')
            )

        conn.commit()

    except sqlite3.Error as e:
        print(f'数据库初始化失败: {str(e)}')
        conn.rollback()
        raise  
    except Exception as e:
        print(f'系统错误: {str(e)}')
        conn.rollback()
        raise

def format_datetime(value, format='%Y-%m-%d'):
    if isinstance(value, str):
        try:
            date_obj = datetime.datetime.strptime(value, '%Y-%m-%d')
            return date_obj.strftime(format)
        except ValueError:
            return value
    elif isinstance(value, datetime.date):
        return value.strftime(format)
    return value

app.jinja_env.filters['dateformat'] = format_datetime
app.jinja_env.globals.update(enumerate=enumerate, datetime=datetime)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/webhook', methods=['POST'])
@csrf.exempt
def webhook_handler():
    try:
        data = request.get_json()
        
        if not data:
            app.logger.error("Webhook received empty payload")
            return jsonify({"status": "error", "message": "Empty payload"}), 400
            
        app.logger.info(f"Received webhook data: {data}")
        
        event_type = data.get('event')
        if event_type == 'project_updated':
            pass
        elif event_type == 'user_created':
            pass
            
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        app.logger.error(f"Webhook processing failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    current_datetime = datetime.datetime.now()
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            next_url = request.form.get('next', '')
            
            if next_url:
                parsed = urlparse(next_url)
                if parsed.netloc != '' or not parsed.path.startswith('/'):
                    next_url = url_for('index')
                elif '//' in parsed.path:
                    next_url = url_for('index')

            if not username or not password:
                return render_template('login.html', 
                    error='用户名和密码不能为空',
                    current_datetime=current_datetime), 400

            with get_db() as conn:
                c = conn.cursor()
                c.execute(
                    "SELECT id, password, is_admin FROM users WHERE username = ?",
                    (username,)
                )
                user = c.fetchone()
                
                if user and check_password_hash(user['password'], password):
                    session.clear()
                    session['user_id'] = user['id']
                    session['is_admin'] = user['is_admin']
                    session.permanent = True
                    session.modified = True  
                    
                    response = redirect(next_url or url_for('index'))
                    return response
                
            return render_template('login.html', 
                error='用户名或密码错误',
                current_datetime=current_datetime), 401
        
        except sqlite3.Error as e:
            app.logger.error(f"数据库查询错误: {str(e)}")
            return render_template('login.html', 
                error='数据库连接失败，请联系管理员',
                current_datetime=current_datetime), 500
        except Exception as e:
            app.logger.error(f"登录异常: {str(e)}")
            return render_template('login.html', 
                error='登录处理异常，请稍后重试',
                current_datetime=current_datetime), 500
    
    next_url = request.args.get('next', '')
    if next_url:
        parsed = urlparse(next_url)
        if parsed.netloc != '' or not parsed.path.startswith('/'):
            next_url = ''
        elif '//' in parsed.path:
            next_url = ''

    return render_template(
        'login.html', 
        current_datetime=current_datetime, 
        next=next_url
    )

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error.html', message=e.description), 400

@app.route('/')
def index():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', current_datetime=current_datetime)

@app.route('/user_management', methods=['GET', 'POST'])
@admin_required
def user_management():
    current_datetime = datetime.datetime.now()
    error = None
    with get_db() as conn:
        users = []
        if request.method == 'POST':
            try:
                if 'download_users' in request.form:
                    filename = request.form.get('filename', 'users').strip() or 'users'
                    filename += '.xlsx'
                    
                    buffer = io.BytesIO()
                    df = pd.read_sql_query("SELECT * FROM users", conn)
                    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                        df.to_excel(writer, index=False)
                    buffer.seek(0)
                    
                    return send_file(
                        buffer,
                        as_attachment=True,
                        download_name=filename,
                        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    )

                elif 'upload_users' in request.form:
                    file = request.files.get('file')
                    if not file or file.filename == '':
                        flash('没有选择文件', 'error')
                        return redirect(request.url)
                        
                    if not file.filename.lower().endswith(('.xlsx', '.xls')):
                        flash('仅支持Excel文件（.xlsx/.xls）', 'error')
                        return redirect(request.url)

                    df = pd.read_excel(file)
                    required_columns = ['username', 'password']
                    if not all(col in df.columns for col in required_columns):
                        flash('Excel文件必须包含username和password列', 'error')
                        return redirect(request.url)
                        
                    df['password'] = df['password'].apply(
                        lambda x: generate_password_hash(str(x)) if pd.notnull(x) else None
                    )
                    
                    try:
                        df.to_sql('users', conn, if_exists='append', index=False)
                        conn.commit()
                        flash(f'成功上传 {len(df)} 条用户数据', 'success')
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        flash('部分用户名已存在，未插入重复数据', 'error')
                    return redirect(request.url)

                elif 'add_user' in request.form:
                    username = request.form.get('username', '').strip()
                    password = request.form.get('password', '123456').strip()
                    phone = request.form.get('phone', '').strip()
                    is_admin = 1 if request.form.get('is_admin') == '1' else 0

                    if not username or not password:
                        error = "用户名和密码不能为空"
                    else:
                        hashed_pw = generate_password_hash(password)
                        try:
                            conn.execute(
                                "INSERT INTO users (username, password, phone, is_admin) VALUES (?, ?, ?, ?)",
                                (username, hashed_pw, phone, is_admin)
                            )
                            conn.commit()
                        except sqlite3.IntegrityError:
                            error = "用户名已存在"

                elif 'delete_user' in request.form:
                    user_id = request.form.get('user_id')
                    if user_id and user_id != str(session['user_id']):
                        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                        conn.commit()

                elif 'update_user' in request.form:
                    user_id = request.form.get('user_id')
                    password = request.form.get('password', '123456').strip()
                    phone = request.form.get('phone', '').strip()
                    is_admin = 1 if request.form.get('is_admin') == '1' else 0

                    updates = []
                    params = []
                    updates.append("password = ?")
                    params.append(generate_password_hash(password))
                    if phone:
                        updates.append("phone = ?")
                        params.append(phone)
                    updates.append("is_admin = ?")
                    params.append(is_admin)
                    params.append(user_id)

                    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
                    conn.execute(query, params)
                    conn.commit()

            except Exception as e:
                error = str(e)
                flash(f'操作失败: {str(e)}', 'error')
            
        users = conn.execute("SELECT id, username, phone, is_admin FROM users").fetchall()

    return render_template('user_management.html', 
                         users=users, 
                         error=error, 
                         current_datetime=current_datetime)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    error = None
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            if not password:
                password = '123456'  # 设置初始密码
            phone = request.form.get('phone', '').strip()
            is_admin = 1 if request.form.get('is_admin') == '1' else 0

            if not username or not password:
                raise ValueError("用户名和密码不能为空")

            hashed_pw = generate_password_hash(password)
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password, phone, is_admin) VALUES (?, ?, ?, ?)",
                    (username, hashed_pw, phone, is_admin)
                )
                conn.commit()
            return redirect(url_for('user_management', current_datetime=current_datetime))

        except sqlite3.IntegrityError as e:
            error = "用户名已存在"
        except Exception as e:
            error = str(e)

    return render_template('add_user.html', error=error, current_datetime=current_datetime)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    with get_db() as conn:
        if request.method == 'POST':
            try:
                password = request.form.get('password', '').strip()
                if not password:
                    password = '123456'  # 设置初始密码
                phone = request.form.get('phone', '').strip()
                is_admin = 1 if request.form.get('is_admin') == '1' else 0

                updates = []
                params = []
                if password:
                    updates.append("password = ?")
                    params.append(generate_password_hash(password))
                if phone:
                    updates.append("phone = ?")
                    params.append(phone)

                updates.append("is_admin = ?")
                params.append(is_admin)
                params.append(user_id)

                query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
                conn.execute(query, params)
                conn.commit()
                flash('用户信息更新成功', 'success')
                return redirect(url_for('user_management', current_datetime=current_datetime))
            except Exception as e:
                flash(f'更新失败: {str(e)}', 'error')

        user = conn.execute("SELECT id, username, phone, is_admin FROM users WHERE id=?", (user_id,)).fetchone()

    return render_template('edit_user.html', user=user, current_datetime=current_datetime)

@app.route('/download_projects')
def download_projects():
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)
    
    try:
        with get_db() as conn:
            df = pd.read_sql_query('''
                SELECT 
                    fp.category, 
                    fp.project_name, 
                    fp.main_work, 
                    fp.work_goal, 
                    fp.completion_time, 
                    fp.responsible_department,
                    u1.username AS responsible_person,
                    u3.username AS responsible_leader,
                    fp.completion_status_1,
                    fp.completion_status_2,
                    fp.completion_status_3,
                    fp.completion_status_4,
                    fp.completion_status_5,
                    fp.completion_status_6,
                    fp.completion_status_7,
                    fp.completion_status_8,
                    fp.completion_status_9,
                    fp.completion_status_10,
                    fp.completion_time_finished
                FROM finished_projects fp
                LEFT JOIN users u1 ON fp.responsible_person_id = u1.id
                LEFT JOIN users u3 ON fp.responsible_leader_id = u3.id
            ''', conn)
            
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                df.to_excel(writer, index=False)
            buffer.seek(0)
            
            return send_file(
                buffer,
                as_attachment=True,
                download_name=f"projects_export_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.xlsx",
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            
    except Exception as e:
        flash(f'导出失败: {str(e)}', 'error')
        return redirect(url_for('finished_projects'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    with get_db() as conn:
        if request.method == 'POST':
            new_password = request.form.get('password', '').strip()
            if not new_password:
                new_password = '123456'  # 设置初始密码
            phone = request.form.get('phone', '').strip()

            updates = []
            params = []
            if new_password:
                updates.append("password = ?")
                params.append(generate_password_hash(new_password))
            if phone:
                updates.append("phone = ?")
                params.append(phone)

            if updates:
                params.append(session['user_id'])
                query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
                conn.execute(query, params)
                conn.commit()
                flash('个人信息修改成功，3秒后自动返回首页...', 'success')
                return redirect(url_for('index'))

        user = conn.execute(
            "SELECT username, phone FROM users WHERE id=?",
            (session['user_id'],)
        ).fetchone()

    return render_template('profile.html', user=user, current_datetime=current_datetime)

@app.route('/add_project', methods=['GET', 'POST'])
def add_project():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    error = None
    with get_db() as conn:
        users = conn.execute("SELECT id, username FROM users").fetchall()
        if request.method == 'POST':
            try:
                required_fields = [
                    'category', 'project_name', 'main_work', 'work_goal',
                    'completion_time', 'responsible_department'
                ]
                for field in required_fields:
                    if not request.form.get(field, '').strip():
                        raise ValueError(f"{field} 不能为空")

                responsible_person_id = request.form.get('responsible_person_id')
                responsible_leader_id = request.form.get('responsible_leader_id')
                collaborator = request.form.get('collaborator', '').strip()

                conn.execute('''
                    INSERT INTO unfinished_projects (
                        category, project_name, main_work, work_goal,
                        completion_time, responsible_person_id, responsible_department,
                        collaborator, collaborating_department, responsible_leader_id
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                ''', (
                    request.form['category'],
                    request.form['project_name'],
                    request.form['main_work'],
                    request.form['work_goal'],
                    request.form['completion_time'],
                    responsible_person_id,
                    request.form['responsible_department'],
                    collaborator,
                    request.form.get('collaborating_department', ''),
                    responsible_leader_id
                ))
                conn.commit()
                return redirect(url_for('unfinished_projects'))

            except Exception as e:
                error = str(e)

    return render_template('add_project.html', users=users, error=error)

@app.route('/unfinished_projects', methods=['GET', 'POST'])
def unfinished_projects():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    is_admin = session.get('is_admin', 0)
    error = None
    projects = []

    with get_db() as conn:
        try:
            if request.method == 'POST':
                if 'download_projects' in request.form:
                    try:
                        df = pd.read_sql_query("SELECT * FROM unfinished_projects", conn)
                        
                        buffer = io.BytesIO()
                        with pd.ExcelWriter(buffer) as writer:
                            df.to_excel(writer, index=False)
                        buffer.seek(0)
                        
                        filename = request.form.get('filename', 'unfinished_projects').strip() or 'unfinished_projects'
                        filename += '.xlsx'

                        return send_file(
                            buffer,
                            as_attachment=True,
                            download_name=filename,
                            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                        )
                    except Exception as e:
                        flash(f'导出失败: {str(e)}', 'error')
                        return redirect(url_for('unfinished_projects'))

                if 'upload' in request.form:
                    file = request.files['project_file']
                    if file and file.filename.endswith('.xlsx'):
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                        file.save(filepath)
                        flash(f'文件 {file.filename} 上传成功')
                
                if is_admin:
                    if 'delete_project' in request.form:
                        project_id = request.form.get('project_id')
                        if project_id:
                            conn.execute("DELETE FROM unfinished_projects WHERE id=?", (project_id,))
                            conn.commit()
                            flash('项目删除成功', 'success')
                            return redirect(url_for('unfinished_projects'))
                    elif 'update_project' in request.form:
                        project_id = request.form.get('project_id')
                        fields = [
                            'category', 'project_name', 'main_work', 'work_goal',
                            'completion_time', 'responsible_department',
                        ]
                        params = [request.form.get(field, '').strip() for field in fields]
                        responsible_person_id = request.form.get('responsible_person_id')
                        collaborator = request.form.get('collaborator', '').strip()
                        responsible_leader_id = request.form.get('responsible_leader_id')
                        is_finished = 1 if request.form.get('is_finished') == '1' else 0
                        params.extend([
                            responsible_person_id,
                            collaborator,
                            responsible_leader_id,
                            request.form.get('collaborating_department', '').strip(),
                            is_finished,
                            project_id
                        ])
                        conn.execute('''
                            UPDATE unfinished_projects SET
                            category=?, project_name=?, main_work=?, work_goal=?,
                            completion_time=?, responsible_department=?,
                            responsible_person_id=?, collaborator=?, responsible_leader_id=?,
                            collaborating_department=?, is_finished=?
                            WHERE id=?
                        ''', params)
                        conn.commit()
                        if is_finished:
                            project = conn.execute(
                                "SELECT * FROM unfinished_projects WHERE id=?", 
                                (project_id,)
                            ).fetchone()
                            if project:
                                status_fields = [project[i] for i in range(12, 22)]
                                conn.execute('''
                                    INSERT INTO finished_projects (
                                        original_id, category, project_name, main_work,
                                        work_goal, completion_time, responsible_person_id,
                                        responsible_department, collaborator,
                                        collaborating_department, responsible_leader_id,
                                        completion_status_1, completion_status_2, completion_status_3,
                                        completion_status_4, completion_status_5, completion_status_6,
                                        completion_status_7, completion_status_8, completion_status_9,
                                        completion_status_10, completion_time_finished
                                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                                ''', (
                                    project_id, project[1], project[2], project[3],
                                    project[4], project[5], project[6], project[7],
                                    project[8], project[9], project[10],
                                    status_fields[0], status_fields[1], status_fields[2],
                                    status_fields[3], status_fields[4], status_fields[5],
                                    status_fields[6], status_fields[7], status_fields[8],
                                    status_fields[9], datetime.datetime.now().strftime('%Y-%m-%d')
                                ))
                                conn.execute("DELETE FROM unfinished_projects WHERE id=?", (project_id,))
                                conn.commit()
                                flash('项目已标记为完成', 'success')
                                return redirect(url_for('unfinished_projects'))
                    elif 'upload_projects' in request.form:
                        try:
                            if 'file' not in request.files:
                                flash('请选择文件', 'error')
                                return redirect(request.url)
                            
                            file = request.files['file']
                            if file.filename == '':
                                flash('没有选择文件', 'error')
                                return redirect(request.url)

                            if not file.filename.lower().endswith(('.xlsx', '.xls')):
                                flash('仅支持Excel文件（.xlsx/.xls）', 'error')
                                return redirect(request.url)

                            df = pd.read_excel(file, engine='openpyxl')
                            required_columns = [
                                'category', 'project_name', 'main_work', 
                                'work_goal', 'completion_time', 
                                'responsible_department'
                            ]
                            if not all(col in df.columns for col in required_columns):
                                missing = set(required_columns) - set(df.columns)
                                flash(f'缺少必要列：{", ".join(missing)}', 'error')
                                return redirect(request.url)
                            
                            existing = pd.read_sql_query(
                                "SELECT category, project_name, main_work, work_goal FROM unfinished_projects",
                                conn
                            )
                            
                            duplicates = []
                            valid_rows = []
                            
                            for _, row in df.iterrows():
                                key = (
                                    row['category'],
                                    row['project_name'],
                                    row['main_work'],
                                    row['work_goal']
                                )
                                if key in existing.itertuples(index=False, name=None):
                                    duplicates.append(row['project_name'])
                                else:
                                    valid_rows.append(row)
                            
                            if valid_rows:
                                clean_df = pd.DataFrame(valid_rows)
                                clean_df.to_sql(
                                    'unfinished_projects', 
                                    conn, 
                                    if_exists='append', 
                                    index=False
                                )
                                conn.commit()
                            
                            if duplicates:
                                dup_list = ', '.join(set(duplicates[:5])) 
                                flash(f"跳过 {len(duplicates)} 个重复项目（示例：{dup_list}...）", 'warning')
                            else:
                                flash(f'成功导入 {len(valid_rows)} 条数据', 'success')
                            
                        except Exception as e:
                            flash(f'导入失败: {str(e)}', 'error')

            projects = conn.execute('''
                SELECT 
                    up.id,
                    up.category,
                    up.project_name,
                    up.main_work,
                    up.work_goal,
                    up.completion_time,
                    u1.username AS responsible_person,
                    up.responsible_department,
                    up.collaborator,
                    up.collaborating_department,
                    u3.username AS responsible_leader,
                    (CASE WHEN julianday(up.completion_time) < julianday('now') 
                        THEN '逾期' ELSE '进行中' END) AS status
                FROM unfinished_projects up
                LEFT JOIN users u1 ON up.responsible_person_id = u1.id
                LEFT JOIN users u3 ON up.responsible_leader_id = u3.id
                ORDER BY up.category, up.project_name
            ''').fetchall()

        except Exception as e:
            error = str(e)
            flash(f'操作失败: {str(e)}', 'error')

    return render_template('unfinished_projects.html',
                         projects=projects,
                         error=error,
                         is_admin=is_admin,
                         current_date=current_datetime.strftime('%Y-%m-%d'))
                         
@app.route('/project_detail/<int:project_id>', methods=['GET', 'POST'])
def project_detail(project_id):
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    is_admin = session.get('is_admin', 0)
    error = None
    with get_db() as conn:
        try:
            project = conn.execute('''
                SELECT 
                    up.*, 
                    u1.username AS responsible_person_name, 
                    u3.username AS responsible_leader_name,
                    fp.final_summary,
                    fp.summary_status,
                    fp.review_comment,
                    fp.summary_submitted_at,
                    fp.summary_reviewed_at,
                    up.is_finished
                FROM unfinished_projects up
                LEFT JOIN finished_projects fp ON up.id = fp.original_id
                LEFT JOIN users u1 ON up.responsible_person_id = u1.id
                LEFT JOIN users u3 ON up.responsible_leader_id = u3.id
                WHERE up.id = ?
            ''', (project_id,)).fetchone()

            if not project:
                abort(404)

            is_responsible = session['user_id'] == project['responsible_person_id']
            can_edit_summary = is_responsible and project['is_finished']
            can_review = is_admin and project['summary_status'] == 'pending'

            completion_time = datetime.datetime.strptime(project['completion_time'], "%Y-%m-%d").date()
            current_date = current_datetime.date()
            is_finished = project['is_finished']
            status = '已完成' if is_finished else '逾期' if completion_time < current_date else '进行中'

            completion_statuses = []
            for i in range(1, 11):
                status_text = project[f'completion_status_{i}'] if project[f'completion_status_{i}'] else '无'
                completion_statuses.append(status_text)

            if request.method == 'POST':
                if 'submit_progress' in request.form and is_responsible and not is_finished:
                    progress = request.form.get('progress', '').strip()
                    if progress:
                        date = request.form.get('date') or current_datetime.strftime('%Y-%m-%d')
                        progress_with_date = f"{progress} ({date})"
                        for i in range(1, 11):
                            if not project[f'completion_status_{i}']:
                                conn.execute(
                                    f"UPDATE unfinished_projects SET completion_status_{i}=? WHERE id=?",
                                    (progress_with_date, project_id)
                                )
                                conn.commit()
                                flash('进度提交成功', 'success')
                                break
                        else:
                            flash('所有进度位已填满', 'warning')
                    return redirect(url_for('project_detail', project_id=project_id))

                if 'submit_history' in request.form and is_responsible and not is_finished:
                    history_date = request.form.get('history_date', '')
                    history_progress = request.form.get('history_progress', '').strip()
                    if history_date and history_progress:
                        progress_with_date = f"{history_progress} ({history_date})"
                        for i in range(1, 11):
                            if not project[f'completion_status_{i}']:
                                conn.execute(
                                    f"UPDATE unfinished_projects SET completion_status_{i}=? WHERE id=?",
                                    (progress_with_date, project_id)
                                )
                                conn.commit()
                                flash('历史进度补录成功', 'success')
                                break
                        else:
                            flash('所有进度位已填满', 'warning')
                    return redirect(url_for('project_detail', project_id=project_id))

                if ('approve_progress' in request.form or 'reject_progress' in request.form) and is_admin:
                    progress_index = request.form.get('progress_index')
                    comment = request.form.get(f'comment_{progress_index}', '').strip()
                    original_status = project[f'completion_status_{progress_index}']
                    
                    new_status = original_status
                    if 'approve_progress' in request.form:
                        new_status = f"[审核通过] {original_status}"
                        if comment:
                            new_status += f"（备注：{comment}）"
                    elif 'reject_progress' in request.form:
                        new_status = f"[已驳回] {original_status}"
                        if comment:
                            new_status += f"（原因：{comment}）"
                        
                    conn.execute(
                        f"UPDATE unfinished_projects SET completion_status_{progress_index}=? WHERE id=?",
                        (new_status, project_id)
                    )
                    conn.commit()
                    flash('进度审核操作成功', 'success')
                    return redirect(url_for('project_detail', project_id=project_id))

                if 'submit_summary' in request.form and can_edit_summary:
                    summary = request.form.get('final_summary', '').strip()
                    if summary:
                        conn.execute('''
                            INSERT OR REPLACE INTO finished_projects (
                                original_id, final_summary, summary_status, 
                                summary_submitted_at
                            ) VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
                        ''', (project_id, summary))
                        conn.commit()
                        flash('总结已提交，等待审核', 'success')
                    else:
                        flash('总结内容不能为空', 'error')
                    return redirect(url_for('project_detail', project_id=project_id))

                if 'review_summary' in request.form and can_review:
                    action = request.form.get('review_action')
                    comment = request.form.get('review_comment', '').strip()
                    
                    if action == 'reject' and not comment:
                        flash('驳回必须填写意见', 'error')
                        return redirect(url_for('project_detail', project_id=project_id))
                    
                    new_status = 'approved' if action == 'approve' else 'rejected'
                    conn.execute('''
                        UPDATE finished_projects SET 
                            summary_status = ?,
                            review_comment = ?,
                            summary_reviewed_at = CURRENT_TIMESTAMP
                        WHERE original_id = ?
                    ''', (new_status, comment, project_id))
                    conn.commit()
                    flash(f'总结已{"通过" if action == "approve" else "驳回"}', 'success')
                    return redirect(url_for('project_detail', project_id=project_id))

            project_data = {
                'id': project['id'],
                'category': project['category'],
                'project_name': project['project_name'],
                'main_work': project['main_work'],
                'work_goal': project['work_goal'],
                'completion_time': format_datetime(project['completion_time']),
                'responsible_person_id': project['responsible_person_id'], 
                'responsible_person': project['responsible_person_name'],
                'responsible_department': project['responsible_department'],
                'collaborator': project['collaborator'],
                'collaborating_department': project['collaborating_department'],
                'responsible_leader': project['responsible_leader_name'],
                'status': status,
                'is_finished': is_finished,
                'final_summary': project['final_summary'],
                'summary_status': project['summary_status'],
                'review_comment': project['review_comment'],
                'summary_submitted_at': format_datetime(project['summary_submitted_at']),
                'summary_reviewed_at': format_datetime(project['summary_reviewed_at'])
            }

        except sqlite3.Error as e:
            flash(f'数据库错误: {str(e)}', 'error')
            return redirect(url_for('unfinished_projects'))
        except ValueError as e:
            flash(f'日期格式错误: {str(e)}', 'error')
            return redirect(url_for('unfinished_projects'))

    return render_template('project_detail.html',
                           project=project_data,
                           status=status,
                           completion_statuses=completion_statuses,
                           responsible_person_name=project['responsible_person_name'],
                           is_admin=is_admin,
                           current_date=current_datetime.strftime('%Y-%m-%d'),
                           status_labels={
                               'pending': ('待审核', 'warning'),
                               'approved': ('已通过', 'success'),
                               'rejected': ('已驳回', 'danger')
                           })

@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    with get_db() as conn:
        project = conn.execute('''
            SELECT 
                up.*,
                u1.username AS responsible_person_name,
                u3.username AS responsible_leader_name,
                (CASE WHEN julianday(up.completion_time) < julianday('now') 
                      THEN '逾期' ELSE '进行中' END) AS status
            FROM unfinished_projects up
            LEFT JOIN users u1 ON up.responsible_person_id = u1.id
            LEFT JOIN users u3 ON up.responsible_leader_id = u3.id
            WHERE up.id = ?
        ''', (project_id,)).fetchone()

        if not project:
            abort(404)

        users = conn.execute("SELECT id, username FROM users").fetchall()

        if request.method == 'POST':
            try:
                update_data = [
                    request.form['category'],
                    request.form['project_name'],
                    request.form['main_work'],
                    request.form['work_goal'],
                    request.form['completion_time'],
                    request.form['responsible_department'],
                    request.form.get('responsible_person_id'),
                    request.form.get('collaborator', ''),
                    request.form.get('collaborating_department', ''),
                    request.form.get('responsible_leader_id'),
                    *[request.form.get(f'completion_status_{i}', '') for i in range(1, 11)],
                    project_id
                ]

                conn.execute('''
                    UPDATE unfinished_projects SET
                        category = ?,
                        project_name = ?,
                        main_work = ?,
                        work_goal = ?,
                        completion_time = ?,
                        responsible_department = ?,
                        responsible_person_id = ?,
                        collaborator = ?,
                        collaborating_department = ?,
                        responsible_leader_id = ?,
                        completion_status_1 = ?,
                        completion_status_2 = ?,
                        completion_status_3 = ?,
                        completion_status_4 = ?,
                        completion_status_5 = ?,
                        completion_status_6 = ?,
                        completion_status_7 = ?,
                        completion_status_8 = ?,
                        completion_status_9 = ?,
                        completion_status_10 = ?
                    WHERE id = ?
                ''', update_data)
                conn.commit()
                flash('项目更新成功', 'success')
                return redirect(url_for('unfinished_projects'))

            except sqlite3.IntegrityError as e:
                flash(f'数据库完整性错误: {str(e)}', 'error')
            except Exception as e:
                flash(f'更新失败: {str(e)}', 'error')

    project_data = dict(project)
    return render_template('edit_project.html',
                         project=project_data,
                         users=users,
                         current_datetime=current_datetime)

@app.route('/mark_project_finished/<int:project_id>', methods=['POST'])
def mark_project_finished(project_id):
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    current_datetime = datetime.datetime.now()
    try:
        with get_db() as conn:
            project = conn.execute(
                "SELECT * FROM unfinished_projects WHERE id = ?",
                (project_id,)
            ).fetchone()

            if not project:
                flash('项目不存在或已被处理', 'error')
                return redirect(url_for('unfinished_projects'))

            status_fields = [project[f'completion_status_{i}'] for i in range(1, 11)]

            conn.execute('''
                INSERT INTO finished_projects (
                    original_id,
                    category,
                    project_name,
                    main_work,
                    work_goal,
                    completion_time,
                    responsible_person_id,
                    responsible_department,
                    collaborator,
                    collaborating_department,
                    responsible_leader_id,
                    completion_status_1,
                    completion_status_2,
                    completion_status_3,
                    completion_status_4,
                    completion_status_5,
                    completion_status_6,
                    completion_status_7,
                    completion_status_8,
                    completion_status_9,
                    completion_status_10,
                    completion_time_finished
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                project_id,
                project['category'],
                project['project_name'],
                project['main_work'],
                project['work_goal'],
                project['completion_time'],
                project['responsible_person_id'],
                project['responsible_department'],
                project['collaborator'] or '',  # 修复点：直接访问字段并用or处理None值
                project['collaborating_department'] or '',  # 修复点：同上
                project['responsible_leader_id'],
                *status_fields,
                current_datetime.strftime('%Y-%m-%d')
            ))

            conn.execute("DELETE FROM unfinished_projects WHERE id = ?", (project_id,))
            conn.commit()
            flash(f'项目 "{project["project_name"]}" 已成功标记为完成', 'success')
    except sqlite3.Error as e:
        app.logger.error(f"数据库错误: {str(e)}")
        flash(f'数据库错误: {str(e)}', 'error')
    except Exception as e:
        app.logger.error(f"标记完成失败: {str(e)}")
        flash(f'标记完成失败: {str(e)}', 'error')

    return redirect(url_for('unfinished_projects'))

@app.route('/finished_projects', methods=['GET', 'POST'])
def finished_projects():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        flash('请先登录以访问该页面', 'warning')
        return redirect(url_for('login', next=request.url))

    is_admin = session.get('is_admin', 0)
    error = None
    all_entries_sorted = []

    with get_db() as conn:
        try:
            # 获取原始项目数据
            raw_projects = conn.execute('''
                SELECT 
                    fp.id AS project_id,
                    fp.category,
                    fp.project_name,
                    fp.main_work,
                    fp.work_goal,
                    fp.completion_time AS plan_date,
                    u1.username AS responsible_person,
                    fp.responsible_department,
                    fp.collaborator,
                    fp.collaborating_department,
                    u3.username AS responsible_leader,
                    fp.completion_time_finished,
                    CASE 
                        WHEN fp.completion_time_finished > fp.completion_time 
                            THEN '逾期' 
                        ELSE '正常' 
                    END AS status
                FROM finished_projects fp
                LEFT JOIN users u1 ON fp.responsible_person_id = u1.id
                LEFT JOIN users u3 ON fp.responsible_leader_id = u3.id
                ORDER BY fp.category, fp.project_name, fp.main_work
            ''').fetchall()

            # 预处理数据：添加合并信息
            work_groups = {}
            for idx, entry in enumerate(raw_projects):
                work_key = (entry['category'], entry['project_name'], entry['main_work'])
                work_groups.setdefault(work_key, []).append(idx)

            # 转换字典为列表并添加rowspan信息
            all_entries_sorted = [dict(entry) for entry in raw_projects]
            for work_key, indices in work_groups.items():
                first_entry = all_entries_sorted[indices[0]]
                first_entry['main_work_rowspan'] = len(indices)
                for i in indices[1:]:
                    all_entries_sorted[i]['main_work_rowspan'] = 0

            # 添加类别合并信息
            current_category = None
            category_start = 0
            for idx, entry in enumerate(all_entries_sorted):
                if entry['category'] != current_category:
                    if current_category is not None:
                        for i in range(category_start, idx):
                            all_entries_sorted[i]['category_rowspan'] = idx - category_start
                    current_category = entry['category']
                    category_start = idx
            # 处理最后一个类别
            if current_category is not None:
                for i in range(category_start, len(all_entries_sorted)):
                    all_entries_sorted[i]['category_rowspan'] = len(all_entries_sorted) - category_start

        except sqlite3.OperationalError as e:
            flash(f'数据库操作错误: {str(e)}', 'error')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'数据加载失败: {str(e)}', 'error')
            return redirect(url_for('index'))

    return render_template('finished_projects.html',
                         all_entries_sorted=all_entries_sorted,
                         is_admin=is_admin,
                         current_datetime=current_datetime)

@app.route('/delete_finished_project/<int:project_id>', methods=['POST'])
@admin_required
def delete_finished_project(project_id):
    if request.method == 'POST':
        try:
            with get_db() as conn:
                # 检查项目是否存在
                project = conn.execute(
                    "SELECT id FROM finished_projects WHERE id = ?", 
                    (project_id,)
                ).fetchone()
                
                if not project:
                    flash('项目不存在或已被删除', 'error')
                    return redirect(url_for('finished_projects'))

                # 执行删除操作
                conn.execute(
                    'DELETE FROM finished_projects WHERE id = ?', 
                    (project_id,)
                )
                conn.commit()
                flash('已完成项目删除成功', 'success')
        except sqlite3.Error as e:
            flash(f'数据库错误: {str(e)}', 'error')
            app.logger.error(f"删除已完成项目失败: {str(e)}")
        except Exception as e:
            flash(f'删除失败: {str(e)}', 'error')
            app.logger.error(f"删除异常: {str(e)}")
    
    return redirect(url_for('finished_projects'))

@app.route('/finished_project_detail/<int:project_id>', methods=['GET', 'POST'])
def finished_project_detail(project_id):
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    is_admin = session.get('is_admin', 0)
    error = None
    with get_db() as conn:
        try:
            project = conn.execute('''
                SELECT 
                    fp.id,
                    fp.category,
                    fp.project_name,
                    fp.main_work,
                    fp.work_goal,
                    fp.completion_time AS original_completion_time,
                    fp.responsible_person_id,
                    fp.responsible_department,
                    fp.collaborator,
                    fp.collaborating_department,
                    fp.responsible_leader_id,
                    fp.completion_time_finished,
                    fp.final_summary,
                    fp.summary_status,
                    fp.summary_submitted_at,
                    fp.summary_reviewed_at,
                    fp.review_comment,
                    u1.username AS responsible_person,
                    u3.username AS responsible_leader,
                    up.completion_status_1,
                    up.completion_status_2,
                    up.completion_status_3,
                    up.completion_status_4,
                    up.completion_status_5,
                    up.completion_status_6,
                    up.completion_status_7,
                    up.completion_status_8,
                    up.completion_status_9,
                    up.completion_status_10
                FROM finished_projects fp
                LEFT JOIN users u1 ON fp.responsible_person_id = u1.id
                LEFT JOIN users u3 ON fp.responsible_leader_id = u3.id
                LEFT JOIN unfinished_projects up ON fp.original_id = up.id
                WHERE fp.id = ?
            ''', (project_id,)).fetchone()

            if not project:
                abort(404)

            is_responsible = session['user_id'] == project['responsible_person_id']
            can_edit_summary = is_responsible and project['summary_status'] in (None, 'rejected')
            can_review = is_admin and project['summary_status'] == 'pending'

            completion_statuses = []
            for i in range(1, 11):
                status = project[f'completion_status_{i}']
                completion_statuses.append(status if status is not None else "未记录")

            try:
                completion_date = datetime.datetime.strptime(
                    project['completion_time_finished'], "%Y-%m-%d"
                ).date() if project['completion_time_finished'] else None
            except (ValueError, TypeError):
                completion_date = None
                
            current_date = current_datetime.date()
            days_diff = (current_date - completion_date).days if completion_date else 0

            if request.method == 'POST':
                if 'submit_summary' in request.form and can_edit_summary:
                    summary = request.form.get('final_summary', '').strip()
                    if summary:
                        conn.execute('''
                            UPDATE finished_projects SET
                                final_summary = ?,
                                summary_status = 'pending',
                                summary_submitted_at = CURRENT_TIMESTAMP,
                                review_comment = NULL
                            WHERE id = ?
                        ''', (summary, project_id))
                        conn.commit()
                        flash('总结已提交，等待审核', 'success')
                    else:
                        flash('总结内容不能为空', 'error')
                    return redirect(url_for('finished_project_detail', project_id=project_id))

                if 'review_summary' in request.form and can_review:
                    action = request.form.get('review_result')
                    comment = request.form.get('review_comment', '').strip()
                    
                    if action not in ['approved', 'rejected']:
                        flash('无效的审核操作', 'error')
                        return redirect(url_for('finished_project_detail', project_id=project_id))
                    
                    if action == 'rejected' and not comment:
                        flash('驳回必须填写审核意见', 'error')
                        return redirect(url_for('finished_project_detail', project_id=project_id))
                    
                    conn.execute('''
                        UPDATE finished_projects 
                        SET summary_status = ?,
                            review_comment = ?,
                            summary_reviewed_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (action, comment if action == 'rejected' else None, project_id))
                    conn.commit()
                    flash(f'总结已{"通过" if action == "approved" else "驳回"}', 'success')
                    return redirect(url_for('finished_project_detail', project_id=project_id))

            project_data = {
                'id': project['id'],
                'category': project['category'],
                'project_name': project['project_name'],
                'main_work': project['main_work'],
                'work_goal': project['work_goal'],
                'original_completion_time': format_datetime(project['original_completion_time']),
                'responsible_person': project['responsible_person'],
                'responsible_department': project['responsible_department'],
                'collaborator': project['collaborator'],
                'collaborating_department': project['collaborating_department'],
                'responsible_leader': project['responsible_leader'],
                'completion_time_finished': format_datetime(project['completion_time_finished']),
                'final_summary': project['final_summary'],
                'summary_status': project['summary_status'],
                'review_comment': project['review_comment'],
                'summary_submitted_at': format_datetime(project['summary_submitted_at']),
                'summary_reviewed_at': format_datetime(project['summary_reviewed_at']),
                'completion_statuses': completion_statuses,
                'days_since_completion': days_diff,
                'is_overdue': days_diff > 30 and project['summary_status'] != 'approved'
            }

        except sqlite3.Error as e:
            flash(f'数据库错误: {str(e)}', 'error')
            return redirect(url_for('finished_projects'))
        except Exception as e:
            flash(f'数据处理错误: {str(e)}', 'error')
            return redirect(url_for('finished_projects'))

    return render_template(
        'finished_project_detail.html',
        project=project_data,
        is_admin=is_admin,
        is_responsible=is_responsible,
        can_edit_summary=can_edit_summary,
        can_review=can_review,
        current_datetime=current_datetime,
        status_labels={
            'pending': ('待审核', 'warning'),
            'approved': ('已通过', 'success'),
            'rejected': ('已驳回', 'danger')
        },
        overdue_warning=project_data['is_overdue']
    )

@app.route('/edit_finished_project/<int:project_id>', methods=['GET', 'POST'])
def edit_finished_project(project_id):
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)

    with get_db() as conn:
        users = conn.execute("SELECT id, username FROM users").fetchall()
        project = conn.execute('''
            SELECT * FROM finished_projects 
            WHERE id = ?
        ''', (project_id,)).fetchone()

        if not project:
            abort(404)

        if request.method == 'POST':
            try:
                update_data = [
                    request.form['category'],
                    request.form['project_name'],
                    request.form['main_work'], 
                    request.form['work_goal'],  
                    project[5],
                    request.form['responsible_department'],
                    project[6],
                    project[8],
                    project[9],
                    request.form.get('collaborating_department', '').strip(),
                    request.form['completion_time_finished'],
                    project_id
                ]

                conn.execute('''
                    UPDATE finished_projects SET
                        category = ?,
                        project_name = ?,
                        main_work = ?,
                        work_goal = ?,
                        completion_time = ?,
                        responsible_department = ?,
                        responsible_person_id = ?,
                        collaborator = ?,
                        responsible_leader_id = ?,
                        collaborating_department = ?,
                        completion_time_finished = ?
                    WHERE id = ?
                ''', update_data)
                conn.commit()
                flash('项目更新成功', 'success')
                return redirect(url_for('finished_projects'))
            except Exception as e:
                flash(f'更新失败: {str(e)}', 'error')

    return render_template('edit_finished_project.html',
                           project=project,
                           users=users,
                           current_datetime=datetime.datetime.now())

@app.route('/finished_projects/add', methods=['GET', 'POST'])
@admin_required
def add_finished_project():
    current_datetime = datetime.datetime.now()
    error = None
    with get_db() as conn:
        users = conn.execute("SELECT id, username FROM users").fetchall()
        if request.method == 'POST':
            try:
                required_fields = [
                    'category', 'project_name', 'main_work', 'work_goal',
                    'responsible_department', 'completion_time_finished'
                ]
                for field in required_fields:
                    if not request.form.get(field, '').strip():
                        raise ValueError(f"{field.replace('_', ' ')} 不能为空")

                form_data = {
                    'category': request.form['category'],
                    'project_name': request.form['project_name'],
                    'main_work': request.form['main_work'],
                    'work_goal': request.form['work_goal'],
                    'responsible_person_id': request.form.get('responsible_person_id'),
                    'responsible_department': request.form['responsible_department'],
                    'collaborator': request.form.get('collaborator', ''),
                    'collaborating_department': request.form.get('collaborating_department', ''),
                    'responsible_leader_id': request.form.get('responsible_leader_id'),
                    'completion_time_finished': request.form['completion_time_finished'],
                    'completion_time': request.form.get('completion_time', '')
                }

                conn.execute('''
                    INSERT INTO finished_projects (
                        category, project_name, main_work, work_goal,
                        responsible_person_id, responsible_department,
                        collaborator, collaborating_department,
                        responsible_leader_id, completion_time_finished,
                        completion_time
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ''', (
                    form_data['category'],
                    form_data['project_name'],
                    form_data['main_work'],
                    form_data['work_goal'],
                    form_data['responsible_person_id'],
                    form_data['responsible_department'],
                    form_data['collaborator'],
                    form_data['collaborating_department'],
                    form_data['responsible_leader_id'],
                    form_data['completion_time_finished'],
                    form_data['completion_time']
                ))
                conn.commit()
                flash('项目添加成功', 'success')
                return redirect(url_for('finished_projects'))

            except sqlite3.IntegrityError as e:
                error = "数据库操作错误，请检查数据唯一性"
            except Exception as e:
                error = str(e)

    return render_template('add_finished_project.html',
                         users=users,
                         error=error,
                         current_datetime=current_datetime)

@app.route('/all_projects', methods=['GET', 'POST'])
def all_projects():
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    
    query_type = request.args.get('query_type', 'deadline')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    with get_db() as conn:
        base_query = '''
            SELECT 
                up.id,
                up.category,
                up.project_name,
                up.main_work,
                up.work_goal,
                up.completion_time AS plan_date,
                u1.username AS responsible_person,
                up.responsible_department,
                up.collaborator,
                up.collaborating_department,
                u3.username AS responsible_leader,
                CASE 
                    WHEN julianday(up.completion_time) < julianday('now') THEN '逾期'
                    ELSE '进行中' 
                END AS status,
                0 AS is_finished,
                NULL AS completion_time_finished
            FROM unfinished_projects up
            LEFT JOIN users u1 ON up.responsible_person_id = u1.id
            LEFT JOIN users u3 ON up.responsible_leader_id = u3.id
            UNION ALL
            SELECT 
                fp.id,
                fp.category,
                fp.project_name,
                fp.main_work,
                fp.work_goal,
                fp.completion_time AS plan_date,
                u1.username AS responsible_person,
                fp.responsible_department,
                fp.collaborator,
                fp.collaborating_department,
                u3.username AS responsible_leader,
                '已完成' AS status,
                1 AS is_finished,
                fp.completion_time_finished
            FROM finished_projects fp
            LEFT JOIN users u1 ON fp.responsible_person_id = u1.id
            LEFT JOIN users u3 ON fp.responsible_leader_id = u3.id
        '''

        where_clauses = []
        params = []
        if start_date and end_date:
            if query_type == 'deadline':
                where_clauses.append("plan_date BETWEEN ? AND ?")
                params.extend([start_date, end_date])
            elif query_type == 'completion':
                where_clauses.append("completion_time_finished BETWEEN ? AND ?")
                params.extend([start_date, end_date])

        full_query = base_query
        if where_clauses:
            full_query = f"SELECT * FROM ({base_query}) WHERE {' AND '.join(where_clauses)}"

        pagination_query = f'''
            SELECT * FROM ({full_query})
            ORDER BY plan_date ASC 
            LIMIT {per_page} OFFSET {(page - 1) * per_page}
        '''
        projects = conn.execute(pagination_query, params).fetchall()

        count_query = f"SELECT COUNT(*) FROM ({full_query})"
        total = conn.execute(count_query, params).fetchone()[0]

        if request.method == 'POST' and 'export' in request.form:
            try:
                df = pd.read_sql_query(full_query, conn, params=params)
                
                buffer = io.BytesIO()
                with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, 
                              sheet_name='所有项目',
                              columns=['category', 'project_name', 'main_work', 'work_goal',
                                      'plan_date', 'responsible_person', 'responsible_department',
                                      'collaborator', 'collaborating_department', 'responsible_leader',
                                      'status', 'completion_time_finished'],
                              header=['类别', '项目名称', '主要工作', '工作目标', 
                                     '计划完成时间', '责任人', '责任部门',
                                     '配合人', '配合部门', '责任领导', 
                                     '状态', '实际完成时间'])
                buffer.seek(0)
                
                return send_file(
                    buffer,
                    as_attachment=True,
                    download_name=f'all_projects_export_{datetime.datetime.now().strftime("%Y%m%d%H%M")}.xlsx',
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                )
            except Exception as e:
                flash(f'导出失败: {str(e)}', 'error')
                app.logger.error(f"导出错误: {str(e)}")

    return render_template(
        'all_projects.html',
        all_projects=projects,
        current_date=current_date,
        query_type=query_type,
        start_date=start_date,
        end_date=end_date,
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total // per_page) + (1 if total % per_page else 0)
        }
    )

@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    if request.method == 'POST':
        try:
            with get_db() as conn:
                conn.execute('DELETE FROM unfinished_projects WHERE id = ?', (project_id,))
                conn.commit()
            flash('项目删除成功', 'success')
            return redirect(url_for('unfinished_projects'))
        except Exception as e:
            flash(f'删除失败: {str(e)}', 'error')
            return redirect(url_for('unfinished_projects'))

@app.errorhandler(401)
def unauthorized(error):
    flash('会话已过期，请重新登录', 'warning')
    return redirect(url_for('login', next=request.url)), 302

@app.errorhandler(404)
def not_found(error):
    current_datetime = datetime.datetime.now()
    return render_template('error.html', message="页面不存在", current_datetime=current_datetime), 404

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, '_database'):
        g._database.close()

@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    with app.app_context():
        db = get_db()
        init_sqlite_schema(db)
        print(f"Initialized SQLite database: {app.config['DATABASE']}")

if __name__ == '__main__':
    with app.app_context():
        try:
            db = get_db()
            print(f"数据库路径: {app.config['DATABASE']}")
            print("数据库初始化完成")
        except Exception as e:
            print(f"数据库初始化失败: {str(e)}")
            sys.exit(1)
    
    app.run(
        host='0.0.0.0', 
        port=5000,
        debug=False
    )