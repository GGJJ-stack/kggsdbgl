from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, validate_csrf, generate_csrf, CSRFError
from urllib.parse import urlparse, urlunparse, unquote
from contextlib import closing
from urllib.parse import urlparse, unquote, urlunparse
import sqlite3
import os
import secrets
import datetime
import io
import sys
import pandas as pd
import psycopg2
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    abort, flash, send_file, g
)
from flask_wtf.csrf import CSRFProtect, validate_csrf, CSRFError
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
csrf = CSRFProtect(app)

# 阿里云适配配置
class AliCloudConfig:
    # 文件存储路径（阿里云ECS建议使用/home/www作为根目录）
    BASE_DIR = '/home/www/supervision_system'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance/project_files')
    # 数据库SSL配置
    DB_SSL_MODE = 'require'  # 阿里云数据库强制SSL
    DB_SSL_ROOT_CERT = os.path.join(BASE_DIR, 'aliyun_root.crt')  # SSL证书路径

# 确保目录存在
os.makedirs(AliCloudConfig.UPLOAD_FOLDER, exist_ok=True)

app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
app.config.update(
    DATABASE=os.environ.get('DATABASE_URL', 'sqlite:///instance/supervision.db'),
    UPLOAD_FOLDER=AliCloudConfig.UPLOAD_FOLDER,
    WTF_CSRF_TIME_LIMIT=7200,
    # 安全配置
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    WTF_CSRF_ENABLED=True  # 阿里云必须启用CSRF保护
)

def get_db():
    if not hasattr(g, '_database'):
        db_url = app.config['DATABASE']
        
        # 统一处理阿里云数据库连接
        if db_url.startswith('postgres://') or db_url.startswith('postgresql://'):
            try:
                # 强制转换为postgresql://格式
                db_url = db_url.replace("postgres://", "postgresql://", 1)
                
                # 添加SSL参数
                parsed = urlparse(db_url)
                query_params = "sslmode={}&sslrootcert={}".format(
                    AliCloudConfig.DB_SSL_MODE,
                    AliCloudConfig.DB_SSL_ROOT_CERT
                )
                if parsed.query:
                    new_query = f"{parsed.query}&{query_params}"
                else:
                    new_query = query_params
                
                parsed = parsed._replace(query=new_query)
                db_url = urlunparse(parsed)

                # 增强的数据库连接配置
                conn = psycopg2.connect(
                    db_url,
                    connect_timeout=10,
                    keepalives=1,
                    keepalives_idle=30,
                    keepalives_interval=10,
                    keepalives_count=5
                )
                conn.autocommit = False
                g._database = conn
                init_postgres_schema(conn)
                print(f"Successfully connected to Alibaba Cloud PostgreSQL")
                return conn

            except Exception as e:
                print(f"PostgreSQL connection failed: {str(e)}")
                print("Falling back to SQLite...")

        # SQLite回退逻辑（阿里云ECS本地存储）
        sqlite_path = os.path.join(AliCloudConfig.BASE_DIR, 'instance/supervision.db')
        os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
        g._database = sqlite3.connect(sqlite_path)
        g._database.row_factory = sqlite3.Row
        init_sqlite_schema(g._database)
        print(f"Using SQLite database at: {sqlite_path}")
            
    return g._database

def init_postgres_schema(conn):
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                phone TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS unfinished_projects (
                id SERIAL PRIMARY KEY,
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
                is_finished BOOLEAN DEFAULT FALSE,
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

        cur.execute('''
            CREATE TABLE IF NOT EXISTS finished_projects (
                id SERIAL PRIMARY KEY,
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

        try:
            cur.execute("SELECT id FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                hashed_password = generate_password_hash(
                    os.environ.get('ADMIN_PASSWORD', 'admin123gg')
                )
                cur.execute('''
                    INSERT INTO users 
                        (username, password, phone, is_admin)
                    VALUES 
                        (%s, %s, %s, TRUE)
                ''', (
                    'admin',
                    hashed_password,
                    os.environ.get('ADMIN_PHONE', '13800138000')
                ))
            conn.commit()
        except Exception as e:
            print(f'初始化管理员账户失败: {str(e)}')
            conn.rollback()

def init_sqlite_schema(conn):
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
    conn.commit()

    try:
        cursor = conn.cursor()
        admin_exists = cursor.execute(
            "SELECT id FROM users WHERE username = 'admin'"
        ).fetchone()
        
        if not admin_exists:
            hashed_password = generate_password_hash('admin123gg')
            cursor.execute('''
                INSERT INTO users (username, password, phone, is_admin)
                VALUES (?, ?, ?, 1)
            ''', ('admin', hashed_password, '13800138000'))
        conn.commit()
    except Exception as e:
        print(f'初始化管理员账户失败: {str(e)}')
        conn.rollback()

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    current_datetime = datetime.datetime.now()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        next_url = request.form.get('next', '')

        if not username or not password:
            return render_template('login.html', error='用户名和密码不能为空', current_datetime=current_datetime)

        with get_db() as conn:
            c = conn.cursor()
            try:
                c.execute("SELECT id, password, is_admin FROM users WHERE username = ?", (username,))
                user = c.fetchone()
                if user and check_password_hash(user[1], password):
                    session.clear()
                    session['user_id'] = user[0]
                    session['is_admin'] = user[2]
                    return redirect(next_url or url_for('index'))
            except Exception as e:
                print(f"数据库查询错误: {str(e)}")
            return render_template('login.html', error='用户名或密码错误', current_datetime=current_datetime)
    return render_template('login.html', current_datetime=current_datetime)

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
        if request.method == 'POST':
            if 'download_users' in request.form:
                try:
                    validate_csrf(request.form.get('csrf_token'))
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
                except Exception as e:
                    flash(f'生成用户数据失败: {str(e)}', 'error')

            if 'upload_users' in request.form:
                try:
                    validate_csrf(request.form.get('csrf_token'))
                    file = request.files['file']
                    if file.filename == '':
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
                        flash('部分用户名已存在，未插入重复数据', 'error')
                    return redirect(request.url)

                except CSRFError:
                    flash('操作令牌无效，请刷新页面后重试', 'error')
                except Exception as e:
                    flash(f'上传失败: {str(e)}', 'error')

            try:
                if 'add_user' in request.form:
                    username = request.form.get('username', '').strip()
                    password = request.form.get('password', '123456').strip()
                    phone = request.form.get('phone', '').strip()
                    is_admin = 1 if request.form.get('is_admin') == '1' else 0

                    hashed_pw = generate_password_hash(password)
                    conn.execute(
                        "INSERT INTO users (username, password, phone, is_admin) VALUES (?, ?, ?, ?)",
                        (username, hashed_pw, phone, is_admin)
                    )
                    conn.commit()

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

            except sqlite3.IntegrityError as e:
                error = "用户名已存在"
            except Exception as e:
                error = str(e)
            
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
            # 修复SQL查询，添加用户表关联
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


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    current_datetime = datetime.datetime.now()
    session.clear()
    return redirect(url_for('login', current_datetime=current_datetime))


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

            return redirect(url_for('profile', current_datetime=current_datetime))

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
                        validate_csrf(request.form.get('csrf_token'))
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
                        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                        file.save(filepath)
                        flash(f'文件 {file.filename} 上传成功')
                
                if is_admin:
                    if 'delete_project' in request.form:
                        project_id = request.form.get('project_id')
                        if project_id:
                            conn.execute("DELETE FROM unfinished_projects WHERE id=?", (project_id,))
                            conn.commit()
                    elif 'update_project' in request.form:
                        if not validate_csrf(request.form.get('csrf_token')):
                            abort(403)
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
                    elif 'upload_projects' in request.form:
                        try:
                            validate_csrf(request.form.get('csrf_token'))
                            if 'file' not in request.files:
                                flash('请选择要上传的文件', 'error')
                                return redirect(url_for('unfinished_projects'))
                            
                            file = request.files['file']
                            if file.filename == '':
                                flash('没有选择文件', 'error')
                                return redirect(url_for('unfinished_projects'))
                            
                            if not file.filename.lower().endswith(('.xlsx', '.xls')):
                                flash('仅支持Excel文件（.xlsx/.xls）', 'error')
                                return redirect(url_for('unfinished_projects'))

                            # 读取并校验Excel文件
                            df = pd.read_excel(file, engine='openpyxl')
                            df.columns = df.columns.str.strip().str.lower()
                            
                            # 校验必要列
                            required_columns = [
                                'category', 'project_name', 'main_work', 
                                'work_goal', 'completion_time', 
                                'responsible_department'
                            ]
                            if not all(col in df.columns for col in required_columns):
                                missing = set(required_columns) - set(df.columns)
                                flash(f'缺少必要列：{", ".join(missing)}', 'error')
                                return redirect(url_for('unfinished_projects'))
                            
                            # 处理分类映射
                            valid_categories = [row[0] for row in 
                                conn.execute("SELECT DISTINCT category FROM unfinished_projects").fetchall()]
                            category_mapping = {
                                c.strip().replace(' ', '').lower(): c 
                                for c in valid_categories
                            }
                            
                            invalid_categories = []
                            corrected = 0
                            
                            for idx, row in df.iterrows():
                                original_category = str(row.get('category', '')).strip()
                                original_category = ' '.join(original_category.split())
                                normalized = original_category.replace(' ', '').lower()
                                
                                matched = category_mapping.get(normalized, None)
                                
                                if not matched:
                                    invalid_categories.append(f"第{idx+2}行: {original_category}")
                                else:
                                    if original_category != matched:
                                        df.at[idx, 'category'] = matched
                                        corrected += 1
                            
                            if invalid_categories:
                                sample_errors = invalid_categories[:3]
                                flash(f"发现{len(invalid_categories)}个无效分类，示例：{', '.join(sample_errors)}", 'error')
                                return redirect(url_for('unfinished_projects'))
                            
                            # 检查重复数据
                            existing = pd.read_sql_query(
                                "SELECT category, project_name, main_work, work_goal FROM unfinished_projects",
                                conn
                            )
                            existing_tuples = set(existing.itertuples(index=False, name=None))
                            
                            duplicates = []
                            valid_rows = []
                            
                            for _, row in df.iterrows():
                                key = (
                                    row['category'],
                                    row['project_name'],
                                    row['main_work'],
                                    row['work_goal']
                                )
                                if key in existing_tuples:
                                    duplicates.append(row['project_name'])
                                else:
                                    valid_rows.append(row)
                            
                            # 插入有效数据
                            if valid_rows:
                                clean_df = pd.DataFrame(valid_rows)
                                clean_df.to_sql(
                                    'unfinished_projects', 
                                    conn, 
                                    if_exists='append', 
                                    index=False
                                )
                                conn.commit()
                            
                            # 生成反馈信息
                            if corrected > 0:
                                msg = f"成功导入 {len(valid_rows)} 条数据"
                                if duplicates:
                                    dup_list = ', '.join(set(duplicates[:5])) 
                                    msg += f"，跳过 {len(duplicates)} 个重复项目（示例：{dup_list}...）"
                                flash(msg, 'success' if valid_rows else 'warning')
                            
                        except Exception as e:
                            flash(f'导入失败: {str(e)}', 'error')
                            return redirect(url_for('unfinished_projects'))

            # 保持原有数据库查询
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
            # 获取项目完整信息（包含关联用户和状态）
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

            # 权限验证
            is_responsible = session['user_id'] == project['responsible_person_id']
            can_edit_summary = is_responsible and project['is_finished']
            can_review = is_admin and project['summary_status'] == 'pending'

            # 状态计算
            completion_time = datetime.datetime.strptime(project['completion_time'], "%Y-%m-%d").date()
            current_date = current_datetime.date()
            is_finished = project['is_finished']
            status = '已完成' if is_finished else '逾期' if completion_time < current_date else '进行中'

            # 处理进度状态
            completion_statuses = []
            for i in range(1, 11):
                status_text = project[f'completion_status_{i}'] if project[f'completion_status_{i}'] else '无'
                completion_statuses.append(status_text)

            # POST请求处理
            if request.method == 'POST':
                validate_csrf(request.form.get('csrf_token'))
                
                # 提交新进度（责任人）
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

                # 提交历史进度（责任人）
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

                # 审核进度（管理员）
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

                # 提交总结（责任人）
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

                # 审核总结（管理员）
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

            # 准备模板数据
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
        # 获取未完成项目详情（修复后的SQL查询）
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
                validate_csrf(request.form.get('csrf_token'))
                
                # 收集更新数据（仅限未完成项目字段）
                update_data = [
                    request.form['category'],
                    request.form['project_name'],
                    request.form['main_work'],
                    request.form['work_goal'],
                    request.form['completion_time'],
                    request.form['responsible_department'],
                    request.form['responsible_person_id'],
                    request.form.get('collaborator', ''),
                    request.form.get('collaborating_department', ''),
                    request.form['responsible_leader_id'],
                    *[request.form.get(f'completion_status_{i}', '') for i in range(1, 11)],  # 10个进度状态
                    project_id
                ]

                # 更新未完成项目表
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

    # 准备表单数据（使用未完成项目字段）
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
        validate_csrf(request.form.get('csrf_token'))
        with get_db() as conn:
            # 获取未完成项目完整数据
            project = conn.execute(
                "SELECT * FROM unfinished_projects WHERE id = ?",
                (project_id,)
            ).fetchone()

            if not project:
                flash('项目不存在或已被处理', 'error')
                return redirect(url_for('unfinished_projects'))

            # 提取完成状态字段（索引12-21对应completion_status_1到10）
            status_fields = [project[i] if project[i] else '' for i in range(12, 22)]

            # 插入到已完成项目表（严格匹配字段顺序）
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
                ) VALUES (
                    ?,?,?,?,?,?,?,?,?,?,?,  -- 前11个基础字段
                    ?,?,?,?,?,?,?,?,?,?,?   -- 10个状态字段 + 完成时间
                )
            ''', (
                project_id,                # original_id
                project[1],                # category
                project[2],                # project_name
                project[3],                # main_work
                project[4],                # work_goal
                project[5],                # completion_time (原计划时间)
                project[6],                # responsible_person_id
                project[7],                # responsible_department
                project[8],                # collaborator
                project[9],                # collaborating_department
                project[10],               # responsible_leader_id
                *status_fields,            # 展开10个状态字段
                current_datetime.strftime('%Y-%m-%d')  # 实际完成时间
            ))

            # 从未完成表中删除
            conn.execute("DELETE FROM unfinished_projects WHERE id = ?", (project_id,))
            conn.commit()

            flash(f'项目 "{project[2]}" 已成功标记为完成', 'success')
    except sqlite3.IntegrityError as e:
        flash(f'数据库完整性错误: {str(e)}', 'error')
    except Exception as e:
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

    try:
        with get_db() as conn:
            if request.method == 'POST':
                try:
                    validate_csrf(request.form.get('csrf_token'))
                    
                    # 管理员删除项目
                    if 'delete_project' in request.form and is_admin:
                        project_id = request.form.get('project_id')
                        if project_id:
                            conn.execute("DELETE FROM finished_projects WHERE id=?", (project_id,))
                            conn.commit()
                            flash('项目删除成功', 'success')
                            return redirect(url_for('finished_projects'))

                    # Excel上传处理
                    if 'upload_projects' in request.form and is_admin:
                        if 'file' in request.files:
                            file = request.files['file']
                            if file and file.filename.endswith('.xlsx'):
                                try:
                                    # 获取有效分类列表
                                    valid_categories = [row[0] for row in 
                                        conn.execute("SELECT DISTINCT category FROM finished_projects").fetchall()]
                                    
                                    # 构建分类映射字典
                                    category_mapping = {c.replace(' ', '').lower(): c for c in valid_categories}
                                    
                                    # 读取Excel文件
                                    df = pd.read_excel(file, engine='openpyxl')
                                    
                                    # 必填字段校验
                                    required_columns = [
                                        'category', 'project_name', 'main_work', 'work_goal',
                                        'completion_time', 'responsible_department',
                                        'completion_time_finished', 'responsible_person_id'
                                    ]
                                    if not all(col in df.columns for col in required_columns):
                                        missing = set(required_columns) - set(df.columns)
                                        flash(f'Excel文件缺少必要列：{", ".join(missing)}', 'error')
                                        return redirect(url_for('finished_projects'))
                                    
                                    # 分类名称匹配校验
                                    df['valid_category'] = df['category'].apply(
                                        lambda x: category_mapping.get(str(x).replace(' ', '').lower(), None)
                                    )
                                    invalid_categories = df[df['valid_category'].isnull()]
                                    if not invalid_categories.empty:
                                        sample_errors = invalid_categories.head(3).apply(
                                            lambda r: f"第{r.name+2}行: {r['category']}", axis=1
                                        ).tolist()
                                        flash(f"发现{len(invalid_categories)}个无效分类，示例：{', '.join(sample_errors)}", 'error')
                                        return redirect(url_for('finished_projects'))
                                    
                                    # 使用映射后的分类名称
                                    df['category'] = df['valid_category']
                                    df = df.drop(columns=['valid_category'])
                                    
                                    # 日期格式转换
                                    try:
                                        date_columns = ['completion_time', 'completion_time_finished']
                                        for col in date_columns:
                                            df[col] = pd.to_datetime(df[col], errors='coerce').dt.strftime('%Y-%m-%d')
                                            if df[col].isnull().any():
                                                raise ValueError(f"{col}列包含无效日期格式")
                                    except Exception as e:
                                        flash(f'日期处理错误: {str(e)}', 'error')
                                        return redirect(url_for('finished_projects'))
                                    
                                    # 数据去重检查
                                    existing = pd.read_sql_query('''
                                        SELECT category, project_name, main_work, work_goal 
                                        FROM finished_projects
                                    ''', conn)
                                    
                                    # 合并新旧数据去重
                                    combined = pd.concat([existing, df], ignore_index=True)
                                    duplicates = combined.duplicated(
                                        subset=['category', 'project_name', 'main_work', 'work_goal'],
                                        keep='first'
                                    )
                                    new_records = df[~duplicates[len(existing):]]
                                    
                                    # 数据库写入
                                    if not new_records.empty:
                                        try:
                                            new_records.to_sql(
                                                'finished_projects', 
                                                conn, 
                                                if_exists='append', 
                                                index=False,
                                                dtype={
                                                    'responsible_person_id': Integer,
                                                    'responsible_leader_id': Integer
                                                }
                                            )
                                            conn.commit()
                                            success_count = len(new_records)
                                            dup_count = len(df) - success_count
                                            flash_msg = f"成功导入 {success_count} 条数据"
                                            if dup_count > 0:
                                                flash_msg += f"，跳过 {dup_count} 个重复项目"
                                            flash(flash_msg, 'success')
                                        except Exception as e:
                                            conn.rollback()
                                            flash(f'数据库写入失败: {str(e)}', 'error')
                                    else:
                                        flash('没有需要导入的新数据', 'warning')

                                except Exception as e:
                                    flash(f'文件处理失败: {str(e)}', 'error')

                    # Excel导出处理
                    if 'download_projects' in request.form:
                        df = pd.read_sql_query("""
                            SELECT 
                                category, project_name, main_work, work_goal,
                                completion_time, responsible_department,
                                collaborator, collaborating_department,
                                completion_time_finished
                            FROM finished_projects
                        """, conn)
                        
                        # 生成Excel
                        buffer = io.BytesIO()
                        with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                            df.to_excel(writer, index=False)
                        buffer.seek(0)
                        
                        filename = f"已完成项目_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.xlsx"
                        return send_file(
                            buffer,
                            as_attachment=True,
                            download_name=filename,
                            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                        )

                except ValidationError:
                    flash('操作令牌已失效，请刷新页面后重试', 'error')
                    return redirect(url_for('finished_projects'))

            # 数据查询与预处理
            raw_projects = conn.execute('''
                SELECT 
                    fp.id,
                    fp.category,
                    fp.project_name,
                    fp.main_work,
                    fp.work_goal,
                    fp.completion_time,
                    u1.username AS responsible_person,
                    fp.responsible_department,
                    fp.collaborator,
                    fp.collaborating_department,
                    u3.username AS responsible_leader,
                    fp.completion_time_finished,
                    (CASE WHEN fp.completion_time_finished > fp.completion_time 
                        THEN '逾期' ELSE '正常' END) AS status
                FROM finished_projects fp
                LEFT JOIN users u1 ON fp.responsible_person_id = u1.id
                LEFT JOIN users u3 ON fp.responsible_leader_id = u3.id
                ORDER BY fp.category, fp.project_name, fp.main_work
            ''').fetchall()

            # 转换为扁平列表并排序
            all_entries = []
            for proj in raw_projects:
                entry = dict(proj)
                all_entries.append({
                    'category': entry['category'],
                    'project_name': entry['project_name'],
                    'main_work': entry['main_work'],
                    'entry_data': entry
                })

            # 按分类、项目、主要工作排序
            all_entries_sorted = sorted(
                all_entries,
                key=lambda x: (x['category'], x['project_name'], x['main_work'])
            )

            # 计算合并单元格信息
            from collections import defaultdict

            # 分类分组
            category_groups = defaultdict(list)
            for idx, entry in enumerate(all_entries_sorted):
                category_groups[entry['category']].append(idx)

            # 项目分组
            project_groups = defaultdict(list)
            for idx, entry in enumerate(all_entries_sorted):
                key = (entry['category'], entry['project_name'])
                project_groups[key].append(idx)

            # 主要工作分组
            work_groups = defaultdict(list)
            for idx, entry in enumerate(all_entries_sorted):
                key = (entry['category'], entry['project_name'], entry['main_work'])
                work_groups[key].append(idx)

            # 添加rowspan信息
            for entry in all_entries_sorted:
                # 分类rowspan
                cat_indices = category_groups[entry['category']]
                entry['category_rowspan'] = len(cat_indices) if entry == all_entries_sorted[cat_indices[0]] else 0

                # 项目rowspan
                proj_key = (entry['category'], entry['project_name'])
                proj_indices = project_groups[proj_key]
                entry['project_rowspan'] = len(proj_indices) if entry == all_entries_sorted[proj_indices[0]] else 0

                # 主要工作rowspan
                work_key = (entry['category'], entry['project_name'], entry['main_work'])
                work_indices = work_groups[work_key]
                entry['main_work_rowspan'] = len(work_indices) if entry == all_entries_sorted[work_indices[0]] else 0

        # 异常处理
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

@app.route('/finished_project_detail/<int:project_id>', methods=['GET', 'POST'])
def finished_project_detail(project_id):
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    is_admin = session.get('is_admin', 0)
    error = None
    with get_db() as conn:
        try:
            # 获取项目完整数据（包含关联用户和原始进度）
            project = conn.execute('''
                SELECT 
                    fp.*,
                    u1.username AS responsible_person,
                    u1.id AS responsible_person_id,
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

            # 权限验证
            is_responsible = session['user_id'] == project['responsible_person_id']
            can_edit_summary = is_responsible and project['summary_status'] in (None, 'rejected')
            can_review = is_admin and project['summary_status'] == 'pending'

            # 处理进度数据
            completion_statuses = []
            for i in range(13, 23):  # 对应 completion_status_1 到 10
                status = project[i]
                if status:
                    completion_statuses.append(status)
                else:
                    completion_statuses.append("未记录")

            # 处理日期计算
            completion_date = datetime.datetime.strptime(
                project['completion_time_finished'], "%Y-%m-%d"
            ).date() if project['completion_time_finished'] else None
            current_date = current_datetime.date()
            days_diff = (current_date - completion_date).days if completion_date else 0

            # POST请求处理
            if request.method == 'POST':
                validate_csrf(request.form.get('csrf_token'))

                # 总结提交（责任人）
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

                # 审核操作（管理员）关键修复点：匹配表单值和数据库枚举
                if 'review_summary' in request.form and can_review:
                    action = request.form.get('review_result')
                    comment = request.form.get('review_comment', '').strip()
                    
                    # 严格验证参数值
                    if action not in ['approved', 'rejected']:
                        flash('无效的审核操作', 'error')
                        return redirect(url_for('finished_project_detail', project_id=project_id))
                    
                    if action == 'rejected' and not comment:
                        flash('驳回必须填写审核意见', 'error')
                        return redirect(url_for('finished_project_detail', project_id=project_id))
                    
                    # 直接使用原始参数更新
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

            # 准备显示数据
            project_data = {
                'id': project['id'],
                'category': project['category'],
                'project_name': project['project_name'],
                'main_work': project['main_work'],
                'work_goal': project['work_goal'],
                'original_completion_time': format_datetime(project['completion_time']),
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
        except ValueError as e:
            flash(f'日期格式错误: {str(e)}', 'error')
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
                    project[5],                # 使用原计划时间（completion_time）
                    request.form['responsible_department'],
                    project[6],                # 使用原责任人（responsible_person_id）
                    project[8],                # 使用原配合人（collaborator）
                    project[9],                # 使用原责任领导（responsible_leader_id）
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
                # 必填字段验证
                required_fields = [
                    'category', 'project_name', 'main_work', 'work_goal',
                    'responsible_department', 'completion_time_finished'
                ]
                for field in required_fields:
                    if not request.form.get(field, '').strip():
                        raise ValueError(f"{field.replace('_', ' ')} 不能为空")

                # 收集表单数据
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
                    'completion_time': request.form.get('completion_time', '')  # 原计划时间
                }

                # 插入数据库
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
    
    # 获取查询参数（修复参数名称映射）
    query_type = request.args.get('query_type', 'deadline')  # 接收前端传递的deadline/completion
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = 15  # 保持每页15条的分页设置

    with get_db() as conn:
        # 联合查询语句（保持原样）
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

        # 构建动态WHERE条件（修复字段映射）
        where_clauses = []
        params = []
        if start_date and end_date:
            # 根据查询类型选择过滤字段
            if query_type == 'deadline':
                where_clauses.append("plan_date BETWEEN ? AND ?")  # 使用plan_date字段
                params.extend([start_date, end_date])
            elif query_type == 'completion':
                where_clauses.append("completion_time_finished BETWEEN ? AND ?")  # 使用完成时间字段
                params.extend([start_date, end_date])

        # 构建完整查询
        full_query = base_query
        if where_clauses:
            full_query = f"SELECT * FROM ({base_query}) WHERE {' AND '.join(where_clauses)}"

        # 分页查询（保持原有分页逻辑）
        pagination_query = f'''
            SELECT * FROM ({full_query})
            ORDER BY plan_date ASC 
            LIMIT {per_page} OFFSET {(page - 1) * per_page}
        '''
        projects = conn.execute(pagination_query, params).fetchall()

        # 获取总数（保持原样）
        count_query = f"SELECT COUNT(*) FROM ({full_query})"
        total = conn.execute(count_query, params).fetchone()[0]

        # 导出处理（保留完整导出功能）
        if request.method == 'POST' and 'export' in request.form:
            try:
                validate_csrf(request.form.get('csrf_token'))  # CSRF保护
                df = pd.read_sql_query(full_query, conn, params=params)
                
                # 生成Excel文件（保持原有导出逻辑）
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

    # 渲染模板（保持所有参数传递）
    return render_template(
        'all_projects.html',
        all_projects=projects,
        current_date=current_date,
        query_type=query_type,      # 传递查询类型回前端
        start_date=start_date,      # 传递开始日期回前端
        end_date=end_date,          # 传递结束日期回前端
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
            # 删除数据库记录
            conn = get_db_connection()
            conn.execute('DELETE FROM projects WHERE id = ?', (project_id,))
            conn.commit()
            conn.close()
            flash('项目删除成功')
            return redirect(url_for('unfinished_projects'))
        except Exception as e:
            flash(f'删除失败: {str(e)}')
            return redirect(url_for('unfinished_projects'))

@app.route('/query_projects', methods=['GET', 'POST'])
def query_projects():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session:
        abort(401)

    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            query_type = request.form.get('query_type')
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')

            with get_db() as conn:
                # 修复后的联合查询语句
                base_query = '''
                    SELECT 
                        p.id,
                        p.category,
                        p.project_name,
                        p.main_work,
                        p.work_goal,
                        u1.username AS responsible_person,
                        p.responsible_department,
                        CASE 
                            WHEN p.is_finished = 1 THEN p.completion_time_finished
                            ELSE p.completion_time 
                        END AS target_date,
                        p.status,
                        p.is_finished
                    FROM (
                        SELECT 
                            id, category, project_name, main_work, work_goal,
                            responsible_person_id, responsible_department,
                            completion_time, 
                            NULL AS completion_time_finished,
                            (CASE WHEN julianday(completion_time) < julianday('now') 
                                THEN '逾期' ELSE '进行中' END) AS status,
                            0 AS is_finished
                        FROM unfinished_projects
                        UNION ALL
                        SELECT 
                            id, category, project_name, main_work, work_goal,
                            responsible_person_id, responsible_department,
                            NULL AS completion_time,
                            completion_time_finished,
                            '已完成' AS status,
                            1 AS is_finished
                        FROM finished_projects
                    ) p
                    LEFT JOIN users u1 ON p.responsible_person_id = u1.id
                    WHERE 1=1
                '''

                where_clause = ''
                params = []
                if query_type == 'deadline':
                    where_clause = " AND p.completion_time BETWEEN ? AND ?"
                    params.extend([start_date, end_date])
                elif query_type == 'completion':
                    where_clause = " AND p.completion_time_finished BETWEEN ? AND ?" 
                    params.extend([start_date, end_date])
                else:
                    flash('无效的查询类型', 'error')
                    return redirect(url_for('finished_projects'))

                projects = conn.execute(
                    f"{base_query} {where_clause} ORDER BY p.category, p.project_name",
                    params
                ).fetchall()

            return render_template('query_results.html',
                                 projects=projects,
                                 query_type=query_type,
                                 start_date=start_date,
                                 end_date=end_date,
                                 current_datetime=current_datetime)

        except Exception as e:
            flash(f'查询失败: {str(e)}', 'error')
            return redirect(url_for('finished_projects'))
    
    # 添加GET请求处理
    return render_template('query_projects.html',
                         current_datetime=current_datetime)

@app.route('/download_users', methods=['POST'])
def download_users():
    current_datetime = datetime.datetime.now()
    if 'user_id' not in session or not session.get('is_admin'):
        abort(403)
    
    try:
        validate_csrf(request.form.get('csrf_token'))  # 新增CSRF验证
        with get_db() as conn:
            df = pd.read_sql_query("SELECT id, username, phone, created_at FROM users", conn)
            df.to_excel('users.xlsx', index=False, engine='openpyxl')
            return send_file('users.xlsx', as_attachment=True)
    except ValidationError:
        flash('操作令牌无效，请刷新页面后重试', 'error')
        return redirect(url_for('user_management'))
    except Exception as e:
        flash(f'生成下载文件失败: {str(e)}', 'error')
        return redirect(url_for('user_management'))

@app.errorhandler(401)
def unauthorized(error):
    current_datetime = datetime.datetime.now()
    return redirect(url_for('login', next=request.path)), 302


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
        if app.config['DATABASE'].startswith('sqlite:///'):
            init_sqlite_schema(db)
        else:
            init_postgres_schema(db)
        print(f"Initialized database: {app.config['DATABASE']}")

if __name__ == '__main__':
    os.makedirs('instance', exist_ok=True)
    with app.app_context():
        try:
            db = get_db() 
            print("Database connection established")
        except Exception as e:
            print(f"Database initialization failed: {str(e)}")
            print("Continuing with potential limited functionality...")
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)