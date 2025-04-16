import os
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from flask import (
    Flask, render_template, request, redirect, 
    session, send_file, send_from_directory, 
    flash, url_for, jsonify
)
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
from io import BytesIO
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, text
from flask_migrate import Migrate

# 初始化Flask应用
app = Flask(__name__, static_folder='static', template_folder='templates')

# 生产环境配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-production-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://user:password@localhost/prod_db?charset=utf8mb4'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB文件上传限制
app.config['UPLOAD_FOLDER'] = '/var/www/uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}

# 初始化数据库
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 生产日志配置
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1024*1024*10,
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    department = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean, default=False)
    is_department_info = db.Column(db.Boolean, default=False)
    is_department_head = db.Column(db.Boolean, default=False)
    is_company_info = db.Column(db.Boolean, default=False)
    is_general_dept_head = db.Column(db.Boolean, default=False)
    is_company_leader = db.Column(db.Boolean, default=False)

class WeeklyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text)
    report_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10))
    submit_time = db.Column(db.DateTime, default=datetime.utcnow)
    report_date = db.Column(db.Date)

class SupervisionProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SupervisionDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('supervision_project.id'), nullable=False)
    main_content = db.Column(db.String(200), nullable=False)
    key_node = db.Column(db.String(100))
    responsible_dept = db.Column(db.String(50))
    responsible_person = db.Column(db.String(20))
    cooperating_dept = db.Column(db.String(200))
    cooperating_persons = db.Column(db.String(200))
    responsible_leader = db.Column(db.String(20))
    deadline = db.Column(db.Date)
    completion_time = db.Column(db.Date)
    status = db.Column(db.String(10), default='进行中')
    last_status_update = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    project = db.relationship('SupervisionProject', backref='details')

class ProgressRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detail_id = db.Column(db.Integer, db.ForeignKey('supervision_detail.id'), nullable=False)
    submitter = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submit_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status = db.Column(db.String(10), default='待审核')
    reviewer = db.Column(db.String(20))

class ProjectPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(20), default='项目类')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TimePlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(20), default='时间类')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProjectPlanDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan_id = db.Column(db.Integer, db.ForeignKey('project_plan.id'), nullable=False)
    main_content = db.Column(db.String(200), nullable=False)
    key_node = db.Column(db.String(100))
    responsible_dept = db.Column(db.String(50))
    responsible_person = db.Column(db.String(20))
    cooperating_dept = db.Column(db.String(200))
    cooperating_persons = db.Column(db.String(200))
    responsible_leader = db.Column(db.String(20))
    deadline = db.Column(db.Date)
    completion_time = db.Column(db.Date)
    status = db.Column(db.String(10), default='进行中')
    last_status_update = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class PlanProgressRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    detail_id = db.Column(db.Integer, db.ForeignKey('project_plan_detail.id'), nullable=False)
    submitter = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submit_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(10), default='待审核')
    reviewer = db.Column(db.String(20))

class PersonalWeeklyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    current_work = db.Column(db.Text)
    next_plan = db.Column(db.Text)
    submitted = db.Column(db.Boolean, default=False)
    department_submitted = db.Column(db.Boolean, default=False)
    submit_time = db.Column(db.DateTime)
    archived = db.Column(db.Boolean, default=False)
    report_date = db.Column(db.Date)
    user = db.relationship('User', backref='weekly_reports')

class PersonalWeeklyTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    current_work = db.Column(db.Text)
    next_plan = db.Column(db.Text)

class HistoricalWeeklyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    page = db.Column(db.Integer)

class CompanyWeeklyReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(50), nullable=False)
    current_work = db.Column(db.Text)
    next_plan = db.Column(db.Text)
    submitted = db.Column(db.Boolean, default=False)
    submitter = db.Column(db.String(20))
    submit_time = db.Column(db.DateTime)
    archived = db.Column(db.Boolean, default=False)
    archive_time = db.Column(db.DateTime)

# 定时任务配置（中国时区）
scheduler = BackgroundScheduler(timezone="Asia/Shanghai")

def check_overdue_projects():
    with app.app_context():
        try:
            tz = ZoneInfo("Asia/Shanghai")
            now = datetime.now(tz).date()
            overdue_details = SupervisionDetail.query.filter(
                SupervisionDetail.status.in_(['进行中', '逾期']),
                SupervisionDetail.deadline < now
            ).all()
            
            for detail in overdue_details:
                if detail.status != '逾期':
                    detail.status = '逾期'
                    detail.last_status_update = datetime.now(tz)
            
            db.session.commit()
        except Exception as e:
            app.logger.error(f"定时任务执行错误: {str(e)}")

def transfer_weekly_reports():
    with app.app_context():
        try:
            tz = ZoneInfo("Asia/Shanghai")
            now = datetime.now(tz)
            
            # 转移个人周报
            personal_reports = WeeklyReport.query.filter_by(report_type='personal').all()
            for report in personal_reports:
                report.report_type = 'history_personal'
                report.report_date = now.date()
            
            # 转移部门周报
            department_reports = WeeklyReport.query.filter_by(report_type='department').all()
            for report in department_reports:
                new_history = WeeklyReport(
                    reporter=report.reporter,
                    department=report.department,
                    content=report.content,
                    report_type='history_department',
                    submit_time=now
                )
                db.session.add(new_history)
                db.session.delete(report)
            
            # 转移公司周报
            company_reports = CompanyWeeklyReport.query.all()
            for report in company_reports:
                new_history = WeeklyReport(
                    reporter='system',
                    department=report.department,
                    content=json.dumps({
                        'current_work': report.current_work,
                        'next_plan': report.next_plan
                    }),
                    report_type='history_company',
                    submit_time=now
                )
                db.session.add(new_history)
                db.session.delete(report)
            
            db.session.commit()
        except Exception as e:
            app.logger.error(f"周报转移错误: {str(e)}")

scheduler.add_job(check_overdue_projects, 'cron', hour=0)
scheduler.add_job(transfer_weekly_reports, 'cron', day_of_week='sun', hour=12)
scheduler.start()

# 辅助函数
def valid_approver():
    user = User.query.filter_by(username=session['user']).first()
    return user.is_admin or user.is_company_leader

def has_company_permission():
    user = User.query.filter_by(username=session['user']).first()
    return user.is_general_dept_head or user.is_company_info or user.is_company_leader

def check_permission(user, target_user):
    return (
        user.is_company_info or 
        user.is_general_dept_head or
        user.is_company_leader or
        (user.is_department_info and user.department == target_user.department) or
        (user.is_department_head and user.department == target_user.department) or
        user.id == target_user.id
    )

@app.context_processor
def inject_permissions():
    def check_company_write_permission(user, department):
        if user.is_company_info or user.is_general_dept_head:
            return True
        return user.department == department and not CompanyWeeklyReport.query.filter_by(
            department=department, archived=False, submitted=True).first()
    
    return dict(
        check_company_write_permission=check_company_write_permission,
        check_permission=check_permission  
    )

# 路由部分
@app.route('/', methods=['GET', 'POST'])  
def login():
    if request.method == 'POST':
        user = User.query.filter_by(
            username=request.form['username'],
            password=request.form['password']
        ).first()
        if user:
            session['user'] = user.username
            session['is_admin'] = user.is_admin
            return redirect('/home')
    return render_template('login.html')

@app.route('/user_profile', methods=['GET', 'POST'])
def user_profile():
    if 'user' not in session:
        return redirect('/')
    
    user = User.query.filter_by(username=session['user']).first()
    
    if request.method == 'POST':
        user.phone = request.form['phone']
        user.password = request.form['password']
        db.session.commit()
        return redirect('/home')
    
    return render_template('user_profile.html',
                         username=user.username,
                         phone=user.phone,
                         password=user.password)

@app.route('/home')
def home():
    if 'user' not in session:
        return redirect('/')
    return render_template('index.html', 
                         is_admin=session.get('is_admin', False),
                         username=session['user'])

@app.route('/plan_management')
def plan_management():
    if 'user' not in session:
        return redirect('/')
    project_plans = ProjectPlan.query.all()
    time_plans = TimePlan.query.all()
    return render_template('plan_management.html',
                         project_plans=project_plans,
                         time_plans=time_plans)

@app.route('/add_project_plan', methods=['POST'])
def add_project_plan():
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    new_plan = ProjectPlan(plan_name=request.form['plan_name'])
    db.session.add(new_plan)
    db.session.commit()
    return redirect('/plan_management')

@app.route('/add_time_plan', methods=['POST'])
def add_time_plan():
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    new_plan = TimePlan(plan_name=request.form['plan_name'])
    db.session.add(new_plan)
    db.session.commit()
    return redirect('/plan_management')

@app.route('/delete_project_plan/<int:plan_id>')
def delete_project_plan(plan_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    plan = ProjectPlan.query.get(plan_id)
    db.session.delete(plan)
    db.session.commit()
    return redirect('/plan_management')

@app.route('/delete_time_plan/<int:plan_id>')
def delete_time_plan(plan_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    plan = TimePlan.query.get(plan_id)
    db.session.delete(plan)
    db.session.commit()
    return redirect('/plan_management')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/user_management')
def user_management():
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/import_users', methods=['POST'])
def import_users():
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    if 'file' not in request.files:
        return "未选择文件", 400
    
    file = request.files['file']
    if file.filename == '':
        return "无效文件", 400
    
    try:
        df = pd.read_excel(file)
        for _, row in df.iterrows():
            new_user = User(
                username=row['用户名'],
                password=row['密码'],
                department=row.get('部门', ''),
                phone=row.get('电话', ''),
                is_admin=row.get('管理员', False),
                is_department_info=row.get('部门信息员', False),
                is_department_head=row.get('部门负责人', False),
                is_company_info=row.get('公司信息员', False),
                is_general_dept_head=row.get('综合部负责人', False),
                is_company_leader=row.get('公司领导', False)
            )
            db.session.add(new_user)
        db.session.commit()
        return redirect('/user_management')
    except Exception as e:
        db.session.rollback()
        return f"导入失败: {str(e)}", 400

@app.route('/export_users')
def export_users():
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    users = User.query.all()
    data = [{
        '用户名': u.username,
        '密码': u.password,
        '部门': u.department,
        '电话': u.phone,
        '管理员': u.is_admin,
        '部门信息员': u.is_department_info,
        '部门负责人': u.is_department_head,
        '公司信息员': u.is_company_info,
        '综合部负责人': u.is_general_dept_head,
        '公司领导': u.is_company_leader
    } for u in users]

    df = pd.DataFrame(data)
    output = BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        download_name='用户列表.xlsx',
        as_attachment=True
    )

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        new_user = User(
            username=request.form['username'],
            password=request.form['password'],
            department=request.form['department'],
            phone=request.form['phone'],
            is_admin='is_admin' in request.form,
            is_department_info='is_department_info' in request.form,
            is_department_head='is_department_head' in request.form,
            is_company_info='is_company_info' in request.form,
            is_general_dept_head='is_general_dept_head' in request.form,
            is_company_leader='is_company_leader' in request.form
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect('/user_management')
    return render_template('add_user.html')

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    user = User.query.get(user_id)
    PersonalWeeklyReport.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    return redirect('/user_management')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.department = request.form.get('department', '')
        user.phone = request.form.get('phone', '')
        user.is_admin = 'is_admin' in request.form
        user.is_department_info = 'is_department_info' in request.form
        user.is_department_head = 'is_department_head' in request.form
        user.is_company_info = 'is_company_info' in request.form
        user.is_general_dept_head = 'is_general_dept_head' in request.form
        user.is_company_leader = 'is_company_leader' in request.form
        if request.form.get('password'):
            user.password = request.form['password']   
        try:
            db.session.commit()
            return redirect('/user_management')
        except Exception as e:
            db.session.rollback()
            return f"更新失败: {str(e)}", 500
    return render_template('edit_user.html', user=user)

@app.route('/supervision')
def supervision():
    if 'user' not in session:
        return redirect('/')
    projects = SupervisionProject.query.all()
    return render_template('supervision.html', projects=projects)

@app.route('/add_supervision', methods=['POST'])
def add_supervision():
    if 'user' not in session:
        return redirect('/')
    project_name = request.form['project_name']
    new_project = SupervisionProject(project_name=project_name)
    db.session.add(new_project)
    db.session.commit()
    return redirect('/supervision')

@app.route('/delete_supervision/<int:project_id>')
def delete_supervision(project_id):
    project = SupervisionProject.query.get(project_id)
    db.session.delete(project)
    db.session.commit()
    return redirect('/supervision')

@app.route('/supervision_detail/<int:project_id>')
def supervision_detail(project_id):
    if 'user' not in session:
        return redirect('/')
    
    project = SupervisionProject.query.get(project_id)
    details = SupervisionDetail.query.filter_by(project_id=project_id).order_by(SupervisionDetail.main_content).all()
    
    merged_details = []
    prev_content = None
    for detail in details:
        if detail.main_content != prev_content:
            merged_details.append({
                'main_content': detail.main_content,
                'details': [detail],
                'rowspan': 1
            })
            prev_content = detail.main_content
        else:
            merged_details[-1]['details'].append(detail)
            merged_details[-1]['rowspan'] += 1
    
    users = User.query.all()
    leaders = User.query.filter_by(is_company_leader=True).all()
    
    return render_template('supervision_detail.html',
                         project=project,
                         merged_details=merged_details,
                         users=users,
                         leaders=leaders,
                         is_admin=session.get('is_admin', False),
                         source='supervision') 

@app.route('/import_project_details/<int:project_id>', methods=['POST'])
def import_project_details(project_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        file = request.files['file']
        df = pd.read_excel(file, engine='openpyxl')
        
        for _, row in df.iterrows():
            new_detail = SupervisionDetail(
                project_id=project_id,
                main_content=row['主要内容'],
                key_node=row['关键节点'],
                responsible_dept=row['责任部门'],
                responsible_person=row['责任人'],
                cooperating_dept=row['配合部门'],
                cooperating_persons=row['配合人'],
                responsible_leader=row['责任领导'],
                deadline=datetime.strptime(row['完成时限'], '%Y-%m-%d') if pd.notnull(row['完成时限']) else None,
                status='进行中'
            )
            
            if new_detail.deadline and new_detail.deadline < datetime.now().date():
                new_detail.status = '逾期'
                
            db.session.add(new_detail)
        
        db.session.commit()
        return redirect(f'/supervision_detail/{project_id}')   
    except Exception as e:
        print(f"导入错误: {str(e)}")
        return redirect(f'/supervision_detail/{project_id}')

@app.route('/export_project_details/<int:project_id>')
def export_project_details(project_id):
    if 'user' not in session:
        return redirect('/')
    
    details = SupervisionDetail.query.filter_by(project_id=project_id).all()
    
    data = [{
        '主要内容': d.main_content,
        '关键节点': d.key_node,
        '责任部门': d.responsible_dept,
        '责任人': d.responsible_person,
        '配合部门': d.cooperating_dept,
        '配合人': d.cooperating_persons,
        '责任领导': d.responsible_leader,
        '完成时限': d.deadline.strftime('%Y-%m-%d') if d.deadline else '',
        '状态': d.status
    } for d in details]

    df = pd.DataFrame(data)
    filename = f"project_{project_id}_details.xlsx"
    df.to_excel(filename, index=False, engine='openpyxl')
    
    return send_from_directory('.', filename, as_attachment=True)

@app.route('/add_project_detail/<int:project_id>', methods=['POST'])
def add_project_detail(project_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        deadline_str = request.form.get('deadline')
        deadline = None
        if deadline_str:
            deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
        
        new_detail = SupervisionDetail(
            project_id=project_id,
            main_content=request.form['main_content'],
            key_node=request.form['key_node'],
            responsible_dept=request.form['responsible_dept'],
            responsible_person=request.form['responsible_person'],
            cooperating_dept=request.form.get('cooperating_dept', ''),
            cooperating_persons=','.join(request.form.getlist('cooperating_persons')),
            responsible_leader=request.form['responsible_leader'],
            deadline=deadline,  # 使用处理后的日期对象
            status='进行中'
        )
        
        if new_detail.deadline and new_detail.deadline < datetime.now().date():
            new_detail.status = '逾期'
        
        db.session.add(new_detail)
        db.session.commit()
        return redirect(f'/supervision_detail/{project_id}')
    except ValueError as e:
        db.session.rollback()
        print(f"日期格式错误: {str(e)}")
        return "日期格式无效，请使用YYYY-MM-DD格式", 400
    except Exception as e:
        db.session.rollback()
        print(f"添加失败: {str(e)}")
        return f"提交失败: {str(e)}", 500

@app.route('/complete_project/<int:detail_id>', methods=['POST'])
def complete_project(detail_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        completion_time_str = request.form.get('completion_time', '').strip()
        if not completion_time_str:
            raise ValueError("缺失完成时间参数")
        try:
            completion_time = datetime.strptime(completion_time_str, '%Y-%m-%d').date()
        except ValueError:
            raise ValueError("无效的日期格式，必须为YYYY-MM-DD")
        
        detail = SupervisionDetail.query.with_for_update().get_or_404(detail_id)
        detail.completion_time = completion_time
        if detail.deadline:
            if completion_time > detail.deadline:
                detail.status = '逾期完成'
            else:
                detail.status = '已完成'
        else:
            detail.status = '已完成'
            
        detail.last_status_update = datetime.utcnow()
        db.session.commit()
        
        return redirect(url_for('supervision_detail', project_id=detail.project_id))
        
    except ValueError as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'error')
        return redirect(url_for('supervision_detail', project_id=detail.project_id))
    
    except SQLAlchemyError as e:  
        db.session.rollback()
        app.logger.error(f"数据库操作异常: {str(e)}")
        flash('操作失败：数据库错误', 'error')
        return redirect(url_for('supervision_detail', project_id=detail.project_id))
    
    except Exception as e:
        db.session.rollback()
        app.logger.critical(f"系统异常: {str(e)}")
        flash('操作失败：系统错误', 'error')
        return redirect(url_for('supervision_detail', project_id=detail.project_id))

@app.route('/delete_project_detail/<int:detail_id>', methods=['DELETE'])
def delete_project_detail(detail_id):
    if 'user' not in session or not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': '未授权'}), 401
    
    try:
        detail = db.session.query(SupervisionDetail).options(
            db.joinedload(SupervisionDetail.project)
        ).get_or_404(detail_id)
        
        project_id = detail.project_id
        ProgressRecord.query.filter_by(detail_id=detail_id).delete()
        db.session.delete(detail)
        db.session.commit()
        
        return jsonify({'status': 'success', 'redirect': f'/supervision_detail/{project_id}'})
    
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"数据库删除错误: {str(e)}")
        return jsonify({'status': 'error', 'message': '数据库操作失败'}), 500
    
    except Exception as e:
        db.session.rollback()
        app.logger.critical(f"系统级删除错误: {str(e)}")
        return jsonify({'status': 'error', 'message': '系统异常'}), 500

@app.route('/submit_progress/<int:detail_id>', methods=['POST'])
def submit_progress(detail_id):
    if 'user' not in session:
        return redirect('/')
    
    detail = SupervisionDetail.query.get(detail_id)
    current_user = session['user']
    
    if current_user not in [detail.responsible_person] + detail.cooperating_persons.split(','):
        return "无操作权限", 403
    
    new_progress = ProgressRecord(
        detail_id=detail_id,
        submitter=current_user,
        content=request.form['content']
    )
    db.session.add(new_progress)
    db.session.commit()
    return redirect(f'/project_progress/{detail_id}')

@app.route('/review_progress/<int:progress_id>/<action>')
def review_progress(progress_id, action):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    progress = ProgressRecord.query.get(progress_id)
    progress.status = '已通过' if action == 'approve' else '已驳回'
    progress.reviewer = session['user']
    db.session.commit()
    return redirect(f'/project_progress/{progress.detail_id}')

@app.route('/project_progress/<int:detail_id>')
def project_progress(detail_id):
    if 'user' not in session:
        return redirect('/')
    
    detail = SupervisionDetail.query.get(detail_id)
    progress_records = ProgressRecord.query.filter_by(detail_id=detail_id).order_by(ProgressRecord.submit_time.desc()).all()
    
    current_user = User.query.filter_by(username=session['user']).first()
    cooperating_persons = [cp.strip() for cp in detail.cooperating_persons.split(',')] if detail.cooperating_persons else []
    has_access = (
        current_user.username == detail.responsible_person or
        current_user.username in cooperating_persons
    )
    
    return render_template('project_progress.html',
                         detail=detail,
                         progress_records=progress_records,
                         is_admin=current_user.is_admin,
                         is_company_leader=current_user.is_company_leader,
                         has_access=has_access,
                         current_user=current_user)  

@app.route('/import_plan_details/<int:plan_id>', methods=['POST'])
def import_plan_details(plan_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        file = request.files['file']
        df = pd.read_excel(file, engine='openpyxl')
        
        for _, row in df.iterrows():
            new_detail = ProjectPlanDetail(
                plan_id=plan_id,
                main_content=row['主要内容'],
                key_node=row['关键节点'],
                responsible_dept=row['责任部门'],
                responsible_person=row['责任人'],
                cooperating_dept=row['配合部门'],
                cooperating_persons=row['配合人'],
                responsible_leader=row['责任领导'],
                deadline=datetime.strptime(row['完成时限'], '%Y-%m-%d') if pd.notnull(row['完成时限']) else None,
                status='进行中'
            )
            
            if new_detail.deadline and new_detail.deadline < datetime.now().date():
                new_detail.status = '逾期'
                
            db.session.add(new_detail)
        
        db.session.commit()
        return redirect(f'/project_plan_detail/{plan_id}')   
    except Exception as e:
        print(f"导入错误: {str(e)}")
        return redirect(f'/project_plan_detail/{plan_id}')

@app.route('/export_plan_details/<int:plan_id>')
def export_plan_details(plan_id):
    if 'user' not in session:
        return redirect('/')
    
    details = ProjectPlanDetail.query.filter_by(plan_id=plan_id).all()
    
    data = [{
        '主要内容': d.main_content,
        '关键节点': d.key_node,
        '责任部门': d.responsible_dept,
        '责任人': d.responsible_person,
        '配合部门': d.cooperating_dept,
        '配合人': d.cooperating_persons,
        '责任领导': d.responsible_leader,
        '完成时限': d.deadline.strftime('%Y-%m-%d') if d.deadline else '',
        '状态': d.status
    } for d in details]

    df = pd.DataFrame(data)
    filename = f"plan_{plan_id}_details.xlsx"
    df.to_excel(filename, index=False, engine='openpyxl')
    
    return send_from_directory('.', filename, as_attachment=True)

@app.route('/add_plan_detail/<int:plan_id>', methods=['POST'])
def add_plan_detail(plan_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        deadline_str = request.form.get('deadline')
        deadline = None
        if deadline_str:
            deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
        
        new_detail = ProjectPlanDetail(
            plan_id=plan_id,
            main_content=request.form['main_content'],
            key_node=request.form['key_node'],
            responsible_dept=request.form['responsible_dept'],
            responsible_person=request.form['responsible_person'],
            cooperating_dept=','.join(request.form.getlist('cooperating_dept')),
            cooperating_persons=','.join(request.form.getlist('cooperating_persons')),
            responsible_leader=request.form['responsible_leader'],
            deadline=deadline,
            status='进行中'
        )
        
        if new_detail.deadline and new_detail.deadline < datetime.now().date():
            new_detail.status = '逾期'
        
        db.session.add(new_detail)
        db.session.commit()
        return redirect(f'/project_plan_detail/{plan_id}')
    except ValueError as e:
        db.session.rollback()
        print(f"日期格式错误: {str(e)}")
        return "日期格式无效，请使用YYYY-MM-DD格式", 400
    except Exception as e:
        db.session.rollback()
        print(f"添加失败: {str(e)}")
        return f"提交失败: {str(e)}", 500

@app.route('/complete_plan_detail/<int:detail_id>', methods=['POST'])
def complete_plan_detail(detail_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        completion_time_str = request.form.get('completion_time', '').strip()
        if not completion_time_str:
            raise ValueError("缺失完成时间参数")
        
        completion_time = datetime.strptime(completion_time_str, '%Y-%m-%d').date()
        
        detail = ProjectPlanDetail.query.get_or_404(detail_id)
        detail.completion_time = completion_time  # 使用用户输入的日期
        detail.last_status_update = datetime.now(timezone.utc).replace(tzinfo=None)
        
        if detail.deadline:
            if completion_time > detail.deadline:
                detail.status = '逾期完成'
            else:
                detail.status = '已完成'
        else:
            detail.status = '已完成'
            
        db.session.commit()
        return redirect(f'/project_plan_detail/{detail.plan_id}')
        
    except ValueError as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'error')
        return redirect(url_for('project_plan_detail', plan_id=detail.plan_id))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"数据库操作异常: {str(e)}")
        flash('操作失败：数据库错误', 'error')
        return redirect(url_for('project_plan_detail', plan_id=detail.plan_id))
    
    except Exception as e:
        db.session.rollback()
        app.logger.critical(f"系统异常: {str(e)}")
        flash('操作失败：系统错误', 'error')
        return redirect(url_for('project_plan_detail', plan_id=detail.plan_id))

@app.route('/delete_plan_detail/<int:detail_id>', methods=['POST'])  # 添加methods参数
def delete_plan_detail(detail_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        detail = db.session.get(ProjectPlanDetail, detail_id)  # 修改为新的session.get方法
        if detail:
            plan_id = detail.plan_id       
            PlanProgressRecord.query.filter_by(detail_id=detail_id).delete()
            db.session.delete(detail)
            db.session.commit()
        return redirect(f'/project_plan_detail/{plan_id}')
    
    except Exception as e:
        db.session.rollback()
        print(f"删除错误: {str(e)}")
        return redirect(f'/project_plan_detail/{plan_id}') if 'plan_id' in locals() else redirect('/plan_management')

@app.route('/project_plan_detail/<int:plan_id>')
def project_plan_detail(plan_id):
    if 'user' not in session:
        return redirect('/')
    
    plan = db.session.get(ProjectPlan, plan_id)
    details = ProjectPlanDetail.query.filter_by(plan_id=plan_id).order_by(ProjectPlanDetail.main_content).all()
    
    merged_details = []
    prev_content = None
    for detail in details:
        if detail.main_content != prev_content:
            merged_details.append({
                'main_content': detail.main_content,
                'details': [detail],
                'rowspan': 1
            })
            prev_content = detail.main_content
        else:
            merged_details[-1]['details'].append(detail)
            merged_details[-1]['rowspan'] += 1
    
    users = User.query.all()
    leaders = User.query.filter_by(is_company_leader=True).all()
    
    return render_template('supervision_detail.html',
                         project=plan,
                         merged_details=merged_details,
                         users=users,
                         leaders=leaders,
                         is_admin=session.get('is_admin', False),
                         source='plan')

@app.route('/time_plan_detail/<int:plan_id>')
def time_plan_detail(plan_id):
    if 'user' not in session:
        return redirect('/')
    return render_template('time_plan_placeholder.html')

@app.route('/submit_plan_progress/<int:detail_id>', methods=['POST'])
def submit_plan_progress(detail_id):  # 修复路由参数名不一致问题
    if 'user' not in session:
        return redirect('/')
    
    detail = ProjectPlanDetail.query.get(detail_id)
    current_user = session['user']
    
    cooperating_persons = detail.cooperating_persons.split(',') if detail.cooperating_persons else []
    if current_user not in [detail.responsible_person] + cooperating_persons:
        return "无操作权限", 403
    
    new_progress = PlanProgressRecord(
        detail_id=detail_id,
        submitter=current_user,
        content=request.form['content']
    )
    db.session.add(new_progress)
    db.session.commit()
    return redirect(url_for('plan_progress', detail_id=detail_id))  # 修复重定向参数

@app.route('/review_plan_progress/<int:progress_id>/<action>')
def review_plan_progress(progress_id, action):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    progress = PlanProgressRecord.query.get(progress_id)
    progress.status = '已通过' if action == 'approve' else '已驳回'
    progress.reviewer = session['user']
    db.session.commit()
    return redirect(url_for('plan_progress', detail_id=progress.detail_id))

@app.route('/plan_progress/<int:detail_id>')  # 确保路由参数与模板中的URL生成一致
def plan_progress(detail_id):
    if 'user' not in session:
        return redirect('/')
    
    detail = ProjectPlanDetail.query.get_or_404(detail_id)
    progress_records = PlanProgressRecord.query.filter_by(detail_id=detail_id).order_by(PlanProgressRecord.submit_time.desc()).all()
    
    current_user = User.query.filter_by(username=session['user']).first()
    cooperating_persons = [cp.strip() for cp in detail.cooperating_persons.split(',')] if detail.cooperating_persons else []
    has_access = (
        current_user.username == detail.responsible_person or
        current_user.username in cooperating_persons
    )
    
    return render_template('plan_progress.html',
                         detail=detail,
                         progress_records=progress_records,
                         is_admin=current_user.is_admin,
                         is_company_leader=current_user.is_company_leader,
                         has_access=has_access,
                         current_user=current_user)

@app.route('/weekly_management')
def weekly_management():
    if 'user' not in session:
        return redirect('/')
    return render_template('weekly_management.html')

@app.route('/historical_weekly')
def historical_weekly():
    if 'user' not in session:
        return redirect('/')
    
    current_user = User.query.filter_by(username=session['user']).first()
    page = request.args.get('page', 1, type=int)
    pagination = HistoricalWeeklyReport.query.order_by(
        HistoricalWeeklyReport.page.desc()
    ).paginate(page=page, per_page=1)
    
    reports = []
    archive_time = None  # 新增归档时间变量
    if pagination.items:
        content = json.loads(pagination.items[0].content)
        # 获取归档时间
        archive_time = datetime.fromisoformat(content['archive_time']).strftime('%Y-%m-%d %H:%M')
        departments = sorted(set(r['department'] for r in content['reports']))
        for dept in departments:
            dept_reports = [r for r in content['reports'] if r['department'] == dept]
            users = User.query.filter(User.username.in_([r['username'] for r in dept_reports])).all()
            sorted_users = sorted(users, key=lambda u: not u.is_department_head)
            reports.extend([
                {
                    'department': u.department,
                    'username': u.username,
                    'current_work': next(r for r in dept_reports if r['username'] == u.username)['current_work'],
                    'next_plan': next(r for r in dept_reports if r['username'] == u.username)['next_plan'],
                    'submit_time': next(r for r in dept_reports if r['username'] == u.username).get('submit_time')
                }
                for u in sorted_users
            ])
    
    return render_template('historical_weekly.html',
                         reports=reports,
                         pagination=pagination,
                         current_user=current_user,
                         archive_time=archive_time) 

@app.route('/delete_historical_weekly/<int:page_id>', methods=['POST'])
def delete_historical_weekly(page_id):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    report = HistoricalWeeklyReport.query.filter_by(page=page_id).first()
    if report:
        db.session.delete(report)
        db.session.commit()
        flash('历史周报删除成功', 'success')
    else:
        flash('周报记录不存在', 'error')
    
    return redirect(url_for('historical_weekly'))


@app.route('/personal_weekly', methods=['GET', 'POST'])
def personal_weekly():
    if 'user' not in session:
        return redirect('/')
    
    user = User.query.filter_by(username=session['user']).first()
    template = PersonalWeeklyTemplate.query.first()
    
    users = User.query.filter_by(is_company_leader=False).order_by(
        User.department,
        User.is_department_head.desc(),
        User.username
    ).all()
    
    current_reports = {r.user_id: r for r in PersonalWeeklyReport.query.filter_by(archived=False)}
    
    if request.method == 'POST':
        if user.is_company_info or user.is_general_dept_head:
            current_work = request.form.get('current_work', '')
            next_plan = request.form.get('next_plan', '')
            
            if template is None:
                template = PersonalWeeklyTemplate(
                    current_work=current_work,
                    next_plan=next_plan
                )
                db.session.add(template)
            else:
                template.current_work = current_work
                template.next_plan = next_plan
            db.session.commit()
            flash('模板保存成功', 'success')
        
        # 处理周报提交
        for u in users:
            if f'submit_{u.id}' in request.form:
                report = current_reports.get(u.id)
                
                # 创建或更新报告
                if not report:
                    report = PersonalWeeklyReport(
                        user_id=u.id,
                        current_work=request.form.get(f'current_work_{u.id}', ''),
                        next_plan=request.form.get(f'next_plan_{u.id}', '')
                    )
                    db.session.add(report)
                else:
                    # 修改权限判断逻辑
                    if check_permission(user, u) or u.id == user.id:
                        report.current_work = request.form.get(f'current_work_{u.id}', '')
                        report.next_plan = request.form.get(f'next_plan_{u.id}', '')

                if u.id == user.id and not report.submitted: 
                    report.submitted = True
                    report.submit_time = datetime.utcnow()
                elif (user.is_department_head or user.is_department_info) and user.department == u.department:
                    report.department_submitted = True
                    report.submit_time = datetime.utcnow() 
                
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    flash(f'提交失败: {str(e)}', 'error')
        
        return redirect(url_for('personal_weekly'))
    
    show_archive_button = (user.is_company_info or user.is_general_dept_head)
    return render_template('personal_weekly.html',
                        users=users,
                        current_reports=current_reports,
                        template=template,
                        user=user,
                        show_archive_button=show_archive_button)

@app.route('/archive_weekly', methods=['POST'])
def archive_weekly():
    if 'user' not in session:
        return redirect('/')
    
    user = User.query.filter_by(username=session['user']).first()
    if not (user.is_company_info or user.is_general_dept_head):
        return "无操作权限", 403
    
    current_reports = PersonalWeeklyReport.query.filter_by(archived=False).all()
    for report in current_reports:
        report.archived = True
        report.report_date = datetime.utcnow().date()
    
    history = HistoricalWeeklyReport(
        content=json.dumps({
            'reports': [
                {
                    'department': report.user.department,  # 修复这里，通过关系访问
                    'username': report.user.username,    # 修复这里
                    'current_work': report.current_work,
                    'next_plan': report.next_plan,
                    'submit_time': report.submit_time.isoformat() if report.submit_time else None
                }
                for report in current_reports
            ],
            'archive_time': datetime.utcnow().isoformat()
        }),
        page=HistoricalWeeklyReport.query.count() + 1
    )
    
    db.session.add(history)
    db.session.commit()
    
    return redirect('/historical_weekly')

@app.route('/export_weekly')
def export_weekly():
    if 'user' not in session:
        return redirect('/')
    
    current_date = datetime.now().date()
    year, week_number, _ = current_date.isocalendar()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"个人周报_{year}年第{week_number}周_{timestamp}.xlsx"
    
    # 获取所有用户（排除公司领导），并按照部门排序
    users = User.query.filter_by(is_company_leader=False).order_by(
        User.department,
        User.is_department_head.desc(),
        User.username
    ).all()
    
    data = []
    for user in users:
        # 查询用户最新的未归档周报
        report = PersonalWeeklyReport.query.filter_by(
            user_id=user.id,
            archived=False
        ).first()
        
        data.append({
            '部门': user.department,
            '姓名': user.username,
            '本周工作内容': report.current_work if report else '',
            '下周计划': report.next_plan if report else '',
            '提交状态': '已提交' if report and report.submitted else '未提交',
            '提交时间': report.submit_time.strftime('%Y-%m-%d %H:%M') if report and report.submit_time else ''
        })
    
    df = pd.DataFrame(data)
    
    # 使用正确的Excel生成方式
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='个人周报')
        worksheet = writer.sheets['个人周报']
        worksheet.column_dimensions['A'].width = 20
        worksheet.column_dimensions['B'].width = 15
        worksheet.column_dimensions['C'].width = 50
        worksheet.column_dimensions['D'].width = 50
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        download_name=filename,
        as_attachment=True
    )

@app.route('/company_weekly', methods=['GET', 'POST'])
def company_weekly():
    if 'user' not in session:
        return redirect('/')
    
    user = User.query.filter_by(username=session['user']).first()
    departments = db.session.query(User.department).filter(
        User.department != '领导'  # 添加过滤条件
    ).distinct().all()
    
    # 获取当前未归档的周报
    current_reports = CompanyWeeklyReport.query.filter_by(archived=False).all()
    
    if request.method == 'POST':
        department = request.form['department']
        report = CompanyWeeklyReport.query.filter_by(department=department, archived=False).first()
        
        if not report:
            report = CompanyWeeklyReport(department=department)
            db.session.add(report)
        
        # 权限检查
        if check_company_write_permission(user, department):
            report.current_work = request.form.get('current_work', '')
            report.next_plan = request.form.get('next_plan', '')
            
            # 如果是部门用户首次提交
            if user.department == department and not report.submitted:
                report.submitted = True
                report.submitter = user.username
                report.submit_time = datetime.utcnow()
            
            db.session.commit()
        
        return redirect(url_for('company_weekly'))
    
    return render_template('company_weekly.html',
                         current_reports=current_reports,
                         user=user,
                         departments=[d[0] for d in departments])

def check_company_write_permission(user, department):
    # 公司信息员和综合部负责人可随时修改
    if user.is_company_info or user.is_general_dept_head:
        return True
    # 部门用户只能修改本部门未提交的
    return user.department == department and not CompanyWeeklyReport.query.filter_by(
        department=department, archived=False, submitted=True).first()

@app.route('/archive_company_weekly', methods=['POST'])
def archive_company_weekly():
    if 'user' not in session:
        return redirect('/')
    
    user = User.query.filter_by(username=session['user']).first()
    if not (user.is_company_info or user.is_general_dept_head):
        return "无操作权限", 403
    
    reports = CompanyWeeklyReport.query.filter_by(archived=False, submitted=True).all()
    for report in reports:
        report.archived = True
        report.archive_time = datetime.utcnow()  # 修正为正确的字段名称
    
    db.session.commit()
    return redirect(url_for('company_weekly'))

@app.route('/company_weekly_history')
def company_weekly_history():
    if 'user' not in session:
        return redirect('/')
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # 获取所有归档时间点（按归档时间分组）
    archive_query = db.session.query(
        CompanyWeeklyReport.archive_time,
        func.max(CompanyWeeklyReport.id).label('latest_id')
    ).filter(
        CompanyWeeklyReport.archived == True
    ).group_by(
        CompanyWeeklyReport.archive_time
    ).order_by(
        CompanyWeeklyReport.archive_time.desc()
    )
    
    archives = archive_query.paginate(page=page, per_page=per_page, error_out=False)
    
    # 组织数据用于模板展示
    archive_data = []
    for item in archives.items:
        # 获取该归档时间的所有周报
        reports = CompanyWeeklyReport.query.filter(
            CompanyWeeklyReport.archive_time == item.archive_time
        ).order_by(CompanyWeeklyReport.department).all()
        
        archive_data.append({
            'archive_time': item.archive_time,
            'latest_id': item.latest_id,  # 用于删除操作的ID参数
            'reports': reports
        })
    
    return render_template('company_weekly_history.html', 
                         archives=archives,
                         archive_data=archive_data,
                         is_admin=session.get('is_admin', False))

@app.route('/delete_company_weekly_archive/<string:archive_time>')
def delete_company_weekly_archive(archive_time):
    if 'user' not in session or not session.get('is_admin'):
        return redirect('/')
    
    try:
        # 将URL参数中的字符串转换为datetime对象
        archive_time = datetime.fromisoformat(archive_time)
        # 删除所有该归档时间的记录
        CompanyWeeklyReport.query.filter_by(archive_time=archive_time).delete()
        db.session.commit()
        flash('历史记录删除成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'error')
    
    return redirect(url_for('company_weekly_history'))

@app.route('/export_company_weekly_archive/<string:archive_time>')
def export_company_weekly_archive(archive_time):
    if 'user' not in session:
        return redirect('/')
    
    try:
        archive_time = datetime.fromisoformat(archive_time)
        reports = CompanyWeeklyReport.query.filter_by(archive_time=archive_time).all()
        
        data = [{
            '部门': r.department,
            '本周工作': r.current_work,
            '下周计划': r.next_plan,
            '提交时间': r.submit_time.strftime('%Y-%m-%d %H:%M'),
            '归档时间': r.archive_time.strftime('%Y-%m-%d %H:%M')
        } for r in reports]

        df = pd.DataFrame(data)
        filename = f"company_weekly_{archive_time.strftime('%Y%m%d_%H%M')}.xlsx"
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='公司周报')
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f'导出失败: {str(e)}', 'error')
        return redirect(url_for('company_weekly_history'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin23gg', is_admin=True)
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 5000))
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    app.run(host=host, port=port, debug=False)