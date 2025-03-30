from flask import Flask, render_template, request, redirect, session, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup, escape
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pymysql
import os
import uuid
import itsdangerous
import re

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

s = itsdangerous.URLSafeTimedSerializer(app.secret_key)

def get_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        db=os.getenv("DB_NAME"),
        charset='utf8',
        cursorclass=pymysql.cursors.DictCursor
    )

# 홈 페이지
@app.route('/')
def home():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """)
    posts = cursor.fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

# 글 작성 폼
@app.route('/write', methods=['GET'])
def write_form():
    if 'user_id' not in session:
        flash("⚠️ 글을 작성하려면 로그인해야 합니다.")
        return redirect('/login')
    return render_template('write.html')

# 글 작성 처리
@app.route('/write', methods=['POST'])
def write_post():
    if 'user_id' not in session:
        flash("⚠️ 로그인이 필요합니다.")
        return redirect('/login')

    title = request.form['title']
    content = request.form['content']
    is_private = 'is_private' in request.form
    post_password = request.form.get('post_password')
    uploaded_file = request.files.get('file')
    user_id = session['user_id']

    if is_private:
        if not post_password:
            flash("⚠️ 비공개 글은 비밀번호를 반드시 입력해야 합니다.")
            return render_template('write.html', title=title, content=content, is_private=is_private)

        if len(post_password) < 4:
            flash("⚠️ 비밀번호는 최소 4자리 이상이어야 합니다.")
            return render_template('write.html', title=title, content=content, is_private=is_private)

    hashed_pw = generate_password_hash(post_password) if is_private else None

    filename = None
    if uploaded_file and uploaded_file.filename:
        filename = str(uuid.uuid4()) + "_" + secure_filename(uploaded_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(filepath)

    conn = get_connection()
    cursor = conn.cursor()
    sql = """
        INSERT INTO posts (title, content, is_private, post_password, filename, user_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(sql, (title, content, is_private, hashed_pw, filename, user_id))
    conn.commit()
    conn.close()

    return redirect('/')

# 글 상세 보기
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT posts.*, users.username, users.id AS user_id
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = %s
    """, (post_id,))
    post = cursor.fetchone()
    conn.close()

    if not post:
        return "글을 찾을 수 없습니다.", 404

    if post['is_private']:
        if request.method == 'POST':
            input_pw = request.form.get('post_password')
            if input_pw and check_password_hash(post['post_password'], input_pw):
                return render_template('detail.html', post=post)
            else:
                flash("⚠️ 비밀번호가 틀렸습니다.")
                return redirect(f'/post/{post_id}')
        return render_template('password_check.html', post_id=post_id)
    else:
        return render_template('detail.html', post=post)

# 첨부파일 다운로드 처리
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# 글 수정 폼
@app.route('/edit/<int:post_id>', methods=['GET'])
def edit_form(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    conn.close()

    if not post:
        return "글을 찾을 수 없습니다.", 404

    if post['user_id'] != session.get('user_id'):
        flash("⚠️ 수정 권한이 없습니다.")
        return redirect(f'/post/{post_id}')

    return render_template('edit.html', post=post)

# 글 수정 처리
@app.route('/edit/<int:post_id>', methods=['POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        flash("⚠️ 로그인이 필요합니다.")
        return redirect('/login')

    title = request.form['title']
    content = request.form['content']
    is_private = 'is_private' in request.form
    new_password = request.form.get('post_password')
    uploaded_file = request.files.get('file')

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()

    if not post:
        conn.close()
        return "글을 찾을 수 없습니다.", 404

    if post['user_id'] != session.get('user_id'):
        conn.close()
        flash("⚠️ 수정 권한이 없습니다.")
        return redirect(f'/post/{post_id}')

    if is_private and new_password and len(new_password) < 4:
        flash("⚠️ 비밀번호는 최소 4자리 이상이어야 합니다.")
        conn.close()
        return render_template('edit.html', post=post)

    if is_private and not post['is_private'] and not new_password:
        flash("⚠️ 비공개 글로 변경하려면 비밀번호를 입력해야 합니다.")
        conn.close()
        return render_template('edit.html', post=post)

    hashed_pw = generate_password_hash(new_password) if new_password else None

    filename = post['filename']
    if uploaded_file and uploaded_file.filename:
        filename = str(uuid.uuid4()) + "_" + secure_filename(uploaded_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(filepath)

    if is_private:
        if new_password:
            sql = "UPDATE posts SET title=%s, content=%s, is_private=%s, post_password=%s, filename=%s WHERE id=%s"
            cursor.execute(sql, (title, content, is_private, hashed_pw, filename, post_id))
        else:
            sql = "UPDATE posts SET title=%s, content=%s, is_private=%s, filename=%s WHERE id=%s"
            cursor.execute(sql, (title, content, is_private, filename, post_id))
    else:
        sql = "UPDATE posts SET title=%s, content=%s, is_private=%s, post_password=NULL, filename=%s WHERE id=%s"
        cursor.execute(sql, (title, content, is_private, filename, post_id))

    conn.commit()
    conn.close()

    flash("게시글이 수정되었습니다.")
    return redirect(f'/post/{post_id}')

# 글 삭제 처리
@app.route('/delete/<int:post_id>')
def delete_post(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()

    if not post:
        conn.close()
        return "글을 찾을 수 없습니다.", 404

    if post['user_id'] != session.get('user_id'):
        conn.close()
        flash("⚠️ 삭제 권한이 없습니다.")
        return redirect(f'/post/{post_id}')

    cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    conn.commit()
    conn.close()

    return redirect('/')

# 검색 기능
@app.route('/search')
def search():
    keyword = request.args.get('keyword')
    option = request.args.get('option')

    conn = get_connection()
    cursor = conn.cursor()

    if option == 'title':
        sql = "SELECT * FROM posts WHERE title LIKE %s ORDER BY created_at DESC"
        cursor.execute(sql, (f"%{keyword}%",))
    elif option == 'content':
        sql = "SELECT * FROM posts WHERE content LIKE %s ORDER BY created_at DESC"
        cursor.execute(sql, (f"%{keyword}%",))
    else:
        sql = "SELECT * FROM posts WHERE title LIKE %s OR content LIKE %s ORDER BY created_at DESC"
        cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))

    posts = cursor.fetchall()
    conn.close()

    return render_template('index.html', posts=posts)

# 프로필 수정
@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        school = request.form['school']
        department = request.form['department']
        profile_image = request.files.get('profile_image')
        profile_image_filename = None

        if profile_image and profile_image.filename:
            profile_image_filename = str(uuid.uuid4()) + "_" + secure_filename(profile_image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], profile_image_filename)
            profile_image.save(filepath)

            cursor.execute("""
                UPDATE users SET name=%s, school=%s, department=%s, profile_image=%s
                WHERE id = %s
            """, (name, school, department, profile_image_filename, session['user_id']))
        else:
            cursor.execute("""
                UPDATE users SET name=%s, school=%s, department=%s
                WHERE id = %s
            """, (name, school, department, session['user_id']))

        conn.commit()
        conn.close()

        return redirect('/profile')

    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    return render_template('edit_profile.html', user=user)


# 프로필
@app.route('/profile')
def my_profile():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    return render_template('profile.html', user=user)

# 다른 사람 프로필 보기
@app.route('/profile/<int:user_id>')
def view_other_profile(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return "존재하지 않는 사용자입니다.", 404
    return render_template('profile.html', user=user)

# 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        name = request.form['name']
        school = request.form['school']
        department = request.form['department']

        if not re.match(r'^[a-z0-9]{4,20}$', username):
            flash("⚠️ 아이디는 소문자와 숫자만 사용, 4~20자여야 합니다.")
            return render_template('signup.html', username=username, email=email, name=name, school=school, department=department)

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+]).{8,}$', password):
            flash("⚠️ 비밀번호는 8자 이상이며, 영문자/숫자/특수문자를 포함해야 합니다.")
            return render_template('signup.html', username=username, email=email, name=name, school=school, department=department)

        if password != confirm_password:
            flash("⚠️ 비밀번호가 서로 일치하지 않습니다.")
            return render_template('signup.html', username=username, email=email, name=name, school=school, department=department)

        hashed = generate_password_hash(password)

        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password, name, school, department) VALUES (%s, %s, %s, %s, %s, %s)",
                (username, email, hashed, name, school, department)
            )
            conn.commit()
        except pymysql.err.IntegrityError:
            flash("⚠️ 이미 존재하는 사용자입니다.")
            return render_template('signup.html', username=username, email=email, name=name, school=school, department=department)
        finally:
            conn.close()

        flash("🎉 회원가입이 완료되었습니다! 로그인 해주세요.")
        return redirect('/login')

    return render_template('signup.html')

# 유저 중복 체크
@app.route('/check_username', methods=['POST'])
def check_username():
    username = request.form['username']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    return 'taken' if user else 'available'

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/')
        else:
            flash("⚠️ 로그인 정보가 올바르지 않습니다.")
            return redirect('/login')

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# 아이디, 비밀번호 찾기
@app.route('/find', methods=['GET', 'POST'])
def find_account():
    if request.method == 'POST':
        mode = request.form['mode']
        email = request.form['email']
        username = request.form.get('username')
        conn = get_connection()
        cursor = conn.cursor()

        if mode == 'find_id':
            cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            conn.close()
            if user:
                flash(f"🎉 당신의 아이디는: {user['username']} 입니다.")
            else:
                flash("⚠️ 일치하는 사용자 정보가 없습니다.")

        elif mode == 'find_pw':
            if not username:
                return render_template('find_account.html')

            cursor.execute("SELECT * FROM users WHERE username = %s AND email = %s", (username, email))
            user = cursor.fetchone()
            conn.close()

            if user:
                token = s.dumps(email, salt='pw-reset')
                reset_url = url_for('reset_password', token=token, _external=True)

                msg = Message('[비밀번호 재설정] 링크입니다',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
                msg.body = f'''안녕하세요!

            요청하신 비밀번호 재설정 링크는 아래와 같습니다:

            {reset_url}

            위 링크는 30분 후 만료됩니다.
            문의사항이 있으면 관리자에게 연락주세요.
            '''

                try:
                    mail.send(msg)
                    flash("비밀번호 재설정 링크를 이메일로 전송했습니다.")
                except Exception as e:
                    print("메일 전송 실패:", e)
                    flash("⚠️ 이메일 전송 중 오류가 발생했습니다.")

    return render_template('find_account.html')

# 비밀번호 재설정
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='pw-reset', max_age=1800)
    except itsdangerous.BadSignature:
        return "링크가 유효하지 않거나 만료되었습니다.", 400

    if request.method == 'POST':
        new_pw = request.form['new_password']

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\.]).{8,}$', new_pw):
            flash("⚠️ 비밀번호는 8자 이상이며, 영문자/숫자/특수문자를 포함해야 합니다.")
            return render_template('reset_password.html')

        hashed_pw = generate_password_hash(new_pw)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        conn.commit()
        conn.close()

        flash("비밀번호가 성공적으로 변경되었습니다.")
        return redirect('/login')

    return render_template('reset_password.html')

# 회원 탈퇴
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        input_pw = request.form['password']
        user_id = session['user_id']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], input_pw):
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            conn.close()
            session.clear()
            flash("회원 탈퇴가 완료되었습니다.")
            return redirect('/')
        else:
            conn.close()
            flash("⚠️ 비밀번호가 일치하지 않습니다.")
            return render_template('confirm_delete.html')

    return render_template('confirm_delete.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
