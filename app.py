from flask import Flask, render_template, request, redirect

import pymysql

app = Flask(__name__)

def get_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='0000',
        db='flask_board',
        charset='utf8',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def home():
    conn = get_connection()
    cursor = conn.cursor()
    sql = "SELECT * FROM posts ORDER BY created_at DESC"
    cursor.execute(sql)
    posts = cursor.fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/write', methods=['GET'])
def write_form():
    return render_template('write.html')

@app.route('/write', methods=['POST'])
def write_post():
    title = request.form['title']
    content = request.form['content']

    conn = get_connection()
    cursor = conn.cursor()
    sql = "INSERT INTO posts (title, content) VALUES (%s, %s)"
    cursor.execute(sql, (title, content))
    conn.commit()
    conn.close()

    return redirect('/')

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    sql = "SELECT * FROM posts WHERE id = %s"
    cursor.execute(sql, (post_id,))
    post = cursor.fetchone()
    conn.close()

    if post:
        return render_template('detail.html', post=post)
    else:
        return "글을 찾을 수 없습니다.", 404

@app.route('/edit/<int:post_id>', methods=['GET'])
def edit_form(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    sql = "SELECT * FROM posts WHERE id = %s"
    cursor.execute(sql, (post_id,))
    post = cursor.fetchone()
    conn.close()

    if post:
        return render_template('edit.html', post=post)
    else:
        return "글을 찾을 수 없습니다.", 404

@app.route('/edit/<int:post_id>', methods=['POST'])
def edit_post(post_id):
    title = request.form['title']
    content = request.form['content']

    conn = get_connection()
    cursor = conn.cursor()
    sql = "UPDATE posts SET title=%s, content=%s WHERE id=%s"
    cursor.execute(sql, (title, content, post_id))
    conn.commit()
    conn.close()

    return redirect(f'/post/{post_id}')

@app.route('/delete/<int:post_id>')
def delete_post(post_id):
    conn = get_connection()
    cursor = conn.cursor()
    sql = "DELETE FROM posts WHERE id = %s"
    cursor.execute(sql, (post_id,))
    conn.commit()
    conn.close()

    return redirect('/')

@app.route('/search')
def search():
    keyword = request.args.get('keyword')
    option = request.args.get('option')

    conn = get_connection()
    cursor = conn.cursor()

    if option == 'title':
        sql = "SELECT * FROM posts WHERE title LIKE %s ORDER BY created_at DESC"
    elif option == 'content':
        sql = "SELECT * FROM posts WHERE content LIKE %s ORDER BY created_at DESC"
    else:  # 제목 + 내용
        sql = "SELECT * FROM posts WHERE title LIKE %s OR content LIKE %s ORDER BY created_at DESC"

    search_keyword = f"%{keyword}%"

    if option in ['title', 'content']:
        cursor.execute(sql, (search_keyword,))
    else:
        cursor.execute(sql, (search_keyword, search_keyword))

    posts = cursor.fetchall()
    conn.close()

    return render_template('index.html', posts=posts)

if __name__ == '__main__':
    app.run(debug=True)
