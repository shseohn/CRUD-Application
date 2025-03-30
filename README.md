# 📝 Flask Bulletin Board Project

A simple web-based bulletin board application built with Python Flask and MySQL.  
Includes user registration, login/logout, post creation/editing/deletion, file upload, private posts, and search functionality.

---

## 🚀 Features

- User sign-up, login, and logout
- Create, edit, delete posts
- Public/private posts with optional password
- File attachments
- Search by title/content or both
- Profile viewing and editing
- Password reset via email
- Session handling with Flash messaging

---

## 🛠️ Tech Stack

- Python 3.x
- Flask
- MySQL
- PyMySQL
- Jinja2 Templating
- HTML / CSS
- Flask-Mail
- `python-dotenv` for environment variable management
- Werkzeug for password hashing

---

## 📦 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/shseohn/CRUD-Application.git
cd CRUD-Application
```

### 2. (Optional) Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create `.env` file

Copy `.env.example` to `.env` and configure your database and email credentials:

```bash
cp .env.example .env
```

Example:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=flask_board
SECRET_KEY=your_secret_key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_app_password
```

> 💡 For Gmail with 2FA, generate an App Password: https://support.google.com/accounts/answer/185833?hl=en

---

### 5. Create database and tables

In MySQL:

```sql
CREATE DATABASE flask_board DEFAULT CHARACTER SET utf8mb4;

USE flask_board;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(100),
    school VARCHAR(100),
    department VARCHAR(100),
    profile_image VARCHAR(255)
);

CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_private TINYINT(1) DEFAULT 0,
    filename VARCHAR(255),
    password VARCHAR(255), -- deprecated
    post_password VARCHAR(255),
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```
---

## 🖥️ Run the App

```bash
python app.py
```

Server will start at [http://localhost:5000](http://localhost:5000) 🚀

---

## 📁 Project Structure

```
CRUD-Application/
├── app.py
├── requirements.txt
├── .env
├── .env.example
├── static/
│   ├── images/
│   │   └── profile.png 
│   └── style.css
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── write.html
│   └── ...
├── uploads/
└── README.md
```

---
