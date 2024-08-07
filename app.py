from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt
import datetime
from functools import wraps
from dotenv import load_dotenv
import os

# .env 파일 로드
load_dotenv()

app = Flask(__name__)

# 환경 변수에서 secret key 로드
app.secret_key = os.getenv('SECRET_KEY')

# MongoDB 설정
client = MongoClient('mongodb://localhost:27017/')
db = client['balancegamedb']
Member_collection = db['Member']

# 사용자명(id)에 대한 고유 인덱스 생성
Member_collection.create_index('id', unique=True)

# JWT 토큰을 요구하는 데코레이터
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        elif 'token' in session:
            token = session['token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Member_collection.find_one({'id': data['user']})
            if current_user is None:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


# 홈 페이지
@app.route('/')
def home():
    return render_template('index.html')

# 로그인 페이지 및 처리
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['id']
        password = request.form['password']

        user = Member_collection.find_one({'id': user_id})

        if user and check_password_hash(user['password'], password):
            token = jwt.encode({
                'user': user_id,
                'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            session['token'] = token
            return redirect(url_for('home'))
        else:
            return render_template('login.html', message="유효하지 않은 아이디거나 비밀번호가 틀렸습니다.", error=True)
    return render_template('login.html')

# 회원가입 페이지 및 처리
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form['nickname']
        user_id = request.form['id']
        password = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        existing_user = Member_collection.find_one({'id': user_id})
        if existing_user:
            return render_template('register.html', message="User already exists", error=True)

        Member_collection.insert_one({
            'nickname': nickname,
            'id': user_id,
            'password': hashed_password,
            'birthday': birthday,
            'gender': gender,
            'participant_questions': [],
            'create_questions': []
        })
        return render_template('login.html', message="You have successfully registered!", error=False)

    return render_template('register.html')

# 보호된 페이지
@app.route('/protected')
@token_required
def protected(current_user):
    return render_template('protected.html', current_user=current_user)

# 마이페이지
@app.route('/mypage', methods = ['GET'])
@token_required
def mypage(current_user):
    return render_template('mypage.html', current_user=current_user)

# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('token', None)
    flash('You have successfully logged out', 'success')
    return redirect(url_for('home'))

# 질문 페이지
@app.route('/question', methods=['GET'])
def question():
    if 'like_count' not in session:
        session['like_count'] = 10  # 기본 좋아요 수
    if 'click_count' not in session:
        session['click_count'] = 10  # 기본 클릭 수
    return render_template('question.html', like_count=session['like_count'], click_count=session['click_count'])

# 좋아요 수 증가 라우트
@app.route('/increment_like', methods=['POST'])
def increment_like():
    if 'like_count' in session:
        session['like_count'] += 1
        return jsonify({'like_count': session['like_count']})
    return jsonify({'error': 'Like count not found'}), 400

# 클릭 수 증가 라우트
@app.route('/increment_click', methods=['POST'])
def increment_click():
    if 'click_count' in session:
        session['click_count'] += 1
        return jsonify({'click_count': session['click_count']})
    return jsonify({'error': 'Click count not found'}), 400

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
