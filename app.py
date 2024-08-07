from flask import Flask, render_template, jsonify, request
from flask.json.provider import JSONProvider
from pymongo import MongoClient
from bson import ObjectId
from bson.json_util import dumps
import json
import datetime

app = Flask(__name__)

client = MongoClient('mongodb+srv://chris309804:1234@cluster0.z80vjt6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client.db_jungle

#######################################################################
# MongoDB 조회 결과를 jsonify 메서드를 통해 JSON으로 만들 때 
# MongoDB의 ObjectId를 파이썬의 문자열 타입으로 변환해주는 부분
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime.datetime):
            return o.strftime('%Y년 %m월 %d일 %H시 %M분')
        return json.JSONEncoder.default(self, o)


class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)

app.json = CustomJSONProvider(app)
#######################################################################

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/api/question/list', methods=['GET'])
def list_question():

    category_mode = request.args.get('category_mode', 'life')
    sort_mode = request.args.get('sortMode', 'likes') # 기본 정렬 값: 좋아요 순
    is_desc = -1                                      # 기본 정렬 방향: 내림차순
    questions = db.questions.find({}, { 'category' : category_mode }).sort({ sort_mode: is_desc })

    return render_template('index.html')

@app.route('/api/question/like', methods=['POST'])
def like_question():
    id_receive = request.form['id_give']
    current_likes = db.memos.find_one({'_id': ObjectId(id_receive)})['likes']
    new_likes = current_likes + 1
    db.questions.update_one({'_id': ObjectId(id_receive)}, {'$set': {'likes': new_likes}})
    return jsonify({ 'result': 'success' })

if __name__ == '__main__':  
    app.run('0.0.0.0',port=5000,debug=True)