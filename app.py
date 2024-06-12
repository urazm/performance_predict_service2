# app.py
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from config import Config
import joblib

app = Flask(__name__)
app.config.from_object(Config)

jwt = JWTManager(app)
db.init_app(app)

with app.app_context():
    db.create_all()

model_grant = joblib.load('models/itis_grant_model.pkl')

model_student_performance = joblib.load('models/student_performance_model.pkl')


@app.route('/grant_predict', methods=['POST'])
@jwt_required()
def grant_predict():
    data = request.json
    average_score = data['average_score']
    grant_student_count = data['grant_student_count']
    grant_student_applied = data['grant_student_applied']

    input_data = [[average_score, grant_student_count, grant_student_applied]]

    prediction = model_grant.predict(input_data)

    response = {'prediction': prediction[0]}
    return jsonify(response), 200


@app.route('/predict_student_score', methods=['POST'])
@jwt_required()
def predict_student_score():
    data = request.json
    m_edu = data['mEdu']
    f_edu = data['fEdu']
    study_time = data['studyTime']
    failures = data['failures']
    support = data['support']
    higher = data['higher']
    absences = data['absences']

    input_data = [[m_edu, f_edu, study_time, failures, support, higher, absences]]
    prediction = model_student_performance.predict(input_data)

    response = {'score': prediction[0]}
    return jsonify(response), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"msg": "User already exists"}), 400

    password_hash = generate_password_hash(password)
    new_user = User(username=username, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password_hash, password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
