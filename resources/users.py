from flask import Flask, jsonify
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from db import db
from flask.views import MethodView 
from dotenv import load_dotenv
from schemas import UserRegisterSchema, UserLoginSchema, UserTokenSchema
from passlib.hash import pbkdf2_sha256
from models.users import UserModel
from flask_smorest import Blueprint, abort
from sqlalchemy import or_



blp = Blueprint("stores", __name__, description="User APIs")

load_dotenv()

app = Flask(__name__)

@blp.route('/register')
class UserRegister(MethodView):
    @blp.arguments(UserRegisterSchema)
    def post(self, user_data):
        if UserModel.query.filter(
            or_(
                UserModel.username == user_data['username'],
                UserModel.password == user_data['password']
            )
        ).first():
            abort(400, message='User already exists')
        
        user = UserModel(
            username = user_data['username'], quote = user_data['quote'], password = pbkdf2_sha256.hash(user_data['password']))
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'Registered successfully'})

@blp.route('/login')
class UserLogin(MethodView):
    @blp.arguments(UserLoginSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            or_(
                UserModel.username == user_data['username'], 
                )
            ).first()
        if user and pbkdf2_sha256.verify(user_data['password'], user.password):
            access_token = create_access_token(identity=user.id, fresh = True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}
        abort (401, message = 'Invalid credentials')


@blp.route('/protected')
class Protected(MethodView):
    # @blp.arguments(UserTokenSchema)
    @jwt_required(refresh = True)
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = UserModel.query.get(current_user_id)
        if not current_user:
            abort(401, message = 'User does not exist')
        return jsonify({"current_user": current_user.username, "quote": current_user.quote})
