from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from passlib.hash import pbkdf2_sha256 as sha256
import re

# Init app
app = Flask(__name__)
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost:5432/db?sslmode=disable'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# Init db
db = SQLAlchemy(app)
api = Api(app).default_namespace

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)


class User(db.Model):
    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, password_hash):
        return sha256.verify(password, password_hash)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100))
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(10))

    def __init__(self, username, email, password, role):
        self.username = username
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.email = email
        else:
            raise Exception("Incorrect email")
        self.password_hash = self.generate_hash(password)
        if role in ('customer', 'chef', 'manager'):
            self.role = role
        else:
            raise Exception("Incorrect role")


class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    dish_description = db.Column(db.String)
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)

    def __init__(self, name, dish_description, price, quantity):
        self.name = name
        self.dish_description = dish_description
        if price >= 0:
            self.price = price
        else:
            raise Exception("Incorrect price")
        if quantity >= 0:
            self.quantity = quantity
        else:
            raise Exception("Incorrect quantity")


dishRegistrationFields = api.model('dish registration model', {
    'name': fields.String(description='name', required=True),
    'dish_description': fields.String(description='dish_description', required=True),
    'price': fields.Float(description='price', required=True),
    'quantity': fields.Integer(description='quantity', required=True)
})

userRegistrationFields = api.model('user registration model', {
    'username': fields.String(description='username', required=True),
    'email': fields.String(description='user email', required=True),
    'password': fields.String(description='password', required=True),
    'role': fields.String(description='user role', required=True)
})

userAuthenticationFields = api.model('user authentication model', {
    'email': fields.String(description='user email', required=True),
    'password': fields.String(description='password', required=True)
})


@api.route("/dish")
class DishRegistration(Resource):
    @jwt_required()
    @api.doc(body=dishRegistrationFields)
    def post(self):
        try:
            email = get_jwt_identity()
        except Exception:
            resp = jsonify({'message': 'incorrect jwt token'})
            resp.status_code = 401
            return resp
        user = db.session.query(User).filter_by(email=email).first()
        if user.role != 'manager':
            resp = jsonify({'message': 'user isnt manager'})
            resp.status_code = 401
            return resp

        try:
            name = request.json['name']
            dish_description = request.json['dish_description']
            price = request.json['price']
            quantity = request.json['quantity']
        except Exception:
            resp = jsonify({'message': 'Missing field(s)'})
            resp.status_code = 400
            return resp

        try:
            new_dish = Dish(name, dish_description, price, quantity)
        except Exception as err:
            resp = jsonify({'message': 'Failed to register - ' + str(err)})
            resp.status_code = 401
            return resp
        db.session.add(new_dish)
        db.session.commit()
        resp = jsonify({'message': 'Registration completed successfully'})
        resp.status_code = 200

        return resp


@api.route("/menu")
class DishesMenu(Resource):
    def get(self):
        menu = db.session.query(Dish).filter(Dish.quantity > 0).all()
        list_dish_dicts = []
        for dish in menu:
            r = dict(dish.__dict__)
            del r['_sa_instance_state']
            list_dish_dicts.append(r)
        resp = jsonify(list_dish_dicts)
        resp.status_code = 200
        return resp


@api.route("/auth")
class UserAuthentication(Resource):
    @api.doc(body=userAuthenticationFields)
    def post(self):
        email = request.json['email']
        password = request.json['password']
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if User.verify_hash(password, user.password_hash):
                access_token = create_access_token(identity=email)
                resp = jsonify({'message': 'Auth completed successfully, JWT token:' + access_token})
                resp.status_code = 200
            else:
                resp = jsonify({'message': 'Incorrect password'})
                resp.status_code = 401
        else:
            resp = jsonify({'message': 'Incorrect email'})
            resp.status_code = 401
        return resp


@api.route("/user")
class UserRegistration(Resource):
    @api.doc(body=userRegistrationFields)
    def post(self):
        try:
            username = request.json['username']
            email = request.json['email']
            password = request.json['password']
            role = request.json['role']
        except Exception:
            resp = jsonify({'message': 'Missing field(s)'})
            resp.status_code = 400
            return resp

        try:
            new_user = User(username, email, password, role)
        except Exception as err:
            resp = jsonify({'message': 'Failed to register - ' + str(err)})
            resp.status_code = 401
            return resp

        try:
            db.session.add(new_user)
            db.session.commit()
            resp = jsonify({'message': 'Registration completed successfully'})
            resp.status_code = 200
        except Exception:
            resp = jsonify({'message': 'Failed to register - user with such username or email already registered'})
            resp.status_code = 401
        return resp


@api.route("/user_info")
class UserInfo(Resource):
    @jwt_required()
    def get(self):
        try:
            email = get_jwt_identity()
        except Exception:
            resp = jsonify({'message': 'incorrect jwt token'})
            resp.status_code = 401
            return resp
        user = db.session.query(User).filter_by(email=email).first()
        resp = jsonify({'username': user.username, 'email': email, 'role': user.role})
        resp.status_code = 200
        return resp


if __name__ == '__main__':
    app.run(debug=True)
