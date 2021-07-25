from flask.globals import request
from flask.helpers import flash
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import *
from flask import Flask, session, flash, redirect, url_for
import sys
app = Flask(__name__)
app.secret_key = "super secret key"

#Хак для того чтобы можно было в режиме отладки или запуска из venv цепляться к sqlite-базе. В проде из докера будет цепляться к postgresql
if len(sys.argv)==2 or __debug__:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://hello_flask:hello_flask@db:5432/hello_flask_dev'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')
    roles = db.relationship('Role', secondary='user_roles')

    def check_password(self, password):
        try:
            return check_password_hash(self.password, password) # from werkzeug.security
        except:
            return False

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

db.create_all()

if not User.query.filter(User.username == 'admin').first():
    user = User(
        username='admin',
        password=generate_password_hash('admin'),
    )
    user.roles.append(Role(name='Admin'))

    role = Role(name='Viewer')
    db.session.add(role)
    db.session.add(user)
    db.session.commit()

@app.route("/login", methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    u = User.query.filter(User.username == username).first()
    
    pass_correct= u.check_password(password)

    if pass_correct==False:
        return 'auth failed'
    else:
        session['role']= u.roles[0].name
        session['logged_in'] = True
        session['username'] = username
        return 'ok'

@app.route("/")
def main():
    if session.get('username')==None:
        return render_template('login.html')
    else:
        return redirect('/users')

@app.route("/users")
@is_logged_in
def list_users():
    users = db.engine.execute(f"SELECT u.id, u.username,u.password, r.name as role FROM USERS as u, roles as r, user_roles as ur where ur.user_id=u.id and ur.role_id=r.id ")
    users = query_to_dict(users)
    return render_template('list_users.html',users = users)

@app.route("/users/create/", methods=['GET', 'POST'])
@is_logged_in
@is_admin
def create_user():
    if request.method == 'GET':
        roles = [x.name for x in Role.query.all()]
        return render_template('create_user.html',roles=roles)
    else:
        new_role = request.json['role']
        new_username = request.json['username']
        new_password = request.json['password']
        
        user = User.query.filter(User.username == new_username).first()
        if user==None:
            user = User(username=new_username, password=generate_password_hash(new_password))
            user.roles.append(Role.query.filter(Role.name==new_role).first())
            db.session.add(user)
            db.session.commit()
            return 'ok'
        else:
            return 'Pls select another login'

@app.route("/users/<int:id>/edit", methods=['GET', 'POST'])
@is_logged_in
@is_admin
def edit_user(id):
    if request.method == 'GET':
        user = User.query.filter(User.id == id).first()
        roles = [x.name for x in Role.query.all()]

        return render_template('edit_user.html',roles=roles, user=user)
    else:
        user_id = request.json['user_id']
        user = User.query.filter(User.id == user_id).first()
        
        new_role = request.json['role']
        new_username = request.json['username']
        new_password = request.json['password']
        
        user.username=new_username
        user.roles[0] = Role.query.filter(Role.name==new_role).first()
        
        if new_password=='':
            return 'password empty'

        if new_password!='its_not_my_password':
            user.password=generate_password_hash(new_password)
        
        db.session.commit()
        return 'ok'

@app.route("/users/<int:id>/delete", methods=['POST'])
@is_logged_in
@is_admin
def delete_user(id):
    user_id = request.json['user_id']
    user = User.query.filter(User.id == user_id).first()
    
    if user.username==session['username']:
        return 'Error deleting current user'
    
    if user.id==1:
        return 'Error deleting global admin'

    db.session.delete(user)    
    db.session.commit()
    return 'ok'

@app.route('/sign_out')
def sign_out():
    session.clear()
    return 'ok'

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')