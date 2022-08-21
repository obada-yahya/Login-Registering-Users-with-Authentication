import flask
import flask_login
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user,\
    logout_user, fresh_login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE TABLE IN DB


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    print("this happens")
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        secure_password = generate_password_hash(request.form["password"], method='pbkdf2:sha256', salt_length=8)
        user = User(email=request.form["email"], password=secure_password, name=request.form["name"])
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('secrets'))
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form['password']
        print(f"the password is {password}")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect("/secrets")
        else:
            return "<h1>You don't have an email with this password in our database</h1>", 401
    return render_template("login.html")


# @login_manager.unauthorized_handler
# def unauthorized():
#     print("Fuck you")
#     return redirect("/")



@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect("/")


@app.route('/download')
def download():
    return send_from_directory("static", "files/cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
