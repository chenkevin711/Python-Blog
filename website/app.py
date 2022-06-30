from flask import Flask, render_template, flash, redirect, request, session, url_for, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import TIMESTAMP, func
from io import BytesIO
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')
app.url_map.strict_slashes = False

app.config['SECRET_KEY'] = "b'\x00\xb4\x8d\xbe\xf8\xa3\x1e;l\xf4,\x12'"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///MakePosts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# init blog database
class Posts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timeCreated = db.Column(TIMESTAMP, nullable=False, server_default=func.now())
    title = db.Column(db.String(), unique=False, nullable=False)
    content = db.Column(db.String(), unique=False, nullable=False)
    fileName = db.Column(db.String())
    fileData = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    posts = db.relationship('Posts')

# reduce unexpected url errors
@app.before_request
def clear_trailing():
    from flask import redirect, request

    rp = request.path
    if rp != '/' and rp.endswith('/'):
        return redirect(rp[:-1])


# index page, view all blog posts
@app.route("/")
@login_required
def index():
    allPosts = Posts.query.all()
    allPosts.reverse()


    return render_template('index.html', posts=allPosts)


@app.route("/database")
@login_required
def database():
    allPosts = Posts.query.all()

    return render_template('fileDataBase.html', posts=allPosts)


# view a blog post
@app.route("/<int:post_id>")
@login_required
def posts(post_id):
    postID = Posts.query.filter_by(id=post_id).first()

    return render_template('posts.html', post=postID)


# display the file of a blog post
@app.route("/<int:post_id>/display")
@login_required
def display(post_id):
    postID = Posts.query.filter_by(id=post_id).first()

    return send_file(BytesIO(postID.fileData), download_name=postID.fileName)


# download a post's file
@app.route("/<int:post_id>/download")
@login_required
def download(post_id):
    postID = Posts.query.filter_by(id=post_id).first()

    return send_file(BytesIO(postID.fileData), attachment_filename=postID.fileName, as_attachment=True)


# create a blog post
@app.route("/createPost", methods=('GET', 'POST'))
@login_required
def createPost():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files['file']
        user_id = current_user.id

        if not title:
            flash('Title is required!')
        else:
            new_post = Posts(title=title, content=content, fileName=file.filename, fileData=file.read(), user_id=user_id)
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('index'))

    return render_template('createPost.html', user=current_user)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash('Incorrect Password, Try Again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash("Email must be greater than 3 characters.", category='error')
        elif len(first_name) < 2:
            flash("First name must be greater than 1 character", category='error')
        elif password1 != password2:
            flash("Passwords don\'t match.", category='error')
        elif len(password1) < 7:
            flash("Passwords must be at least 7 characters", category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account Created!", category='success')
            return redirect(url_for('index'))


    return render_template("sign_up.html", user=current_user)

@app.route("/<int:post_id>/delete_post", methods=['GET','POST'])
def delete_post(post_id):
    postID = Posts.query.filter_by(id=post_id).first()
    try:
        db.session.delete(postID)
        db.session.commit()
        flash("Post was Deleted!", category="success")
        return redirect(url_for('index'))
    except:
        flash("Error", category='error')
        return redirect(url_for('database'))

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
    