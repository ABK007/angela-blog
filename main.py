from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuring for user login and logout
login_manager = LoginManager()
login_manager.init_app(app)


# Managing the logged-in user session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# images of the commenters by gravatar flask module
gravatar = Gravatar(app,
                    size=300,
                    rating='g',
                    default='monsterid',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")  # relationship with Blog_post table
    comments = relationship("Comment", back_populates="comment_author") # relationship with comment table


db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # defining foreign key
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post") # relationship with comments table


db.create_all()


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(350), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")  # relationship with user table

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))  # defining foreign key
    parent_post = relationship("BlogPost", back_populates="comments") # relationship with Blog_post table


db.create_all()


@app.route('/')
def get_all_posts():

    # Authenticate user to show blogs otherwise redirect to login page
    if current_user.is_authenticated:
        posts = BlogPost.query.all()
    else:
        return redirect(url_for('login'))

    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    new_user = User()  # User class instance

    register_form = RegistrationForm()  # Registration form instance

    if request.method == "POST":
        # Registering new user
        if register_form.validate_on_submit():

            # User already exists
            if User.query.filter_by(email=register_form.email.data).first():
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))

            # new user
            else:
                new_user.name = register_form.username.data
                new_user.email = register_form.email.data
                # hashing and salting the user password
                hashed_password = generate_password_hash(password=register_form.password.data, salt_length=8)
                new_user.password = hashed_password

                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()  # Login form instance

    if request.method == "POST":
        email = None
        password = None

        if login_form.validate_on_submit():
            email = login_form.email.data
            password = login_form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("This email does not exist, please try again ")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    comment_form = CommentForm()
    new_comment = Comment()

    if request.method == "POST":
        if comment_form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("You need to login or register to comment.")
                return redirect(url_for("login"))
            else:
                new_comment.text = comment_form.comment.data
                new_comment.comment_author = current_user
                new_comment.parent_post = requested_post

                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", post=requested_post, cform=comment_form, current_user=current_user,
                           comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if request.method == "POST":

        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
