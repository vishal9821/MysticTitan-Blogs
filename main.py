from datetime import date, datetime
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import os
from random import randint
# Import your forms from the forms.py

from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm, CreateOptCheckForm,CreateFinduserForm, CreateResetPasswordForm

EMAIL = os.getenv('email')
PASSWORD = os.getenv('password')
RECEIVER = os.getenv('rec')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('key')
ckeditor = CKEditor(app)
Bootstrap5(app)

#for current year for copyright
@app.context_processor
def inject_year():
    return {'current_year':datetime.now().year}

#gravatar initialization
gravatar = Gravatar(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)

def admin_only(f):
    @wraps(f)
    @login_required
    def decorative_function(*args,**kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorative_function

def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(db.Model,UserMixin):
    __tablename__ = "user_data"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email:Mapped[str] = mapped_column(String(200),unique=True,nullable=False)
    password:Mapped[str] = mapped_column(String(250),nullable=False)
    name:Mapped[str] = mapped_column(String(250),nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user_data.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = 'comments'
    id:Mapped[int] = mapped_column(Integer,primary_key=True)
    text:Mapped[str] = mapped_column(String(500),nullable=False)
    author_id :Mapped[int] = mapped_column(Integer,db.ForeignKey('user_data.id'))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=['GET','POST'])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.c_password.data:
            flash("Password mismatch please try again !")
            return redirect(url_for('register'))
        else:
            salted_password = generate_password_hash(form.password.data,'scrypt',salt_length=8)
            otp = randint(100000,999999)
            new_user = {
                'name':form.name.data,
                'email':form.email.data,
                'password':salted_password
            }
            with app.app_context():
                existing_user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
                if existing_user:
                    flash('You already sign up with this email please login instead')
                    return redirect(url_for('login'))
                else:
                    text = f"subject: From MysticTitan Blogs\n\nHere is Your OTP: {otp}\nValid for 5 minutes."
                    with smtplib.SMTP("smtp.gmail.com",587) as connection:
                        connection.starttls()
                        connection.login(user=EMAIL, password=PASSWORD)
                        connection.sendmail(from_addr=new_user['email'], to_addrs=form.email.data, msg=text)
                    session['otp'] = otp
                    session['user'] = new_user
                    session['finduser'] = None
                    return redirect(url_for('otpverification'))
    return render_template("register.html",form=form)

#reset password
@app.route('/reset',methods=['GET','POST'])
def resetpassword():
    form = CreateResetPasswordForm()
    user = session.get('finduser')
    if form.validate_on_submit():
        if form.password.data != form.confirm.data:
            flash('Password mismatch please try again !')
            return redirect(url_for('resetpassword'))
        else:
            salted_password = generate_password_hash(form.password.data, 'scrypt', salt_length=8)
            with app.app_context():
                existed_user = db.session.execute(db.select(User).where(User.email == user)).scalar()
                if existed_user:
                    existed_user.password = salted_password
                    db.session.commit()
                    login_user(existed_user)
                    flash("Password Updated Successfully")
                    return redirect(url_for('get_all_posts'))
                else:
                    flash("Something went wrong please try again later!!")
                    return redirect(url_for('resetpassword'))
    return render_template('reset.html',form=form)

@app.route("/finduser",methods=['GET','POST'])
def finduser():
    form = CreateFinduserForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if not user:
            flash("Email Not Found. Try Again!")
        else:
            otp = randint(100000,999999)
            text = f"subject: From MysticTitan Blogs\n\nHere is Your OTP to reset your password: {otp}\nValid for 5 minutes."
            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.starttls()
                connection.login(user=EMAIL, password=PASSWORD)
                connection.sendmail(from_addr=email, to_addrs=form.email.data, msg=text)
            session['otp'] = otp
            session['user'] = None
            session['finduser'] = user.email
            return redirect(url_for('otpverification'))
    return render_template('finduser.html',form=form)
# otp varifiaction
@app.route('/OTP',methods=['GET','POST'])
def otpverification():
    form = CreateOptCheckForm()
    if form.validate_on_submit():
        enter_otp = int(form.otp.data)
        stored_otp = int(session.get('otp'))
        user_details = session.get('user')
        already_user = session.get('finduser')
        if enter_otp == stored_otp:
            if not already_user:
                new_user = User(
                    email=user_details['email'],
                    password=user_details['password'],
                    name=user_details['name']
                )
                with app.app_context():
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user)
                    return redirect(url_for('get_all_posts'))
            else:
                return redirect(url_for('resetpassword'))
        else:
            flash('Invalid OTP please try again !')
            return render_template('otpcheck.html',form=form)
    return render_template('otpcheck.html',form=form)

#Retrieve a user from the database based on their email.
@app.route('/login',methods=['GET','POST'])
def login():
    form = CreateLoginForm()
    if form.validate_on_submit():
        with app.app_context():
            user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
            if user:
                if check_password_hash(user.password,form.password.data):
                    login_user(user)
                    return redirect(url_for('get_all_posts'))
                else:
                    flash('Incorrect Password please try again!')
            else:
                flash('User not exist check your email !')
    return render_template("login.html",form=form)

#userprofile
@app.route("/userprofile",methods=['GET'])
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost).order_by(BlogPost.id.desc()))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)



@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    form = CreateCommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=form.text.data,post=requested_post,comment_author=current_user)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post',post_id=requested_post.id))
        else:
            flash('Please login or register first for commenting.')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post,form=form)

@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))
# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
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


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        if current_user.is_authenticated:
            name = request.form.get('name')
            mail = request.form.get('email')
            phone = request.form.get('phone')
            message = request.form.get('message')
            text = f"subject:From blog site user {name}\n\nName: {name}\nEmail: {mail}\nPhone: {phone}\nMessage: {message}"
            with smtplib.SMTP("smtp.gmail.com",587) as connection:
                connection.starttls()
                connection.login(user=EMAIL, password=PASSWORD)
                connection.sendmail(from_addr=EMAIL, to_addrs=RECEIVER, msg=text)
            return render_template("contact.html",msg_sent=True)
        else:
            flash("Please login or register first !!")
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
