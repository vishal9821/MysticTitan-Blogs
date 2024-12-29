from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField , PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField



# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


#Create a RegisterForm to register new users
class CreateRegisterForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired()])
    name = StringField('Name',validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    c_password = PasswordField("Confirm Password",validators=[DataRequired()])
    submit = SubmitField('Sign Up')

# Create a LoginForm to login existing users
class CreateLoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField('Login')


#Create a CommentForm so users can leave comments below posts
class CreateCommentForm(FlaskForm):
    text = CKEditorField('Comment')
    submit = SubmitField('Submit')

#otp check form
class CreateOptCheckForm(FlaskForm):
    otp = StringField("OTP",validators=[DataRequired()])
    submit = SubmitField('Submit')

class CreateResetPasswordForm(FlaskForm):
    password = PasswordField('password',validators=[DataRequired()])
    confirm = PasswordField('confirm password',validators=[DataRequired()])
    submit = SubmitField('Submit')

class CreateFinduserForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired()])
    submit = SubmitField('Find Me!')