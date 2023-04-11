from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegistrationForm(FlaskForm):
    username = StringField("Enter username", validators=[DataRequired()])
    email = EmailField("Enter your email", validators=[DataRequired()])
    password = PasswordField("Enter password here", validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = EmailField("Enter your email", validators=[DataRequired()])
    password = PasswordField("Enter password here", validators=[DataRequired()])
    submit = SubmitField('Submit')

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment")
    submit = SubmitField('Submit Comment')
