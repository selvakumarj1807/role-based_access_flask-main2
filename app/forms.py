from flask_wtf import FlaskForm
from wtforms import SelectMultipleField, StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo

class RoleForm(FlaskForm):
    role_name = StringField('Role Name', validators=[DataRequired()])
    permissions = SelectMultipleField('Permissions', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Role')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role_name = SelectField('Role', choices=[], validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
