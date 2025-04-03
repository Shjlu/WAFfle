from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, BooleanField, 
    SubmitField, IntegerField, FieldList, FormField,
    Form
    )
from wtforms.validators import DataRequired
from .db import db, User, WebsiteAddress
from typing import Any, List, Mapping, Sequence, Optional

class InvalidString(Exception):
    pass

class IpForm(Form):
    ip = StringField('ip', validators=[DataRequired()])
    port = IntegerField('port', validators=[DataRequired()])

    def validate(self, extra_validators: Optional[Mapping[str, Sequence[Any]]] = None) -> bool:
        initial_validation = super().validate(extra_validators)
        if not initial_validation:
            return False

        if self.port.data < 0 or self.port.data > 65535:
            self.port.errors.append("Port must be between 0-65535")
            return False

        ip_ = self.ip.data.split('.')
        if len(ip_) != 4:
            self.ip.errors.append("Ip must be made from four numbers between 0-255 seperated by '.'")
            return False     
        for i in ip_:
            try:
                i = int(i)
            except:
                self.ip.errors.append("ip must be made from numbers")
                return False
            
            if i < 0 or i > 255:
                self.ip.errors.append("Ip must be made from four numbers between 0-255 seperated by '.'")
                return False

        return True

class EndpointWhitelistForm(Form):
    endpoint = StringField('Endpoint', validators=[DataRequired()])
    SQLi = BooleanField('Ignore SQLi attacks?', default=False)
    XXE = BooleanField('Ignore XXE attacks?', default=False)
    DT = BooleanField('Ignore DT attacks?', default=False)

class UsernamePasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

    def validate(self, extra_validators=None):
        initial_validation = super(UsernamePasswordForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        user = db.session.query(User).filter_by(username=self.username.data).first()
        if not user:
            self.username.errors.append('User doesnt exist')
            return False
        if not user.verify_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False
        return True

class WebsiteForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    addresses = FieldList(FormField(IpForm), min_entries=1)
    blocked_countries = StringField('Blocked countries (country codes separated with commas)')
    endpoints = FieldList(FormField(EndpointWhitelistForm))
    submit = SubmitField('Add website!')

