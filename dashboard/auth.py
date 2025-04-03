from functools import wraps
from flask import (
    Blueprint, redirect, request, session, render_template, url_for
)
from .db import db, User
from .forms import UsernamePasswordForm 
bp = Blueprint('auth', __name__, url_prefix='/auth')

def loginRequired(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        else:
            return func(*args, **kwargs)
    return wrapper


@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = UsernamePasswordForm()
    if form.validate_on_submit():
        session['username'] = form.username
        if form.remember_me:
            session.permanent = True
        return redirect(url_for('index.index'))
                
    return render_template('login.html', form=form) 

@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('auth.login'))