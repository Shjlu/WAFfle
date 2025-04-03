from flask import Flask, render_template, request, make_response, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from .db import db, User, BlackListEntry
from functools import wraps



def create_app():
    # init app
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://waffle:waffle@localhost:9090/waffle"
    app.secret_key = "This is a secret key, I really hope you couldn't guess it because it's secret yknow"

    # init db
    db.init_app(app)
    with app.app_context():
        db.create_all()

    #init views
    from . import auth, logs, blacklist, index, websites, blockadblock
    app.register_blueprint(auth.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(blacklist.bp)
    app.register_blueprint(websites.bp)
    app.register_blueprint(index.bp)
    app.register_blueprint(blockadblock.bp)
    
    return app