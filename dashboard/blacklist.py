from .db import db, BlackListEntry
from flask import (
    render_template, Blueprint, request, redirect, url_for
)
from .auth import loginRequired

bp = Blueprint('blacklist', __name__, url_prefix='/blacklist')


@bp.route('/')
@loginRequired
def blacklist():
    blacklist = db.session.execute(db.select(BlackListEntry)).scalars().all()
    return render_template('blacklist.html', blacklist=blacklist, current_endpoint = "blacklist")

@bp.route('/remove_entries', methods=['POST'])
@loginRequired
def remove_entries():
    entries = request.form.getlist('ips[]')
    for entry in entries:
        row = db.session.execute(db.select(BlackListEntry).filter_by(ip=entry)).scalars().first()
        db.session.delete(row)
    db.session.commit()
    return redirect(url_for('blacklist.blacklist'))