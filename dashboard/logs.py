import socket
import struct
from .db import db, Logs
from flask import (
    render_template, Blueprint
)
from .auth import loginRequired

bp = Blueprint('logs', __name__, url_prefix='/logs')


def get_logs():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 7070))
    sock.settimeout(3)
    sock.send(b"2")
    logs_length = sock.recv(4)

    logs_length = struct.unpack(">I", logs_length)

    logs = sock.recv(logs_length[0]).decode()
    sock.close()
    return logs


@bp.route('/')
@loginRequired
def logs():
    all_logs_from_db = db.session.execute(db.select(Logs)).scalars().all()
    return render_template('logs.html', current_endpoint="logs", logs=all_logs_from_db)
