import socket
import struct
from flask import (
    render_template, Blueprint
)
from .auth import loginRequired

bp = Blueprint('blockadblock', __name__, url_prefix='/blockadblock')

@bp.route('/')
@loginRequired
def blockadblock():
    return render_template('blockadblock.html', current_endpoint = "blockadblock")
