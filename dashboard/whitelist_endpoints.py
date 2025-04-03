from flask import (
    render_template, Blueprint, request, redirect, url_for
)
from .auth import loginRequired

bp = Blueprint('whitelist_endpoints', __name__, url_prefix='/whitelist_endpoints')

@bp.route('/')
@loginRequired
def whitelist_endpoints():
    
    return