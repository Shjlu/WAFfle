from email import message
import socket
import struct
import json
from .db import db, Logs
from .logs import get_logs
from flask import (
    render_template, Blueprint, url_for
)
from .auth import loginRequired
from datetime import date
from datetime import timedelta
from enum import Enum

class LogType(Enum):
    PROXY_UP = 1
    PROXY_DOWN = 2
    USER_REQUEST = 4
    ATTACK_ATTEMPT = 8
    BLOCKED_USER_ENTRY = 16


bp = Blueprint('index', __name__, url_prefix='/')



def get_last_week_dates():
    today = date.today()
    last_week_dates = []
    for i in range(0, 7):
        last_week_dates.append(str(today - timedelta(days=i)))
    return last_week_dates


def get_attacks_numbers(all_logs):
    attacks_num = {"DOS": 0, "SQLi": 0, "HTTP SMUGGLING": 0, "DT": 0, "XXE": 0}
    for i in all_logs:
        if "SQL" in i.message.upper():
            attacks_num["SQLi"] += 1
        elif "DOS" in i.message.upper():
            attacks_num["DOS"] += 1
        elif "HTTP SMUGGLING" in i.message.upper():
            attacks_num["HTTP SMUGGLING"] += 1
        elif "DT" in i.message.upper():
            attacks_num["DT"] += 1
        elif "XXE" in i.message.upper():
            attacks_num["XXE"] += 1
    return [[k, v] for k, v in attacks_num.items()]


def get_blocked_users_entries(all_logs):
    blocked_users_entries = {}
    last_week_dates = get_last_week_dates()
    for date in last_week_dates:
        blocked_users_entries[date] = 0

    for log in all_logs:
        if log.log_type == int(LogType.BLOCKED_USER_ENTRY.value):
            for date in last_week_dates:
                if date in log.date:
                    blocked_users_entries[date] += 1
    return [[k, v] for k, v in blocked_users_entries.items()]


@bp.route('/')
@loginRequired
def index():
    all_logs_from_db = db.session.execute(db.select(Logs)).scalars().all()
    all_attacks = get_attacks_numbers(all_logs_from_db)
    all_attacks.insert(0, ["Attack", "Attack times"])
    all_blocked_users_entries = get_blocked_users_entries(all_logs_from_db)
    all_blocked_users_entries.insert(0, ["Blocked Attack Entries", "Attack times"])
    return render_template('index.html', current_endpoint="home", attack_num=json.dumps(all_attacks),
                           blocked_users_entries=json.dumps(all_blocked_users_entries))
