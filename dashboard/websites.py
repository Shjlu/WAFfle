from .db import db, WebsiteConfig, WebsiteAddress, WebsiteBlockedCountry, WebsiteWhitelistedEndpoints
from flask import (
    render_template, Blueprint, request, redirect, url_for
)
from .forms import WebsiteForm
from .auth import loginRequired
from typing import List

bp = Blueprint('websites', __name__, url_prefix='/websites')


def boolToEmoji(v):
    return '✅' if v else '❌'

@bp.route('/')
@loginRequired
def websites():
    websites: List[WebsiteConfig] = db.session.execute(
        db.select(WebsiteConfig)
        ).scalars().all()

    payload = []
    for website in websites:
        entry = {'domain': website.domain, 'addresses': '', 'blocked_country_codes': '', 'whitelist_endpoints': '' }
        if website.addresses:
            entry['addresses'] = '<ul>'
            for i in website.addresses:
                entry['addresses'] += f"<li><code>{i.ip}:{i.port}</code></li>"
            entry['addresses'] += '</ul>'

        for i in website.blocked_country_codes:
            entry['blocked_country_codes'] += ''.join(map(lambda x: chr(ord(x) + 127397),i.country.upper()))
        
        if website.whitelisted_endpoints:
            entry['whitelist_endpoints'] = '<table  class="table table-striped"><thead><tr><td scope="col">Endpoint</td><td scope="col">SQLi ignored</td><td scope="col">XXE ignored</td><td scope="col">DT ignored</td></tr></thead><tbody>'
            for i in website.whitelisted_endpoints:
                entry['whitelist_endpoints'] += f"<tr><td>{i.endpoint}</td><td>{boolToEmoji(i.SQLi)}</td><td>{boolToEmoji(i.XXE)}</td><td>{boolToEmoji(i.DT)}</td></tr>"
            entry['whitelist_endpoints'] += "</tbody></table>"
        
        payload.append(entry)

    return render_template('websites.html', websites=payload, current_endpoint = "websites")

@bp.route('/add', methods=['GET', 'POST'])
@loginRequired
def add_website():
    form = WebsiteForm()

    if form.validate_on_submit():
        site = WebsiteConfig()
        site.domain = form.domain.data
        db.session.add(site)
        db.session.flush([site])
        
        for i in form.addresses:
            addr = WebsiteAddress()
            addr.ip = i.ip.data
            addr.port = i.port.data
            addr.website_id = site.id
            db.session.add(addr)
        
        for i in form.blocked_countries.data.split(','):
            if len(i) == 2:
                bc = WebsiteBlockedCountry()
                bc.country = i
                bc.website_id = site.id
                db.session.add(bc)


        for i in form.endpoints:
            e = WebsiteWhitelistedEndpoints()
            e.endpoint = i.endpoint.data
            e.SQLi = i.SQLi.data
            e.DT = i.DT.data
            e.XXE = i.XXE.data
            e.website_id = site.id
            db.session.add(e)

        db.session.commit()
        return redirect(url_for('websites.websites'))

        
    return render_template('add_website.html', form=form)