from posixpath import join
from flask import Flask, render_template, request, Response, redirect, flash, abort, url_for
from flask_login.mixins import UserMixin
from flask_wtf import FlaskForm, CSRFProtect
import wifi
from wtforms import BooleanField, FloatField, IntegerField, SelectField, StringField, PasswordField, validators, TextAreaField
from wtforms.fields.core import FormField
from wtforms.fields.simple import SubmitField
from flask_login import LoginManager, login_user, login_required, logout_user
import json
import werkzeug
import os
import subprocess
from wtforms.fields.html5 import EmailField
from wifi import Cell, Scheme, exceptions
import pathlib

config_path = os.path.join(pathlib.Path.home(), ".config/gateway_config")
ttnzh = "/opt/ttn-gateway/bin"
netadapt = "wlan0"

wifiap = []
secret = os.urandom(24).hex()

if not os.path.isdir(config_path):
    os.makedirs(config_path, exist_ok=True)

if not os.path.isfile(os.path.join(config_path, "secret")):
    with open(os.path.join(config_path, 'secret'), 'w') as pa:
        pa.write(werkzeug.security.generate_password_hash(
            "root", method='pbkdf2:sha256', salt_length=16))

if not os.path.isfile(os.path.join(config_path, "config.json")):
    with open(os.path.join(config_path, 'config.json'), 'w') as f:
        json.dump({
            "wifi":
                {"ssid": "", "country": "FR"},
            "ttnzh": ttnzh,
            "secret": secret
        }, f)
else:
    with open(os.path.join(config_path, 'config.json'), 'r') as f:
        j = json.load(f)
        if "ttnzh" in j:
            ttnzh = j["ttnzh"]
        if "secret" in j:
            secret = j['secret']


app = Flask(__name__)
app.config['SECRET_KEY'] = secret
app.config['TEMPLATES_AUTO_RELOAD'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

csrf = CSRFProtect(app)

countries = ["AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR",
             "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE",
             "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO",
             "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY", "CF", "TD",
             "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI",
             "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG",
             "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF",
             "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD",
             "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN",
             "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT",
             "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG",
             "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK",
             "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT",
             "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA",
             "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP",
             "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN",
             "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "BL", "SH", "KN",
             "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC",
             "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES",
             "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ",
             "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV",
             "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN",
             "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"]


# callback to reload the user object
@login_manager.user_loader
def load_user(userid):
    return User(userid)


wpa = """ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country={0}
network={{
	ssid=\"{1}\"
	psk=\"{2}\"
}}
"""


class GatewayConfig(FlaskForm):
    gateway_id = StringField("Gateway ID")
    server_address = StringField("Server address")
    server_port_up = IntegerField()
    server_port_down = IntegerField()
    server_enable = BooleanField()
    latitude = FloatField()
    longitude = FloatField()
    altitude = IntegerField()
    contact_email = EmailField(validators=[])
    description = TextAreaField()
    save = SubmitField()
    reload = SubmitField()
    reboot = SubmitField()


def validate_password(form, field):
    with open(os.path.join(config_path, 'secret'), 'r') as pa:
        hashpass = pa.readline()
    if not werkzeug.security.check_password_hash(hashpass, field.data):
        raise validators.ValidationError('Wrong password')


class WifiForm(FlaskForm):
    activate = BooleanField()
    essid = SelectField("ESSID", coerce=str)
    password = PasswordField("Password", validators=[
                             validators.InputRequired()])
    country = StringField("Country", validators=[validators.InputRequired()])

    def validate_country(form, field):
        if field.data.upper() not in countries:
            raise validators.ValidationError('Unknown country')
    save = SubmitField()
    reload = SubmitField()


class LoginForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired()])
    password = PasswordField(
        validators=[validators.DataRequired(), validate_password])
    submit = SubmitField()


class ChangePass(FlaskForm):
    password = PasswordField(
        validators=[validators.DataRequired(), validate_password])
    password2 = PasswordField(validators=[
        validators.DataRequired(),
        validators.EqualTo(
            'password', message='Passwords must match')])
    newpassword = PasswordField(validators=[validators.DataRequired()])


class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.name = "root"
        self.password = self.name + "_secret"

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)


user = User(0)


def file2form():
    form = GatewayConfig()
    with open(os.path.join(ttnzh, 'local_conf.json'), 'r') as f:
        conf = json.load(f)

    form.server_address.data = conf['gateway_conf']['servers'][0]['server_address']
    form.server_port_up.data = conf['gateway_conf']['servers'][0]['serv_port_up']
    form.server_port_down.data = conf['gateway_conf']['servers'][0]['serv_port_down']
    form.server_enable.checked = conf['gateway_conf']['servers'][0]['serv_enabled']
    form.gateway_id.data = conf['gateway_conf']['gateway_ID']
    form.latitude.data = conf['gateway_conf']['ref_latitude']
    form.longitude.data = conf['gateway_conf']['ref_longitude']
    form.altitude.data = conf['gateway_conf']['ref_altitude']
    form.contact_email.data = conf['gateway_conf']['contact_email']
    form.description.data = conf['gateway_conf']['description']
    return form


def form2file(form):
    with open(os.path.join(ttnzh, 'local_conf.json'), 'r') as f:
        conf = json.load(f)
    conf['gateway_conf']['servers'][0]['server_address'] = form.server_address.data
    conf['gateway_conf']['servers'][0]['serv_port_up'] = form.server_port_up.data
    conf['gateway_conf']['servers'][0]['serv_port_down'] = form.server_port_down.data
    conf['gateway_conf']['servers'][0]['serv_enabled'] = form.server_enable.data
    conf['gateway_conf']['gateway_ID'] = form.gateway_id.data
    conf['gateway_conf']['ref_latitude'] = form.latitude.data
    conf['gateway_conf']['ref_longitude'] = form.longitude.data
    conf['gateway_conf']['ref_altitude'] = form.altitude.data
    conf['gateway_conf']['contact_email'] = form.contact_email.data
    conf['gateway_conf']['description'] = form.description.data

    with open(os.path.join(ttnzh, 'local_conf.json'), 'w') as f:
        json.dump(conf, f, indent=4)
    return conf

import time
@ app.route("/scan", methods=["GET", "POST"])
@ login_required
def scanWifi():
    if request.method == "POST":
        if "activate" in request.form:
            if request.form['activate'] == "true":
                print("up")
                subprocess.call([f"ip link set {netadapt} up"], shell=True)
            if request.form['activate'] == "false":
                print("down")
                subprocess.call([f"ip link set {netadapt} down"], shell=True)
            time.sleep(1)
    e = ""
    global wifiap
    online = True
    essid = []
    try:
        Cells = Cell.all(netadapt)
        essid = [elem.ssid for elem in Cells]
        essid = list(set(essid))
        
        wifiap = essid
    except exceptions.InterfaceError:
        online = False
        e = "Interface is down"
    connected = os.popen("iwgetid -r").read()
       
    return json.dumps({"wifi": essid, "connected": connected.strip(), "online": online, "errors": e})
    


@ app.route("/account", methods=["POST", "GET"])
@ login_required
def changePassword():
    message = ""
    f = ChangePass()
    if request.method == 'POST':
        if f.validate_on_submit():
            with open('secret', 'w') as pa:
                pa.write(werkzeug.security.generate_password_hash(
                    f.newpassword.data, method='pbkdf2:sha256', salt_length=16))
            message = "Password changed"
            # return render_template('change-password.html')

    return render_template('account.html', formp=f, message=message)


# somewhere to login
@ app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            login_user(user)
            return redirect("/")
        # else:
        #     print(form.errors.items())
        #     return abort(401)
    # else:
    return render_template("login.html", form=form)


# somewhere to logout
@ app.route("/logout")
@ login_required
def logout():
    logout_user()
    return render_template('logout.html')


@ app.route('/', methods=["GET", "POST"])
@ login_required
def index():
    form = GatewayConfig()
    formp = ChangePass()
    if request.method == 'GET':
        form = file2form()
    elif request.method == 'POST':
        if form.save.data:
            form2file(form)

        elif form.reload.data:
            # returns the exit code in unix
            returned_value = subprocess.call(
                "systemctl restart ttn-gateway", shell=True)
            print('returned value:', returned_value)
        elif form.reboot.data:
            os.system("reboot")

    return render_template('index.html', form=form, formp=formp)


@ app.route("/wifi", methods=['GET', 'POST'])
@ login_required
def configWifi():
    form = WifiForm()
    print("wifi")
    if request.method == "GET":
        with open(os.path.join(config_path, 'config.json'), 'r') as f:
            c = json.load(f)
            if c['wifi']['ssid'] != '':
                form.essid.data = c['wifi']['ssid']
            form.country.data = c['wifi']['country']
    elif request.method == "POST":
        form.essid.choices = []
        for elem in wifiap:
            form.essid.choices.append((elem, elem))

        print(form.essid.data)
        print(form.essid.choices)
        if form.validate_on_submit():
            print("validate")
            wi = {"ssid": form.essid.data, "country": form.country.data,
                  "activate": form.activate.data}
            with open(os.path.join(config_path, 'config.json'), 'r+') as f:
                j = json.load(f)
                j['wifi'] = wi
                f.seek(0)
                f.truncate(0)
                json.dump(j, f)
            print("saving wifi config")
            with open("/etc/wpa_supplicant/wpa_supplicant.conf", "w") as f:
                f.writelines(wpa.format(form.country.data,
                                        form.essid.data,
                                        form.password.data))

            subprocess.call(["systemctl daemon-reload"], shell=True)
            subprocess.call(["systemctl restart dhcpcd"], shell=True)
        else:
            print("error")
            print(form.errors)

    return render_template("wifi.html", form=form)


def main():
    app.run("0.0.0.0", debug=True)


if __name__ == "__main__":
    main()
