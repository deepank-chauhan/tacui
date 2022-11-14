import os # For fetching environment variables
import subprocess # For calling bash and escripts
import logging # For log management
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file # For webpage rendering and management
from flask_session import Session # For user session management
from flask_sqlalchemy import SQLAlchemy # For Database configuration
from tempfile import mkdtemp
from sqlalchemy.sql import func
from sqlalchemy import update
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, formatCase
from creds import vm_username, vm_password

# Path for project directory
basedir = os.path.abspath(os.path.dirname(__file__))
print(basedir)
# Log management
# Create and configure logger
logging.basicConfig(filename=basedir + "/log/" + "/debug.log", format='%(asctime)s %(message)s', filemode='a')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

# To create a log
#logger.info("Request for mode change of pps_id=" + str(PPS_ID) + " to " + MODE)

app = Flask(__name__)

# Auto reload templates
app.config['DEBUG'] = True
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tacui.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Defining class for user table schema
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_active = db.Column(db.Boolean, nullable=False)
    account_type = db.Column(db.String(20), nullable=False)
    created_on = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(120), nullable=False)
    lastname = db.Column(db.String(120), nullable=True)
    password = db.Column(db.String(200), nullable=False)
    updated_on = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Defining class for site table schema
class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sitename = db.Column(db.String(80), nullable=False)
    site_alias = db.Column(db.String(80), nullable=False)
    butler_server_ip = db.Column(db.String(80))
    platform_core_server_ip = db.Column(db.String(80))
    platform_db_server_ip = db.Column(db.String(80))
    metrics_server_ip = db.Column(db.String(80))
    interface_server_ip = db.Column(db.String(80))
    tower_server_ip = db.Column(db.String(80))
    site_active = db.Column(db.Boolean, nullable=False)
    erlang_version = db.Column(db.String(20))
    created_on = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    username = db.Column(db.String(20))
    password = db.Column(db.String(100))
    
    def __repr__(self):
        return f'<Site {self.sitename}>'

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
    response.headers['Expires'] = 0
    response.headers['Pragma'] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Upload folder to store files
UPLOAD_FOLDER = basedir + '/log/butler_log/'
print(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Registration
@app.route('/register', methods = ['GET', 'POST'])
# @login_required
def register():
    return render_template('register.html')


# Site Registration
@app.route('/register/site', methods = ['GET', 'POST'])
# @login_required
def site_register():

    if request.method == 'POST':

        sitename = request.form.get("sitename")
        site_alias = request.form.get("site_alias")
        butler_server_ip = request.form.get("butler_server_ip")
        platform_core_server_ip = request.form.get("platform_core_server_ip")
        platform_db_server_ip = request.form.get("platform_db_server_ip")
        metrics_server_ip = request.form.get("metrics_server_ip")
        interface_server_ip = request.form.get("interface_server_ip")
        tower_server_ip = request.form.get("tower_server_ip")

        print(sitename,site_alias,butler_server_ip,platform_core_server_ip,platform_db_server_ip,metrics_server_ip,interface_server_ip,tower_server_ip)
        logger.info("Registering new site with details:" + " sitename:" + sitename + ", sitealias:" + site_alias + ", butler_ip:" + butler_server_ip + ", platform_core_ip:" + platform_core_server_ip + ", platform_db_ip:" + platform_db_server_ip + ", metrics_server_ip:" + metrics_server_ip + ", interface_server_ip:" + interface_server_ip + ", tower_ip:" + tower_server_ip)

        # Ensure site name is provided
        if not request.form.get("sitename"):
            flash("must provide site name")
            return redirect('/register/site')

        # Ensure site alias name is provided
        if not request.form.get("site_alias"):
            site_alias = formatCase(sitename)

        # Ensure butler ip is provided    
        if not request.form.get("butler_server_ip"):
            flash("must provide butler server ip")
            return redirect('/register/site')

        # Ensure platform core ip is provided    
        if not request.form.get("platform_core_server_ip"):
            flash("must provide platform core server ip")
            return redirect('/register/site')

        # Ensure platform db ip is provided    
        if not request.form.get("platform_db_server_ip"):
            flash("must provide platform db server ip")
            return redirect('/register/site')

        # Ensure metric ip is provided    
        if not request.form.get("metrics_server_ip"):
            flash("must provide metrics server ip")
            return redirect('/register/site')

        # Ensure interface ip is provided    
        if not request.form.get("interface_server_ip"):
            flash("must provide interface server ip")
            return redirect('/register/site')

        # Ensure tower ip is provided    
        if not request.form.get("tower_server_ip"):
            flash("must provide tower server ip")
            return redirect('/register/site')

        try:
            #db.engine.execute("INSERT INTO sites (site_name, username, butler_server_ip, jump_required, password, platform_core_server_ip, platform_db_server_ip, metrics_server_ip, interface_server_ip, tower_server_ip, maintenance_script_present) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", site_name, username, butler_server_ip, jump_required, password, platform_core_server_ip, platform_db_server_ip, metrics_server_ip, interface_server_ip, tower_server_ip, maintenance_script_present)
            site = Site(site_active=True, sitename=sitename, site_alias=site_alias, butler_server_ip=butler_server_ip, platform_core_server_ip=platform_core_server_ip, platform_db_server_ip=platform_db_server_ip, metrics_server_ip=metrics_server_ip, interface_server_ip=interface_server_ip, tower_server_ip=tower_server_ip)
            db.session.add(site)
            db.session.commit()

        # If username already exists
        except Exception:
            flash("Unable to register new site :(")
            logger.error("Unable to register new site_name " + sitename + " :(")
            return redirect('/register/site')

        
        # Success message
        flash("Site Registered!")
        logger.info("New site registered! site_name: " + sitename)

        return redirect('/register')

    else:
        return render_template('site_register.html')


# User Registration
@app.route('/register/user', methods = ['GET', 'POST'])
# @login_required
def user_register():

    # Variables taken from the register form
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    account_type = request.form.get("account_type")

    print(firstname, lastname, email, username, password, account_type)
    # User reached route via GET
    if request.method == 'GET':
        return render_template('user_register.html')

    # User reached route via POST
    else:

        # Ensure firstname was submitted
        if not request.form.get("firstname"):
            flash("must provide firstname")
            return redirect('/register/user')

        # Ensure email was submitted
        if not request.form.get("email"):
            flash("must provide email")
            return redirect('/register/user')

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username")
            return redirect('/register/user')

        # Ensure password was submitted
        if not request.form.get("password"):
            flash("must provide password")
            return redirect('/register/user')

        # Ensure password was repeated
        if not request.form.get("confirmation"):
            flash("must repeat password")        
            return redirect('/register/user')

        # Matching password
        if password != confirmation:
            flash("password didn't match")
            return redirect('/register/user')

        # Hashing the password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        
        # If account_type is not submitted create user as standard
        if not request.form.get("account_type"):
            account_type = 'standard'

        
        logger.info("New user registered with details: firstname:" + firstname + ", lastname:" + lastname + ", email:" + email + ", username" + username + ", hash" + password_hash + ", account_type" + account_type)

        # Adding user to the database
        try:
            # db.engine.execute("INSERT INTO users (username, password) VALUES (%s, %s);", username, password_hash)
            user = User(account_active=True, firstname=firstname, lastname=lastname, email=email, username=username, password=password_hash, account_type=account_type)
            db.session.add(user)
            db.session.commit()

        # If username already exists
        except Exception:
            flash("Unable to register new user :(")
            logger.error("Unable to register new username:" + username + ":(")
            return redirect('/register/user')
        
        # Success message
        flash("User Registered!")
        logger.info("New user registered! username: " + username)

        # Prompt user to login after registering
        return redirect('/register')

# User Login
@app.route('/login', methods = ['GET', 'POST'])
def login():

    # Forget any user_id
    session.clear()

    # User reached out via POST
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("must provide username")
            return render_template('login.html', username=username)

        elif not password:
            flash("must provide password")    
            return render_template('login.html', username=username)

        # Query database for username
        # rows = db.engine.execute("SELECT * FROM users WHERE username = %s", username).fetchone()
        db_record = User.query.filter_by(username=username).all()
        db_user = User.query.filter_by(username=username).first()
        # print(db_record)
        # print(type(db_password))
        # print(db_password.firstname)
        if not db_record:
            flash("User doesn't exist. Contact admin for user registration.")
            return render_template('login.html', username=username)

        # Ensure username exists and password is correct
        try:
            if not check_password_hash(db_user.password, password):
                flash("invalid username and/or password")
                return render_template('login.html', username=username)
        except Exception:
            flash("user does not exist")
            return redirect('/login')

        # Remember which user is logged in
        session["user_id"] = db_user.username

        print(session["user_id"])
        logger.info("User " + session["user_id"] + " logged in.")
        # Redirect user to home page
        return redirect('/sites')

    else:
        return render_template("login.html")


# Homepage
@app.route("/", methods = ['GET', 'POST'])
def index():
    if "user_id" not in session.keys():
        logger.info("No user logged in. Redirecting to login page.")
        return redirect('/login')
    else:
        logger.info("user " + session["user_id"] + " logged in. Redirecting to site page.")
        return redirect("/sites")

# Site list
@app.route("/sites", methods=['GET', 'POST'])
@login_required
def sites():
    if request.method == 'GET':
        sites = Site.query.order_by(Site.sitename).all()
        print(sites)
        logger.info(sites)
        return render_template("sites.html", sites=sites)

# Site info
@app.route("/<site_name>", methods=['GET', 'POST'])
def site_info(site_name):
    site = Site.query.filter_by(site_alias=site_name).first()
    print(site)
    logger.info("Showing info for site: " + site_name)
    return render_template('site_info.html', site=site)

# Log maker
@app.route("/<site_name>/log-maker", methods = ['GET', 'POST'])
@login_required
def log_maker(site_name):

    # Takes data from the db into variables
    site = Site.query.filter_by(site_alias=site_name).first()
    butler_ip = site.butler_server_ip
    site_alias = site.site_alias
    erlang_version = site.erlang_version
    
    print(butler_ip)
    print(site)
    print(site_alias)
    
    if request.method == 'POST':
        ticket_id = request.form.get('ticket_id')
        issue_type = request.form.get('issue_type')
        pps_id = request.form.get('pps_id')
        order_node = request.form.get('order_node')
        put_node = request.form.get('put_node')
        audit_id = request.form.get('audit_id')
        butler_id = request.form.get('butler_id')
        taskkey = request.form.get('taskkey')


        if not ticket_id:
            flash("must provide ticket id")
        if not issue_type:
            flash("must provide issue type")

        
        if pps_id == '':
            pps_id = 'a'
        
        print(ticket_id)
        print(issue_type)
        print(pps_id)
        print(order_node)
        print(put_node)
        print(audit_id)
        print(butler_id)
        print(taskkey)
        
        arguments = {"pps_id":pps_id, "order_node":order_node, "put_node":put_node, "audit_id":audit_id, "butler_id":butler_id, "taskkey":taskkey}
        print(arguments)
        filename = ticket_id + '.log'
        myoutput = open('log/butler_log/' + filename, 'w')
        #make sure logs are deleted later
        # remove ticket_id and add butler_id
        if issue_type == 'Audit':
            subprocess.check_call(['bash','static/scripts/log-maker/log-maker.sh', site.username, butler_ip, site.password, issue_type, erlang_version, arguments["pps_id"], arguments["audit_id"]], stdout=myoutput)
        elif issue_type == 'GMC':
            subprocess.check_call(['bash','static/scripts/log-maker/log-maker.sh', site.username, butler_ip, site.password, issue_type, erlang_version, arguments["butler_id"], arguments["taskkey"]], stdout=myoutput)
        elif issue_type == 'Pick':
            subprocess.check_call(['bash','static/scripts/log-maker/log-maker.sh', site.username, butler_ip, site.password, issue_type, erlang_version, arguments["pps_id"], arguments["order_node"]], stdout=myoutput)
        elif issue_type == 'Platform':
            subprocess.check_call(['bash','static/scripts/log-maker/log-maker.sh', site.username, butler_ip, site.password, issue_type, erlang_version, arguments], stdout=myoutput)
        elif issue_type == 'Platform':
            subprocess.check_call(['bash','static/scripts/log-maker/log-maker.sh', site.username, butler_ip, site.password, issue_type, erlang_version, arguments["pps_id"], arguments["put_node"],], stdout=myoutput)
        else:
            flash("Not a valid component! :(")
        # flash("Logs Downloaded")
        return redirect('/return-files/' + filename)
        
    else:
        return render_template('log-maker.html',site=site)


# To Download files
@app.route('/return-files/<filename>')
def return_files_tut(filename):
    file_path = UPLOAD_FOLDER + filename
    return send_file(file_path, as_attachment=True, attachment_filename='')

# Route for Audit form
@app.route('/Audit')
def Audit():
    return render_template('components/Audit.html')

# Route for GMC form
@app.route('/GMC')
def GMC():
    return render_template('components/GMC.html')

# Route for Pick form
@app.route('/Pick')
def Pick():
    return render_template('components/Pick.html')

# Route for Platform form
@app.route('/Platform')
def Platform():
    return render_template('components/Platform.html')

# Route for Put form
@app.route('/Put')
def Put():
    return render_template('components/Put.html')



# # Route for mode-conversion
# @app.route('/sbs/mode-conversion', methods = ['GET', 'POST'])
# def mode_conversion():

#     if request.method == 'GET':
#         return render_template('mode-conversion.html')
#     else:
#         pps_id = request.form.get("pps_id")
#         mode_type = request.form.get("mode_type")
#         return redirect('/sbs/mode-conversion/' + pps_id + '/' + mode_type)


# @app.route('/sbs/mode-conversion/<pps_id>/<mode_type>', methods = ['GET', 'POST'])
# def mode_conversion_rest(pps_id, mode_type):

#     if request.method == 'GET':
#         print(pps_id)
#         print(mode_type)

#         result = subprocess.check_output(['bash', 'static/scripts/mode_conversion/mode_conversion.sh', 'gor', '10.115.43.26', 'apj0702', str(pps_id), str(mode_type)]).decode()

#         logs, status = result.split("#")
#         print(logs)
#         print(status)
#         if status == 'true':
#             flash('PPS ' + pps_id + ' converted to ' + mode_type)
#         else:
#             flash("PPS " + pps_id + " can't be converted to " + mode_type)
#         return render_template('mode-conversion.html', logs=logs)

# Syncing and updating routes
@app.route('/erlang-update', methods=['POST'])
def erlang_update():

    if request.method == 'POST':
        sites = Site.query.all()
        payload = []
        for site in sites:
            erlang_version = subprocess.check_output(['bash', 'static/scripts/erlang_version.sh', site.username, site.butler_server_ip, site.password]).decode()
            erlang_version = erlang_version[erlang_version.find('erts'):].strip()
            print(erlang_version)
            Site.query.filter_by(site_alias=site.site_alias).update(dict(erlang_version=erlang_version))
            db.session.commit()
            payload.append({site.site_alias:erlang_version})
        return str(payload)

# Search for vm credentials
@app.route('/cred-sync', methods = ['POST'])
@app.route('/cred-sync/<hard_check>', methods = ['POST'])
def credsync(hard_check=0):
    
    if request.method == 'POST':
        sites = Site.query.all()
        print(sites)
        print(type(hard_check))
        payload = []
        for site in sites:
            print(site, site.butler_server_ip)
            if not site.username or int(hard_check) == 1:
                Output = subprocess.check_output(['bash', 'static/scripts/vm_login.sh', site.butler_server_ip]).decode()
                Output = Output.split('\n')
                user, password = Output[0], Output[1]
                print(user, password)
                Site.query.filter_by(site_alias=site.site_alias).update(dict(username=user, password=password))
                db.session.commit()
                payload.append({site.site_alias:[user,password]})
            else:
                print("skipping " + site.site_alias)
                payload.append({site.site_alias:[site.username,site.password]})
        print(payload)
        return str(payload)


if __name__ == "__main__":
  app.run(host='0.0.0.0', port=5005)




