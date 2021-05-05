# pip install Flask pymysql bcrypt flask_sendgrid pydiscourse
from flask import Flask, jsonify, request, render_template, g, make_response, redirect, url_for, json
from flask_cors import CORS
import sys, os, random, bcrypt, time, re, pymysql, logging, datetime
from urllib import parse
import app_config as ac
from flask_sendgrid import SendGrid
from pydiscourse.client import DiscourseClient
import pydiscourse.sso as dcsso
from werkzeug.exceptions import HTTPException
from logging import FileHandler

# configuration
DEBUG = False

def menu_link_active():
    dict_menu_link_active={}
    # if g.userdata:
    if 'userdate' in g:
        dict_menu_link_active['user_service']=bool(max([int(x in g.parseResult.path.lower()) for x in ('/profile', '/change_email')]))
    else:
        dict_menu_link_active['user_service']=bool(max([int(x in g.parseResult.path.lower()) for x in ('/signin', '/signup')]))
    dict_menu_link_active['data']=bool(max([int(x in g.parseResult.path.lower()) for x in ('/data', '/databrowser')]))
    return dict_menu_link_active

def getRootPath():
    try:
        return sys._MEIPASS
    except:
        return os.path.abspath(os.path.dirname(__file__))

def generateRandomString(length = 12):
    characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    randomString=''
    for _ in range(length):
        randomString+=characters[random.randint(0,len(characters)-1)]
    return randomString

def discourse_sso(sso=None, sig=None, userdcemail=None, userdcid=None, userdcusername=None):
    # payload = request.GET.get('sso')
    # signature = request.GET.get('sig')
    payload = sso
    signature = sig
    nonce = dcsso.sso_validate(payload, signature, ac.discourseForumConfig['strSsoSecret'])
    url = dcsso.sso_redirect_url(nonce, ac.discourseForumConfig['strSsoSecret'], userdcemail, userdcid, userdcusername)
    return redirect(ac.discourseForumConfig['strUrl'] + url)

def login(email=None, password=None, userid=None, loginkey=None, sso=None, sig=None):
    if (loginkey and userid):
        sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `activate_code`, `fido2`, `fido2_challenge`, `fido2_registrations`, `forum_userid` FROM user WHERE id={userid} and `login_key`='{loginkey}'"
        return redirect(url_for('page_error', errorcode=999999))
    else:
        sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `activate_code`, `fido2`, `fido2_challenge`, `fido2_registrations`, `forum_userid` FROM user WHERE email='{email}'"
        with g.conn.cursor() as cursor:
            cursor.execute(sql)
            data = cursor.fetchone()
            if not data:
                return redirect(url_for('page_error', errorcode=460765))
            elif (data['activated'] == 0):
                new_user_activate_link = g.parseResult.scheme+'://'+g.parseResult.netloc+'/signup/'+email+'/'+data['activate_code']
                try:
                    mail = SendGrid(app)
                    mail.send_email(
                        from_email=ac.sendGrid['strSenderEmailAddress'],
                        to_email=data['email'],
                        subject='Please confirm your email for Annswer register',
                        html=f'感謝您註冊Annswer會員，為了確認您的真實郵件，請點選以下連結：<br><a href={new_user_activate_link}>{new_user_activate_link}</a>',
                    )
                    return redirect(url_for('page_success', successcode=674962))
                except:
                    # return redirect(url_for('page_success', successcode=674963))
                    return redirect(url_for('page_error', errorcode=460762))
                return redirect(url_for('page_error', errorcode=460762))
            elif (data['salt']==None or len(data['salt'])==0):
                return redirect(url_for('page_error', errorcode=460801))
            try:
                passwordcrypt = bcrypt.hashpw(password.encode('utf-8'),data['salt'].encode('utf-8')).decode('utf-8')
            except:
                return redirect(url_for('page_error', errorcode=460801))
            if (passwordcrypt==data['password']):
                login_key = generateRandomString(24)
                sql_update = f"UPDATE user set login_key='{login_key}' where id={data['id']}"
                with g.conn.cursor() as cursor:
                    if not cursor.execute(sql_update):
                        return redirect(url_for('page_error', errorcode=470001))
                    else:
                        g.conn.commit()
                if (sso and sig and ac.discourseForumConfig['blnActivate']):
                    # do discourse sso
                    # header("Location: ./sso/forum.php?sso=".$payload."&sig=".$signature);
                    # die();
                    resp = make_response(discourse_sso(sso=sso, sig=sig, userdcemail=data['email'], userdcid=data['forum_userid'], userdcusername=data['username']))
                    resp.set_cookie("UserId", str(data['id']), expires=time.time()+60*60*24*7)
                    resp.set_cookie("UserLoginKey", login_key, expires=time.time()+60*60*24*7)
                    return resp
                else:
                    resp = make_response(redirect(url_for('page_success', successcode=674958)))
                    resp.set_cookie("UserId", str(data['id']), expires=time.time()+60*60*24*7)
                    resp.set_cookie("UserLoginKey", login_key, expires=time.time()+60*60*24*7)
                    return resp
            else:
                return redirect(url_for('page_error', errorcode=460766))
    return None

def signup():
    email = str(request.form.get('email'))
    username = str(request.form.get('username'))
    password1 = str(request.form.get('password1'))
    password2 = str(request.form.get('password2'))
    name_last = str(request.form.get('name_last'))
    name_first = str(request.form.get('name_last'))
    if not email:
        return redirect(url_for('page_error', errorcode=460773))
    elif len(email)==0:
        return redirect(url_for('page_error', errorcode=460773))
    elif not username:
        return redirect(url_for('page_error', errorcode=460774))
    elif len(username)<3:
        return redirect(url_for('page_error', errorcode=460776))
    elif len(username)>20:
        return redirect(url_for('page_error', errorcode=460780))
    elif not re.search('^[a-zA-Z0-9]{1,}', username):
        return redirect(url_for('page_error', errorcode=460777))
    elif not re.search('[a-zA-Z0-9]{1,}$', username):
        return redirect(url_for('page_error', errorcode=460778))
    elif len(password1)==0:
        return redirect(url_for('page_error', errorcode=460771))
    elif password1!=password2:
        return redirect(url_for('page_error', errorcode=460772))
    elif len(password1)<8:
        return redirect(url_for('page_error', errorcode=460775))
    for _ in ('admin', 'moderator', 'administrator', 'mod', 'sys', 'system', 'community', 'info', 'you', 
    'name', 'username', 'user', 'nickname', 'discourse', 'discourseorg', 'discourseforum', 
    'annswer', 'annswerorg', 'annswerforum', 'macs', 'macsai', 'support', 'hp', 'account-created', 
    'password-reset', 'admin-login', 'confirm-admin', 'account-created', 'activate-account', 
    'confirm-email-token', 'authorize-email', 'theannswer', 'theanswer', 'theannswerorg', 'theanswerorg'):
        if _ == username:
            return redirect(url_for('page_error', errorcode=460781))
    sql = f"SELECT `id`, `email`, `username`, `password`, `salt` FROM user WHERE email='{email}'"
    with g.conn.cursor() as cursor:
        cursor.execute(sql)
        data = cursor.fetchone()
        if data:
            return redirect(url_for('page_error', errorcode=460764))
    # return render_template('resetpw.html', email=email, resetpwcode=resetpwcode)
    sql = f"SELECT `id`, `email`, `username`, `password`, `salt` FROM user WHERE username='{username}'"
    with g.conn.cursor() as cursor:
        cursor.execute(sql)
        data = cursor.fetchone()
        if data:
            return redirect(url_for('page_error', errorcode=460763))
    
    salt = bcrypt.gensalt()
    passwordcrypt = bcrypt.hashpw(password1.encode('utf-8'), salt).decode('utf-8')    
    activate_code = generateRandomString(24)
    sql_insert = f"INSERT INTO user (`email`, `username`, `password`, `salt`, `activate_code`, `name_first`, `name_last`, `reset_pw_code`, `login_key`) VALUES ('{email}', '{username}', '{passwordcrypt}', '{salt.decode('utf-8')}', '{activate_code}', '{name_first}', '{name_last}', '', '')"
    with g.conn.cursor() as cursor:
        if not cursor.execute(sql_insert):
            return redirect(url_for('page_error', errorcode=470001))
        else:
            g.conn.commit()
            new_user_activate_link = g.parseResult.scheme+'://'+g.parseResult.netloc+'/signup/'+email+'/'+activate_code
            try:
                mail = SendGrid(app)
                mail.send_email(
                    from_email=ac.sendGrid['strSenderEmailAddress'],
                    to_email=email,
                    subject='Please confirm your email for Annswer register',
                    html=f'感謝您註冊Annswer會員，為了確認您的真實郵件，請點選以下連結：<br><a href={new_user_activate_link}>{new_user_activate_link}</a>',
                )
                return redirect(url_for('page_success', successcode=674963))
            except:
                return redirect(url_for('page_success', successcode=674963))
        return redirect(url_for('page_success', successcode=674963))
    return 'kk'

def activat_check_code(email=None, activatecode=None):
    sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `fido2`, `fido2_challenge`, `fido2_registrations` FROM user WHERE email='{email}' and activate_code='{activatecode}'"
    with g.conn.cursor() as cursor:
        cursor.execute(sql)
        data = cursor.fetchone()
        if not data:
            return redirect(url_for('page_error', errorcode=460768))
        elif data['activated']==1:
            return redirect(url_for('page_error', errorcode=460767))
    sql_update = f"UPDATE user SET `activated`=1 WHERE email='{email}' and activate_code='{activatecode}'"
    with g.conn.cursor() as cursor:
        if not cursor.execute(sql_update):
            return redirect(url_for('page_error', errorcode=470001))
        else:
            g.conn.commit()
            if ac.discourseForumConfig['blnActivate']:
                discoursepassword = generateRandomString(24)
                discourseuser = g.discourseClient.create_user('', data['username'], email, discoursepassword, active='true')
                if discourseuser:
                    sql_update = f"UPDATE user SET `forum_password`='{discoursepassword}', forum_userid={discourseuser['user_id']}  WHERE email='{email}' and activate_code='{activatecode}'"
                    cursor.execute(sql_update)
                    g.conn.commit()
                print(discourseuser)
                # def create_user(self, name, username, email, password, **kwargs):
            return redirect(url_for('page_success', successcode=674964))
    return redirect(url_for('page_index'))

def resetpw_check_code(email=None, resetpwcode=None):
    sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `fido2`, `fido2_challenge`, `fido2_registrations` FROM user WHERE email='{email}' and reset_pw_code='{resetpwcode}'"
    with g.conn.cursor() as cursor:
        cursor.execute(sql)
        data = cursor.fetchone()
        if not data:
            return redirect(url_for('page_error', errorcode=460770))
    return render_template('resetpw.html', email=email, resetpwcode=resetpwcode)

def resetpw_action(email=None, resetpwcode=None, password1=None, password2=None):
    if email != None and resetpwcode != None and password1 != None and password2 != None:
        if password1!=password2:
            return redirect(url_for('page_error', errorcode=460772))
        elif len(password1)==0:
            return redirect(url_for('page_error', errorcode=460771))
        elif len(password1)<8:
            return redirect(url_for('page_error', errorcode=460775))
        salt = bcrypt.gensalt()
        sql_update = f"UPDATE user SET salt='{salt.decode('utf-8')}', password='{bcrypt.hashpw(password1.encode('utf-8'), salt).decode('utf-8')}', reset_pw_code='{generateRandomString(24)}' WHERE email='{email}' and reset_pw_code='{resetpwcode}'"
        with g.conn.cursor() as cursor:
            if not cursor.execute(sql_update):
                return redirect(url_for('page_error', errorcode=470001))
            else:
                g.conn.commit()
            return redirect(url_for('page_success', successcode=674960))
    else:
        sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `fido2`, `fido2_challenge`, `fido2_registrations` FROM user WHERE email='{email}'"
        with g.conn.cursor() as cursor:
            cursor.execute(sql)
            data = cursor.fetchone()
            if not data:
                return redirect(url_for('page_error', errorcode=460765))
        reset_pw_code = generateRandomString(24)
        print(reset_pw_code)
        reset_pw_link = g.parseResult.scheme+'://'+g.parseResult.netloc+'/resetpw/'+email+'/'+reset_pw_code
        sql_update = f"UPDATE user SET reset_pw_code='{reset_pw_code}' WHERE email='{email}'"
        print(sql_update)
        with g.conn.cursor() as cursor:
            if not cursor.execute(sql_update):
                return redirect(url_for('page_error', errorcode=470001))
            else:
                g.conn.commit()
            mail = SendGrid(app)
            mail.send_email(
            from_email='info@annswer.com',
            to_email=email,
            subject='Reset password',
            html=f'<a href={reset_pw_link}>{reset_pw_link}</a>',
        )
        return redirect(url_for('page_success', successcode=674959))
    return redirect(url_for('page_error', errorcode=999999))

# app = Flask(__name__, static_folder='static', static_url_path="/static")
app = Flask(__name__, 
            static_folder=getRootPath()+'/static', 
            static_url_path="/static", 
            template_folder=getRootPath()+'/templates')
# app = Flask(__name__)
app.config.from_object(__name__)
app.config['SENDGRID_API_KEY'] = ac.sendGrid['strApiKey']
app.config['SENDGRID_DEFAULT_FROM'] = ac.sendGrid['strSenderEmailAddress']

# enable CORS
CORS(app, resources={r'/*': {'origins': '*'}})

@app.template_filter('formatdatetime')
def format_datetime(value, format="%Y/%m/%d %H:%M:%S"):
    """Format a date time to (Default): d Mon YYYY HH:MM P"""
    offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    if value is None:
        return ""       
    return datetime.datetime.fromtimestamp(datetime.datetime.fromisoformat(value[:-1]).timestamp()-offset).strftime(format)

@app.before_request
def before():
    g.internalUserDataFromDbId = 0
    g.internalUserDataFromDbEmail = ''
    g.internalUserDataFromDbUserName = ''
    g.internalstrUserDataFromDbNameFirst = ''
    g.internalstrUserDataFromDbNameLast = ''
    g.parseResult = parse.urlparse(request.url)
    UserId = request.cookies.get('UserId')
    UserLoginKey = request.cookies.get('UserLoginKey')
    # 連接資料庫
    conn = pymysql.connect(host=ac.dbConfig['strServer'], 
                            port=ac.dbConfig['intPort'], 
                            user=ac.dbConfig['strDbUserID'], 
                            password=ac.dbConfig['strPassword'], 
                            database=ac.dbConfig['strDatabase'],
                            cursorclass=pymysql.cursors.DictCursor)
    # 獲取游標
    # cursor = conn.cursor()
    # g物件，這是一個全域的命名空間
    g.conn = conn
    # g.cursor = cursor
    if ac.discourseForumConfig['blnActivate']:
        g.discourseClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username='system', api_key=ac.discourseForumConfig['strSystemApiKey'])
    g.discourseUserClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username='benctw', api_key=ac.discourseForumConfig['strSystemApiKey'])

    # cursor = g.conn.cursor()
    try:
        # cursor = g.conn.cursor()
        UserId = int(UserId)
        if UserId>0:
            try:
                with g.conn.cursor() as cursor:
                # Read a single record
                    sql = f"SELECT `id`, `email`, `username`, `password`, `salt`, `activated`, `login_key`, `name_first`, `name_last`, `forum_userid` \
                            FROM user \
                            WHERE id='{UserId}'"
                    cursor.execute(sql)
                    g.userdata = cursor.fetchone()
                    # print(data)
                    if (g.userdata["login_key"]==UserLoginKey):
                        g.internalUserDataFromDbId = g.userdata["id"]
                        g.internalUserDataFromDbEmail = g.userdata["email"]
                        g.internalUserDataFromDbUserName = g.userdata["username"]
                        g.internalstrUserDataFromDbNameFirst = g.userdata["name_first"]
                        g.internalstrUserDataFromDbNameLast = g.userdata["name_last"]
                        g.discourseUserClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username=g.userdata['forum_userid'], api_key=ac.discourseForumConfig['strSystemApiKey'])
                    else:
                        resp = make_response(redirect(request.url))
                        resp.delete_cookie("UserId")
                        resp.delete_cookie("UserLoginKey")
                        g.discourseUserClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username='benctw', api_key=ac.discourseForumConfig['strSystemApiKey'])
                        return resp
            except:
                resp = make_response(redirect(request.url))
                resp.delete_cookie("UserId")
                resp.delete_cookie("UserLoginKey")
                g.discourseUserClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username='benctw', api_key=ac.discourseForumConfig['strSystemApiKey'])
                return resp
            finally:
                pass
    except:
        g.discourseUserClient = DiscourseClient(ac.discourseForumConfig['strUrl'], api_username='benctw', api_key=ac.discourseForumConfig['strSystemApiKey'])
        pass

@app.teardown_request
def teardown(exception):
    # 關閉連線資源
    g.conn.close()

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# @app.errorhandler(500)
# def page_error_500(error):
#     return render_template('500.html'), 500

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return render_template("500.html", e=e), 500

@app.route('/')
def page_index():
    dictnews={}
    try:
        dictnews = g.discourseUserClient.latest_topics()
        i=0
        for item in dictnews['topic_list']['topics']:
            dictnews['topic_list']['topics'][i]['last_posted_at_timestamp']=datetime.datetime.fromisoformat(dictnews['topic_list']['topics'][i]['last_posted_at'][:-1]).timestamp()
            i+=1
    except:
        pass
    # dictnews['topic_list']['topics'] = [x for x in dictnews['topic_list']['topics'] if x['id']!=517]
    return render_template('index.html', menu_link_active = menu_link_active(), dictnews = dictnews)

@app.route('/about')
def page_about():
    return render_template('about.html')

@app.route('/profile', methods=['GET', 'POST'])
def page_profile():
    try:
        g.userdata
        if request.method=='POST':
            pass
        else:
            return render_template('profile.html')
    except:
        return redirect(url_for('page_index'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    try:
        g.userdata
        if request.method=='POST':
            pass
        else:
            return render_template('change_email.html')
    except:
        return redirect(url_for('page_index'))

@app.route('/2fa', methods=['GET', 'POST'])
def _2fa():
    try:
        g.userdata
        if request.method=='POST':
            pass
        else:
            return render_template('2fa.html')
    except:
        return redirect(url_for('page_index'))

@app.route('/signout')
def page_signout():
    if ac.discourseForumConfig['blnActivate']:
        g.discourseClient.log_out(g.userdata['forum_userid'])
    resp = make_response(render_template('success.html', successcode=674957))
    resp.delete_cookie("UserId")
    resp.delete_cookie("UserLoginKey")
    return resp

@app.route('/signin', methods=['GET', 'POST'])
def page_signin():
    if request.method=='POST':
        return login(email=request.form.get('email'), password=request.form.get('password'), userid=None, loginkey=None, sso=request.form.get('sso'), sig=request.form.get('sig'))
    else:
        if request.args.get('sso') and request.args.get('sig') and hasattr(g, 'userdata') and ac.discourseForumConfig['blnActivate']:
            sso = request.args.get('sso')
            sig = request.args.get('sig')
            resp = make_response(discourse_sso(sso=sso, sig=sig, userdcemail=g.userdata["email"], userdcid=g.userdata['forum_userid'], userdcusername=g.userdata['username']))
            return resp
            # return login(email=request.form.get('email'), password=request.form.get('password'), userid=None, loginkey=None, sso=request.form.get('sso'), sig=request.form.get('sig'))
        elif g.internalUserDataFromDbId>0:
            return redirect(url_for('page_index'))
        return render_template('signin.html', 
                                payload = '' if request.args.get('sso')==None else request.args.get('sso'),
                                signature = '' if request.args.get('sig')==None else request.args.get('sig'))

@app.route('/signup/<string:email>/<string:activatecode>')
def page_signup2(email, activatecode):
    return activat_check_code(email=email, activatecode=activatecode)

@app.route('/signup', methods=['GET', 'POST'])
def page_signup():
    if request.method=='POST':
        return signup()
    else:
        return render_template('signup.html')

@app.route('/resetpw/<string:email>/<string:resetpwcode>', methods=['GET', 'POST'])
def page_resetpw2(email, resetpwcode):
    if request.method=='POST':
        return resetpw_action(email=email, resetpwcode=resetpwcode, password1=request.form.get('password1'), password2=request.form.get('password2'))
    elif len(email)>0 and len(resetpwcode)>0:
        return resetpw_check_code(email=email, resetpwcode=resetpwcode)
        
@app.route('/resetpw', methods=['GET', 'POST'])
def page_resetpw():
    if request.method=='POST':
        return resetpw_action(email=request.form.get('email'))
    else:
        return render_template('resetpw.html')

@app.route('/machinelearning_21578465789464')
def page_machinelearning():
    return render_template('./machinelearning/index.html')

@app.route('/error/<int:errorcode>')
def page_error(errorcode):
    return render_template('error.html', errorcode=errorcode)

@app.route('/success/<int:successcode>')
def page_success(successcode):
    return render_template('success.html', successcode=successcode)

# sanity check route
@app.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify({"action":"pong!"})

# @app.route('/<path:path>')
# def catch_all(path):
#     return f'{path}'

# run app
if __name__ == "__main__":
    # app.debug=True
    # app = create_app()
    if not app.debug:
        handler = logging.FileHandler('flask.log')
        app.logger.addHandler(handler)
    app.run(host='127.0.0.1', port=5001, debug=True)

# pyinstaller command
# pyinstaller --add-data "templates/*;templates" --add-data "static/*;static"  -F app.py