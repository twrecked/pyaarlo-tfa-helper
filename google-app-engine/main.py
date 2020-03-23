
import os
import time
import secrets
import re

from flask import Flask, request, jsonify, render_template

from google.cloud import datastore

datastore_client = datastore.Client()

app = Flask(__name__)


def fixup_email(email):
    email = email.replace('@','.')
    email = email.replace('+','.')
    return email


def check_admin_token(token):

    # is token sane
    if not token:
        return False

    # get token from env
    saved_token = os.environ['AUTH_TOKEN']
    if not saved_token:
        return False

    # check for match
    return token == saved_token


def get_user_token(fmail):

    # get existing token
    query = datastore_client.query(kind='tokens')
    query.add_filter('fmail','=',fmail)
    tokens = list(query.fetch())
    if tokens:
        return tokens[0]['token']
    else:
        return None


def create_user_token(fmail):

    # create a new one!
    token = secrets.token_hex(24)
    entity = datastore.Entity(key=datastore_client.key('tokens'))
    entity.update({
        'fmail': fmail,
        'token': token,
        'timestamp': int(time.time())
    })
    datastore_client.put(entity)
    return token


def check_user_token(fmail,token):
    if token is None:
        return False
    return token == get_user_token(fmail)


def get_user_code(fmail):

    query = datastore_client.query(kind='codes')
    query.add_filter('fmail','=',fmail)
    codes = list(query.fetch())
    if codes:
        #if codes[0]['timestamp'] > int(time.time() - 300 ):
        return codes[0]
    return None

def clear_user_code(fmail):
    query = datastore_client.query(kind='codes')
    query.add_filter('fmail','=',fmail)
    codes = query.fetch()
    for old_code in codes:
        datastore_client.delete(datastore_client.key('codes',old_code.id))


def set_user_code(fmail,code):

    # wipe out old first
    clear_user_code(fmail)

    # add in new
    entity = datastore.Entity(key=datastore_client.key('codes'))
    entity.update({
        'fmail': fmail,
        'code': code,
        'timestamp': int(time.time())
    })
    datastore_client.put(entity)


def parse_mail(mail):

    # Search for bits we are interested in
    email= None
    code = None
    for line in mail:
        line = line.decode().rstrip()

        # look for fmail
        m = re.match('^To:\W+<*(.+?)>*\W*$',line)
        if m is not None:
            email = m.group(1)

        # look for code
        m = re.match('^\W*(\d{6})\W*$',line)
        if m is not None:
            code = m.group(1)

    return email, code


@app.route('/register')
def register():
    return render_template( 'register.html' )


@app.route('/register_done')
def register_done():

    email = request.args.get('email',None)
    fmail = fixup_email(email)
    token = get_user_token(fmail)
    if token is None:
        token = create_user_token(fmail)
        return jsonify({ 'success': True,
                            'email': email,
                            'fwd-to': "pyaarlo+{}@thewardrobe.ca".format(fmail),
                            'token': token })
    else:
        return jsonify({ 'success': False, 'error': 'email already registered' })


@app.route('/get')
def get():

    # validate args
    email = request.args.get('email',None)
    token = request.args.get('token',None)
    if not email or not token:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'please provide email and token', 'code': None }})

    # validate email/token
    fmail = fixup_email(email)
    if not check_user_token(fmail,token):
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'incorrect email or token', 'code': None }})

    # should be 0 or 1 entries
    code = get_user_code(fmail)
    if code is None:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'no valid code for email address', 'code': None }})

    return jsonify({ 'meta': { 'code': 200 },
                     'data': { 'success': True, 'email': email, 'code': code['code'], 'timestamp': code['timestamp'] }})


@app.route('/clear')
def clear():

    # validate args
    email = request.args.get('email',None)
    token = request.args.get('token',None)
    if not email or not token:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'please provide email and token', 'code': None }})

    # validate email/token
    fmail = fixup_email(email)
    clear_user_code(fmail)
    return jsonify({ 'meta': { 'code': 200 },
                     'data': { 'success': True, 'email': email }})


@app.route('/add')
def add():

    # check token to start
    if not check_admin_token(request.args.get('token',None)):
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'invalid admin token' }})

    # get email/code info
    email = request.args.get('email',None)
    code = request.args.get('code',None)
    if not email or not code:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'please provide email and token', 'code': None }})

    fmail = fixup_email(email)
    if get_user_token(fmail) is None:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'unknown email', 'code': None }})

    set_user_code(fmail,code)
    return jsonify({ 'meta': { 'code': 200 },
                     'data': { 'success': True, 'email': email, 'code': code }})


@app.route('/mail',methods=['POST'])
def mail():

    # check token to start
    if not check_admin_token(request.args.get('token',None)):
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'invalid admin token' }})

    # check file is there
    if 'file' not in request.files:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'no attached email' }})
    mail = request.files['file']
    if mail.filename != 'email.txt':
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'incorrectly attached email' }})

    # Search for bits we are interested in
    email, code = parse_mail(mail)
    if email is None or code is None:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'unable to parse email' }})

    # is valid user?
    fmail = fixup_email(email)
    if get_user_token(fmail) is None:
        return jsonify({ 'meta': { 'code': 400 },
                         'data': { 'success': False, 'error': 'unknown email', 'code': None }})

    # update and indicate success
    set_user_code(fmail,code)
    return jsonify({ 'meta': { 'code': 200 },
                     'data': { 'success': True, 'email': email, 'code': code }})


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.

    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
