import json
import urllib.parse
import urllib.request
import flask

AUTH_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'

app = flask.Flask(__name__)
app.secret_key = 'CzPcxd2uET8rbK5ARFjCyAdVKvPKyUyh'


def read_credentials():
    try:
        with open('client_secret.json', 'r') as f:
            credentials = json.load(f)
        return credentials["web"]
    except Exception as e:
        print(str(e))
        return None


def url_escape(text):
    # See OAUTH 5.1 for a definition of which characters need to be escaped.
    return urllib.parse.quote(text, safe='~-._')


def url_unescape(text):
    # See OAUTH 5.1 for a definition of which characters need to be escaped.
    return urllib.parse.unquote(text)


def format_url_params(params):
    """Formats parameters into a URL query string.
  
    Args:
      params: A key-value map.
  
    Returns:
      A URL query string version of the given parameters.
    """
    param_fragments = []
    for param in sorted(params.keys()):
        param_fragments.append('%s=%s' % (param, url_escape(params[param])))
    return '&'.join(param_fragments)


@app.route('/')
@app.route('/auth')
def authenticate():
    credentials = read_credentials()
    if credentials is None:
        return "ERROR"

    params = {'client_id': credentials['client_id'],
              'redirect_uri': credentials['redirect_uris'][0],
              'scope': AUTH_SCOPE,
              'response_type': 'code',
              'access_type': 'offline'}
    params = format_url_params(params)
    url = f'{credentials["auth_uri"]}?{params}'
    # return flask.render_template("authenticate.html", stuff=url)
    return flask.redirect(url)


@app.route('/oauth2-callback')
def oauth2_callback():
    code = flask.request.args.get('code', None)
    if code is None:
        return "ERROR"

    credentials = read_credentials()
    if credentials is None:
        return "ERROR"

    params = {'client_id': credentials['client_id'],
              'client_secret': credentials['client_secret'],
              'redirect_uri': credentials['redirect_uris'][0],
              'code': code,
              'grant_type': 'authorization_code'}
    params = urllib.parse.urlencode(params).encode('utf-8')
    refresh_url = credentials["token_uri"]
    response = urllib.request.urlopen(refresh_url, params).read()
    response = json.loads(response)

    return flask.render_template("authenticate-finish.html", token=response["refresh_token"])


@app.route('/refresh')
def refresh():
    token = flask.request.args.get('token', None)
    if token is None:
        return "ERROR"

    credentials = read_credentials()
    if credentials is None:
        return "ERROR"

    params = {'client_id': credentials['client_id'],
              'client_secret': credentials['client_secret'],
              'redirect_uri': credentials['redirect_uris'][0],
              'refresh_token': token,
              'grant_type': 'refresh_token'}
    params = urllib.parse.urlencode(params).encode('utf-8')
    refresh_url = credentials["token_uri"]
    print(params)
    return urllib.request.urlopen(refresh_url, params).read()


@app.route('/test')
def test():

    tests = {"access_token": "ya29.a0Aa4xrXMoxmlVCSWwKDSUdNcsXNZjTmHR-UARfXpNpG-FBSEReXiURNnhe1tUV4wYbc9mGOctTtB8PJSptURScdqEgWRmDLcAGMVKt5FW25aTOWKyV_IeH7ajb5ojGPcVypeT3c7PF5HWZMJCAdAxYt9VkdMSaCgYKATASARESFQEjDvL9_87oPJ7An0Y2_U_r6ekA6w0163",
             "expires_in": 3599,
             "refresh_token": "1//0d8h5W5ZDA2eOCgYIARAAGA0SNwF-L9Ir5sSf5pF9xxJv2qI-qfD2Myg_00A1v3Fa577rE3Ki5Q3PLFpqF5nHJCi7e_v7bhKQUBE",
             "scope": "https://mail.google.com/",
             "token_type": "Bearer"}
    return flask.render_template("authenticate-finish.html", token=tests['refresh_token'])


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.

    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
