"""Performs support tasks for Pyaarlo to use OAUTH authentication.

In order to keep the client secret (erm...) secret, we provide a simple
web wrapper to retrieve an OUATH2 token for Pyaarlo users. After the
initial interactive authentication the Pyarrlo code can use the refresh
token to return update authentication tokens without user interaction.

The code requests 'https://www.googleapis.com/auth/gmail.readonly' scope,
I tried to keep it as minimal as possible, but we do need to search for
messages from Arlo to parse out the 2FA code.
"""

import json
import urllib.parse
import urllib.request
import flask

AUTH_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'

app = flask.Flask(__name__)
app.secret_key = 'CzPcxd2uET8rbK5ARFjCyAdVKvPKyUyh'


def read_credentials():
    """Read secrets and endpoint from Google provided json file.

    Returns:
        A dictionary containing the values or None on failure.
    """
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
    """Redirect the user to the Google Authentication Webpage.

    All information needed, username etc... is grabbed by the Google code.
    """
    credentials = read_credentials()
    if credentials is None:
        return flask.render_template('error.html', error="The system isn't deployed correctly. Contact the author.")

    params = {'client_id': credentials['client_id'],
              'redirect_uri': credentials['redirect_uris'][0],
              'scope': AUTH_SCOPE,
              'response_type': 'code',
              'access_type': 'offline'}
    params = format_url_params(params)
    url = f'{credentials["auth_uri"]}?{params}'

    return flask.redirect(url)


@app.route('/oauth2-callback')
def oauth2_callback():
    """Handle the Google Authentication callback.

    If everything went well the code will display the refresh
    token and some small configuration and code snippets and how to use
    it.
    """
    code = flask.request.args.get('code', None)
    if code is None:
        return flask.render_template('error.html', error="The outh callback didn't supply a code.")

    credentials = read_credentials()
    if credentials is None:
        return flask.render_template('error.html', error="The system isn't deployed correctly. Contact the author.")

    params = {'client_id': credentials['client_id'],
              'client_secret': credentials['client_secret'],
              'redirect_uri': credentials['redirect_uris'][0],
              'code': code,
              'grant_type': 'authorization_code'}
    params = urllib.parse.urlencode(params).encode('utf-8')
    refresh_url = credentials["token_uri"]

    response = urllib.request.urlopen(refresh_url, params).read()
    response = json.loads(response)

    refresh_token = response.get("refresh_token", None)
    if refresh_token is None:
        return flask.render_template('error.html', error="There was no refresh_token returned.")

    return flask.render_template("success.html", token=response["refresh_token"])


@app.route('/refresh')
def refresh():
    """Get a new Authentication Token.

    This is called from Pyaarlo when it detects a login failure to refresh
    the authentication token.

    It returns a JSON encoded string with the new token or gives an error on any
    kind of failure.
    """
    token = flask.request.args.get('token', None)
    if token is None:
        return {'error': "You need to supply a refresh token."}, 404

    credentials = read_credentials()
    if credentials is None:
        return {'error': "The system isn't deployed correctly. Contact the author."}, 404

    params = {'client_id': credentials['client_id'],
              'client_secret': credentials['client_secret'],
              'redirect_uri': credentials['redirect_uris'][0],
              'refresh_token': token,
              'grant_type': 'refresh_token'}
    params = urllib.parse.urlencode(params).encode('utf-8')
    refresh_url = credentials["token_uri"]
    return urllib.request.urlopen(refresh_url, params).read()


@app.route('/test')
def test():
    tests = {"access_token": "teesting",
             "expires_in": 3599,
             "refresh_token": "testing",
             "scope": "https://mail.google.com/",
             "token_type": "Bearer"}
    return flask.render_template("success.html", token=tests['refresh_token'])


@app.route('/etest')
def etest():
    return flask.render_template("error.html", error="There is no error!")


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.

    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
