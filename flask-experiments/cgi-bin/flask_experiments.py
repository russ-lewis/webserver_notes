import google.oauth2.credentials
import google_auth_oauthlib.flow

import MySQLdb
import private_no_share_dangerous_passwords as pnsdp
SQL_DB = "flask_experiments"

import github_client_secret

import random   # in Python 3, use: import secrets

import json
import urllib
import requests

from googleapiclient.discovery import build

from flask import Flask, request, render_template, url_for, redirect, make_response, g
app = Flask(__name__)



LOGIN_TIMEOUT   = "00:05:00"
SESSION_TIMEOUT = "00:30:00"



# this seems very strange to me, but I think it's actually correct: the
# database connection is a single object, which is shared amongst *all*
# of the requests.  Note that I don't have any code for re-connecting
# the database; if this connection fails, the application is dead.  I
# need to fix that!
#
# TOOD: fix that

def get_db():
    # the database connection is stored in the application context.  Contrary
    # to what the name implies, this really doesn't persist across requests;
    # rather, it's a single context, per-client-request, which can be shared
    # across requests if you happen to have *nested invocation*.
    #
    # So on every new HTTP operation, expect to open a new DB connection.
    #
    # TODO: investigate connection pooling and SQL Alchemy.  That seems to be
    #       the standard-of-choice for SQL databases in Flask.

    if not hasattr(g, "db"):
        g.db = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                               user   = pnsdp.SQL_USER,
                               passwd = pnsdp.SQL_PASSWD,
                               db     = SQL_DB)
    return g.db



def gen_nonce():
    return "%032x" % random.getrandbits(128)
    


def get_session():
    # if the user doesn't even report a cookie, then we don't have any session
    # to connect to; create one.
    if "sessionID" not in request.cookies or request.cookies["sessionID"] == "":
        return new_session()

    # ok, the session ID appears to exist.  Let's confirm it in the DB.
    id = request.cookies["sessionID"]

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id,gmail,github FROM sessions WHERE id=%s AND expiration>NOW();", (id,))
    records = cursor.fetchall()
    cursor.close()

    # ignore the cookie if it's not in the database.  Recreate from scratch.
    # Note that an expired session is treated the same as a non-existent one.
    if len(records) == 0:
        return new_session()

    # touch the record; keep the session alive by adjusting the expiration.
    # Note that this operation is completely isolated from other operations, so
    # I'm OK with committing here.  (I don't care if the session-creation operation
    # isn't atomic with other operations.)
    cursor = db.cursor()
    cursor.execute("UPDATE sessions SET expiration=ADDTIME(NOW(),%s);", (SESSION_TIMEOUT,))
    cursor.close()
    db.commit()

    # build the session dictionary
    return { "id"    : id,
             "gmail" : records[0][1],
             "github": records[0][2], }

def new_session():
    nonce = gen_nonce()

    # create the session in the DB
    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO sessions(id,expiration) VALUES(%s,ADDTIME(NOW(),%s));", (nonce, SESSION_TIMEOUT))
    rowcount = cursor.rowcount 
    cursor.close()
    db.commit()

    global russ_set_sessionID
    russ_set_sessionID = nonce

    return { "id"    : nonce,
             "gmail" : None,
             "github": None, }

# if this is anything other than None, then we will call set_cookie() on the response
# object when we're done, to update the sessionID variable.
russ_set_sessionID = None

@app.after_request
def russ_set_sessionID_callback(resp):
    global russ_set_sessionID

    if russ_set_sessionID is not None:
        resp.set_cookie("sessionID", russ_set_sessionID)
        russ_set_sessionID = None

    return resp



# this holds the flash messages stored by russ_flash().  It has three
# possible states:
#    None - no cookie changes required at end (init state)
#    []   - browser has non-empty cookie; empty it at end
#    list - store messages at end

russ_flash_messages_pending = None

def russ_flash(msg):
    global russ_flash_messages_pending

    if russ_flash_messages_pending is None:
        russ_flash_messages_pending = [msg]
        russ_flash_messages_pending.append("TODO: include code to check if we've read the old messages.  If we haven't, then read them in...because we're losing multiple-message situations, in the case where we have multiple redirects or pages before we actually display the messages.")
        return

    # otherwise, must be a list; could be empty
    russ_flash_messages_pending.append(msg)

@app.after_request
def russ_post_flash_messages(resp):
    global russ_flash_messages_pending

    if russ_flash_messages_pending is None:
        return resp   # NOP

    # otherwise, must be a list; could be empty
    if len(russ_flash_messages_pending) == 0:
        resp.set_cookie("flash_messages", "")
    else:
        resp.set_cookie("flash_messages", json.dumps(russ_flash_messages_pending))

    # reset the list.  I *think* this is necessary, since it's a global,
    # although I don't 100% understand Flask's model for how global
    # variables work.
    russ_flash_messages_pending = None

    return resp

def russ_get_flashed_messages():
    global russ_flash_messages_pending

    if "flash_messages" not in request.cookies or request.cookies["flash_messages"] == "":
        russ_flash_messages_pending = None   # this is probably redundant, right?
        return []

    msgs = json.loads(request.cookies["flash_messages"])
    russ_flash_messages_pending = []
    return msgs

# this makes the get() function callable from our templates
app.jinja_env.globals.update(russ_get_flashed_messages=russ_get_flashed_messages)



@app.route("/")
def index():
    return render_template("index.html")



@app.route("/login")
def login():
    session = get_session()

    if "service" not in request.values:
        russ_flash("The 'login' page requires certain parameters, which were not supplied.")
        return redirect(url_for("index"), code=303)

    service = request.values["service"]
    if service not in ["google","github"]:
        russ_flash("Unsupported service for the 'login' page.")
        return redirect(url_for("index"), code=303)

    if service == "github":
        russ_flash("TODO: integrate the two login processes")
        return redirect(url_for("login_github"), code=303)

    # is the user already logged in?  If so, then redirect back to the index.
    # Note that this is not an error, so we probably shouldn't flash to the
    # user, but I'm going to do this temporarily just for the sake of debug.
    if session is not None and session["gmail"] is not None:
        russ_flash("You are already logged in as: "+session["gmail"])
        return redirect(url_for("index"), code=303)

    # Use the google_client_secret.json file to identify the application
    # requesting authorization. The client ID (from that file) and access
    # scopes are required.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "google_client_secret.json",
        scopes=["https://www.googleapis.com/auth/userinfo.email"])

    # Indicate where the API server will redirect the user after the user
    # completes the authorization flow. The redirect URI is required.  Note
    # that the 'external' argument will cause the hostname to be included,
    # which is critical for an redirect that we're going to send to Google!
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    # NOTE: The login attempt has a different nonce than the session, since
    #       there might be multiple login attempts by the same user, in the
    #       same browser.
    nonce = gen_nonce()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""INSERT INTO login_states(nonce,service,sessionID,expiration) VALUES(%s,"google",%s,ADDTIME(NOW(),%s));""", (nonce,session["id"],LOGIN_TIMEOUT))
    cursor.close()
    db.commit()
    db.close()

    auth_url,state = flow.authorization_url(
        state="google:"+nonce,
        include_granted_scopes="true"
    )

    russ_flash("URL going to Google: "+auth_url)
    return redirect(auth_url, code=303)



@app.route("/login_oauth2callback", methods=["GET"])
def login_oauth2callback():
    nonce = request.values["state"]
    code  = request.values["code"]
    scope = request.values["scope"]

    # sanity check that this nonce is for the proper service!
    nonce = nonce.split(":")
    assert len(nonce) == 2   # TODO: make this user error
    assert nonce[0] == "google"   # TODO: also this
    nonce = nonce[1]

    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    # is the nonce reasonable?  Note that we'll reject anything where the
    # time is too old.
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM login_states WHERE nonce=%s AND service="google" AND NOW()<expiration;""", (nonce,))
    ok = (cursor.rowcount > 0)
    cursor.close()

    # clean up the nonce from the table (if it happens to exist).  Note that
    # this is common code between the 'ok' and login-expired code
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_states WHERE nonce=%s;", (nonce,))
    rowcount = cursor.rowcount
    cursor.close()

    if not ok:
        conn.commit()
        conn.close()
        if rowcount > 0:
            russ_flash("Login process has expired")
        else:
            russ_flash("Invalid nonce")
        return redirect(url_for("index"), code=303)

    # exchange the code for the real token.

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "google_client_secret.json",
        scopes=None,
        state=nonce)

    # I'm not sure why we have to set the redirect_uri here; it seems
    # like it would be redundant.  But the operation will fail if we
    # don't do this.
    flow.redirect_uri = url_for("login_oauth2callback", _external=True)

    flow.fetch_token(code=code)

    cred = flow.credentials
    cred_text = json.dumps({"token"     : cred.token,
                            "token_uri" : cred.token_uri,
                            "scopes"    : cred.scopes})

    # get the user's email address
    userinfo = build("oauth2","v2", credentials=cred).userinfo().get().execute()

    gmail = userinfo["email"]

    return "TODO: update the session update here.  Don't set 'gmail', set 'github' instead, and also don't INSERT, do an UPDATE"

    # create the session in the database
    cursor = conn.cursor()
    cursor.execute("INSERT INTO sessions(id,gmail,expiration) VALUES(%s,%s,ADDTIME(NOW(),%s));", (nonce,gmail, SESSION_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    russ_flash("Successfully logged in as gmail account '%s'" % gmail);
    return redirect(url_for("index"), code=303)



@app.route("/login_github")
def login_github():
    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    nonce = gen_nonce()

    cursor = conn.cursor()
    cursor.execute("""INSERT INTO login_states(nonce,service,expiration) VALUES(%s,"github",ADDTIME(NOW(),%s));""", (nonce,LOGIN_TIMEOUT))
    assert cursor.rowcount == 1
    cursor.close()
    conn.commit()
    conn.close()

    github_oauth_url = "https://github.com/login/oauth/authorize"
    client_id    = github_client_secret.CLIENT_ID
    redirect_uri = url_for("login_github_oauth2callback", _external=True)
    scope        = ""    # just ask for public info.  All we care about is the GitHub ID of the user that's logging in
    state        = "github:"+nonce

    url = "%s?%s" % (
              github_oauth_url,
              urllib.urlencode({"client_id"    : client_id,
                                "redirect_url" : redirect_uri,
                                "scope"        : scope,
                                "state"        : state,})
          )

    russ_flash("URL going to GitHub: "+url)
    return redirect(url, code=303)



@app.route("/login_github_oauth2callback")
def login_github_oauth2callback():
    nonce = request.values["state"]
    code  = request.values["code"]

    # sanity check that this nonce is for the proper service!
    nonce = nonce.split(":")
    assert len(nonce) == 2   # TODO: make this user error
    assert nonce[0] == "github"   # TODO: also this
    nonce = nonce[1]

    # connect to the SQL database.  Note that we're using the parameters from
    # the the private config file.
    conn = MySQLdb.connect(host   = pnsdp.SQL_HOST,
                           user   = pnsdp.SQL_USER,
                           passwd = pnsdp.SQL_PASSWD,
                           db     = SQL_DB)

    # is the nonce reasonable?  Note that we'll reject anything where the
    # time is too old.
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM login_states WHERE nonce=%s AND service="github" AND NOW()<expiration;""", (nonce,))
    ok = (cursor.rowcount > 0)
    cursor.close()

    # clean up the nonce from the table (if it happens to exist).  Note that
    # this is common code between the 'ok' and login-expired code
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_states WHERE nonce=%s;", (nonce,))
    rowcount = cursor.rowcount
    cursor.close()

    if not ok:
        conn.commit()
        conn.close()
        if rowcount > 0:
            return "login process has expired"
        else:
            return "invalid nonce"

    # exchange the code for the real token.

    github_token_url = "https://github.com/login/oauth/access_token"
    client_id     = github_client_secret.CLIENT_ID
    client_secret = github_client_secret.CLIENT_SECRET
    # 'code' is taken from the form variables above
    redirect_uri  = url_for("login_github_oauth2callback", _external=True)
    state         = "github:"+nonce

    url = "%s?%s" % (
              github_token_url,
              urllib.urlencode({"client_id"     : client_id,
                                "client_secret" : client_secret,
                                "code"          : code,
                                "redirect_url"  : redirect_uri,
                                "state"         : state,})
          )

    resp = requests.post(url)
    token = None
    vars = {}
    for param in resp.text.strip().split('&'):
        (name,val) = param.split('=')
        vars[name] = val
        if name == "access_token":
            token = val
            break

    if token is None:
        russ_flash("ERROR: access_token not provided in data from GitHub.")
        return redirect(url_for("index"), code=303)

    email_resp = requests.get("https://api.github.com/user?access_token="+token)
    github_id = json.loads(email_resp.text.encode("utf-8"))["login"]

    return "TODO: need to change how we update the database here.  Change the existing session, instead of inserting a new one."

    # create the session in the database
    cursor = conn.cursor()
    cursor.execute("INSERT INTO sessions(id,gmail,expiration) VALUES(%s,%s, ADDTIME(NOW(),%s));", (nonce,gmail, SESSION_TIMEOUT))
    cursor.close()
    conn.commit()
    conn.close()

    # send the nonce as the cookie ID to the user
    resp = make_response(render_template("loginOK.html", username="russ", gmail=gmail))
    resp.set_cookie("sessionID", nonce)

    return resp



@app.route("/debug/test_flash_msg")
def test_flash_msg():
    if "msg" not in request.values:
        russ_flash("test_flash_msg(): the 'msg' variable is required.")
        return redirect(url_for("index"), code=303)

    russ_flash(request.values["msg"])
    return redirect(url_for("index"), code=303)



@app.route("/util/cleanup_expired_records")
def cleanup_expired_records():
    db = get_db()

    cursor = db.cursor()
    cursor.execute("DELETE FROM login_states WHERE expiration<NOW();")
    russ_flash("Deleted %d rows from the table 1" % cursor.rowcount)
    cursor.close()

    cursor = db.cursor()
    cursor.execute("DELETE FROM sessions WHERE expiration<NOW();")
    russ_flash("Deleted %d rows from the table 2" % cursor.rowcount)
    cursor.close()

    db.commit()

    return redirect(url_for("index"), code=303)


