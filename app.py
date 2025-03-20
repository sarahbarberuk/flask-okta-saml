from flask import Flask, redirect, request, session, render_template
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import json

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

def get_saml_settings():
    """ Load SAML settings from the JSON file """
    with open("settings.json", "r") as f:
        return json.load(f)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    """ Redirect user to Okta for authentication """
    req = {
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args,
        "post_data": request.form
    }
    
    auth = OneLogin_Saml2_Auth(req, get_saml_settings())
    return redirect(auth.login())

@app.route("/auth/acs", methods=["POST"])
def acs():
    """ Assertion Consumer Service (ACS) - Handle SAML response """
    req = {
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args,
        "post_data": request.form
    }
    
    auth = OneLogin_Saml2_Auth(req, get_saml_settings())
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        return f"Error: {errors}"

    if not auth.is_authenticated():
        return "Authentication failed"

    session["user_data"] = auth.get_attributes()
    session["name_id"] = auth.get_nameid()
    
    return redirect("/profile")

@app.route("/profile")
def profile():
    """ Show user profile after login """
    if "user_data" not in session:
        return redirect("/login")
    
    return render_template("profile.html", user=session["user_data"], name_id=session["name_id"])

@app.route("/logout")
def logout():
    """ Log user out and redirect to Okta logout """
    req = {
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args,
        "post_data": request.form
    }
    
    auth = OneLogin_Saml2_Auth(req, get_saml_settings())
    return redirect(auth.logout())

if __name__ == "__main__":
    app.run(debug=True)
