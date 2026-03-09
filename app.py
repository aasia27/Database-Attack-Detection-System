from flask import Flask, render_template, request, redirect, url_for
from attack_detector import detect_sql_injection, get_attack_type
from database import validate_login, log_attack, get_recent_attacks

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # detect SQLi on raw inputs
        if detect_sql_injection(username) or detect_sql_injection(password):
            attack_type = get_attack_type(username + " " + password)
            log_attack(username or "unknown", f"{username} | {password}", attack_type)
            msg = "⚠ Attack detected and logged!"
            return render_template("login.html", message=msg)

        # safe login check
        if validate_login(username, password):
            return redirect(url_for("dashboard"))
        else:
            msg = "❌ Invalid credentials"

    return render_template("login.html", message=msg)

@app.route("/dashboard")
def dashboard():
    attacks = get_recent_attacks(10)
    return render_template("dashboard.html", attacks=attacks)

if __name__ == "__main__":
    app.run(debug=True)