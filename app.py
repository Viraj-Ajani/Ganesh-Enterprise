import os
from cs50 import SQL
from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, usd
from re import compile

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    kankotri = db.execute("SELECT * FROM kankotri")
    kankotris = []
    for i in kankotri:
        kankotris.append(i["id"])
    if session['username'] == "admin":
        orders = db.execute("SELECT * FROM orders")
        if request.method == "POST":
            db.execute("DELETE FROM orders WHERE orderid = ?", int(request.form.get("button")))
            orders = db.execute("SELECT * FROM orders")
        return render_template("admin.html", orders = orders)
    if request.method == "POST":
        if not request.form.get("id"):
            return render_template("index.html", kankotris = kankotris, message = "Oops! You forget to write ID")
        if not request.form.get("quantity"):
            return render_template("index.html", kankotris = kankotris, message = "Oops! You forget to write Quantity")
        if request.form.get("button") == "availability":
            if db.execute("SELECT stock FROM kankotri WHERE id = ?", request.form.get("id"))[0]["stock"]-int(request.form.get("quantity")) > 0:
                return render_template("index.html", kankotris = kankotris, message = "Available")
            else:
                return render_template("index.html", kankotris = kankotris, message = "Out of Stock")
        else:
            if db.execute("SELECT stock FROM kankotri WHERE id = ?", request.form.get("id"))[0]["stock"]-int(request.form.get("quantity")) > 0:
                db.execute("UPDATE kankotri SET stock = ? WHERE id = ?", db.execute("SELECT stock FROM kankotri WHERE id = ?", request.form.get("id"))[0]["stock"]-int(request.form.get("quantity")),request.form.get("id"))
                amount = int(db.execute("SELECT price FROM kankotri WHERE id = ?", request.form.get("id"))[0]["price"]*int(request.form.get("quantity"))/100)
                db.execute("INSERT INTO orders (username, id, quantity, amount) VALUES (?, ?, ?, ?)", session["username"], request.form.get("id"), request.form.get("quantity"), amount)
                return render_template("index.html", kankotris = kankotris, message = "Order placed successfully")
            else:
                return render_template("index.html", kankotris = kankotris, message = "Out of Stock")
    return render_template("index.html", kankotris = kankotris)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        session['username'] = request.form.get("username")
        session['password'] = request.form.get("password")
        # print(session['username'])

        # Ensure username was submitted
        if not session['username']:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not session['password']:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM user WHERE username = ?", session['username'])
        # print(rows)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], session['password']):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/order", methods=["GET", "POST"])
@login_required
def order():
    orders = db.execute("SELECT * FROM orders WHERE username = ?", session["username"])
    total = db.execute("SELECT SUM(amount) AS total FROM orders WHERE username = ?", session["username"])[0]["total"]
    return render_template("order.html", orders = orders, total = total)

@app.route("/stock", methods=["GET", "POST"])
@login_required
def stock():
    kankotri = db.execute("SELECT * FROM kankotri")
    kankotris = []
    for i in kankotri:
        kankotris.append(i["id"])
    print(kankotris)
    if request.method == "POST":
        if request.form.get("button") == "edit":
            db.execute("UPDATE kankotri SET stock = ? WHERE id = ?", request.form.get("quantity"), request.form.get("id"))
        if request.form.get("button") == "add":
            db.execute("UPDATE kankotri SET stock = ? WHERE id = ?", db.execute("SELECT stock FROM kankotri WHERE id = 3701")[0]["stock"]+int(request.form.get("quantity")),request.form.get("id"))
        if request.form.get("button") == "remove":
            db.execute("UPDATE kankotri SET stock = ? WHERE id = ?", db.execute("SELECT stock FROM kankotri WHERE id = 3701")[0]["stock"]-int(request.form.get("quantity")),request.form.get("id"))
    return render_template("stock.html", kankotris = kankotris)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirm password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirm password", 400)

        # Ensure that password and confirm password matches
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirm password are not same", 400)

        mailid = request.form.get("mailid")
        p = compile("[A-Za-z0-9'.']+@[a-z]+.[a-z'.']+")
        if not p.match(mailid):
            return apology("Mail id is not valid")

        # Ensure that username doesn't exists
        for i in db.execute("SELECT username FROM user"):
            if i["username"] == request.form.get("username"):
                return apology("Sorry username already exists")
        db.execute("INSERT INTO user (username, hash, mailid) VALUES(?, ?, ?)", request.form.get("username"),
                   generate_password_hash(request.form.get("password")), mailid)
        return redirect("/login")
    else:
        return render_template("register.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
