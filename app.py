import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    money = db.execute(
        "SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares)>0", session["user_id"])

    # for item in portfolio:
    #     print(item)

    total = money

    for item in portfolio:
        lookedup = lookup(item["symbol"])
        item["name"] = lookedup["name"]
        item["price"] = usd(lookedup['price'])
        item["total"] = usd(lookedup['price'] * item["SUM(shares)"])
        total += (lookedup['price'] * item["SUM(shares)"])

    money = usd(money)
    total = usd(total)

    return render_template("index.html", portfolio=portfolio, money=money, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # TODO:
    # use SQL to find out how much money user has
    # lookup the price of a selected stock multiplied by number of shares and check if user has enough money
    # if yes, and deduct the price
    price = ""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # print(lookup(symbol))
        quoted = lookup(symbol)
        money = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"])
        new_amount = money
        try:
            shares = int(shares)
            price = shares * quoted['price']
        except:
            return apology("Wrong Symbol or Amount")

        result = ""

        if shares < 1:
            return apology("Not valid Amount")

        if quoted != None and type(shares) == type(1):

            if money[0]["cash"] > price:
                result = f"You bought {quoted['name']} ({quoted['symbol']}) for {usd(price)}"

                new_amount = money[0]["cash"] - price
                db.execute("UPDATE users SET cash = ? WHERE id = ?",
                           new_amount, session["user_id"])

                db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                           session["user_id"], symbol, shares, -1 * price, )
                new_amount = usd(new_amount)
            else:
                return apology("You do not have enough money to complete this transaction")
            # print(result)
        else:
            # result = "Symbol not found"
            # print(result)
            return apology("Wrong Symbol")

        return render_template("buy.html", result=result, new_amount=new_amount)

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    # print(history)

    for i in history:
        i["name"] = lookup(i["symbol"])["name"]

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # print(lookup(symbol))
        quoted = lookup(symbol)

        result = ""

        if quoted != None:
            result = f"A share of {quoted['name']} ({quoted['symbol']}) costs {usd(quoted['price'])}"
            # print(result)
        else:
            return apology("Symbol not found")

        return render_template("quote.html", result=result)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # return apology("TODO")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if username == "":
            return apology("must provide username")

        # Ensure username is not used
        rows = db.execute("SELECT * FROM users")

        usernames = []
        for i in rows:
            usernames.append(i["username"])

        if username in usernames:
            return apology("Used username")

        # Ensure password was submitted
        elif not password:
            return apology("must provide password")

        # Ensure that password contains at least one number
        elif password.isalpha():
            return apology("Your password has to conatin at least one number or special sign")

        # Ensure password was confirmed
        elif not confirmation:
            return apology("must provide password")

        # Ensure confirmed password was the same
        elif confirmation != password:
            return apology("password must be the same")

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       username, generate_password_hash(password))

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    price = ""
    index = db.execute(
        "SELECT symbol, SUM(shares) FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", session["user_id"])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # print(lookup(symbol))
        quoted = lookup(symbol)

        try:
            shares = int(shares)
            price = shares * quoted['price']
        except:
            return apology("Wrong Symbol or Amount")

        result = ""

        if shares < 1:
            return apology("Not valid Amount")

        money = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"])

        owned = db.execute(
            "SELECT symbol, SUM(shares) FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol HAVING SUM(shares) >= ?", session["user_id"], symbol, shares)

        if owned != [] and type(shares) == type(1):

            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                       session["user_id"], symbol, -1 * shares, price)

            new_amount = money[0]["cash"] + price
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       new_amount, session["user_id"])

        else:
            return apology("Not enough owned shares")
        price = usd(price)
        new_amount = usd(new_amount)
        return render_template("sell.html", new_amount=new_amount, price=price, owned=owned)

    else:
        return render_template("sell.html", index=index)
