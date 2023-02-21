import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from pathlib import Path

from helpers import apology, login_required, lookup, usd

# Configure application
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
THIS_FOLDER = Path(__file__).parent.resolve()
db = SQL(f"sqlite:////{THIS_FOLDER}/finance.db")

# Allow foreign keys in sqlite db
db.execute("PRAGMA foreign_keys = ON")

# Create tables

# users
db.execute("CREATE TABLE IF NOT EXISTS 'users' ('id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'username' TEXT NOT NULL, 'hash' TEXT NOT NULL, 'cash' NUMERIC NOT NULL DEFAULT 10000.00 )")
db.execute("CREATE UNIQUE INDEX IF NOT EXISTS 'username' ON 'users' ('username')")

# portfolios: symbol, shares, user_id
db.execute("CREATE TABLE IF NOT EXISTS 'portfolios' ( 'user_id' INTEGER NOT NULL, 'symbol' VARCHAR(5) NOT NULL, 'shares' INTEGER NOT NULL, FOREIGN KEY('user_id') REFERENCES 'users'('id') PRIMARY KEY('user_id', 'symbol') )")

# transactions: user_id, shares, price, symbol
db.execute("CREATE TABLE IF NOT EXISTS 'transactions' ( 'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'user_id' INTEGER NOT NULL, 'shares' INTEGER NOT NULL,'price' NUMERIC NOT NULL, 'symbol' VARCHAR(5) NOT NULL, 'date' TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, FOREIGN KEY('user_id') REFERENCES 'users'('id') )")

# Make sure API key is set
load_dotenv()
if not os.getenv("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]
    stocks = []

    user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    total = cash = user[0]["cash"]
    portfolio = db.execute("SELECT symbol, shares FROM portfolios WHERE user_id = ? ORDER BY symbol ASC", user_id)

    for entry in portfolio:
        quoted = lookup(entry["symbol"])
        price_stock = quoted["price"]
        total_stock = price_stock * entry["shares"]
        stock = {
            "symbol": quoted["symbol"],
            "name": quoted["name"],
            "shares": entry["shares"],
            "price": usd(price_stock),
            "total": usd(total_stock)
        }
        total += total_stock
        stocks.append(stock)

    return render_template("index.html", total=usd(total), cash=usd(cash), stocks=stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")

        # Ensure symbol was submitted
        if not symbol:
            return apology("missing symbol", 400)

        shares = request.form.get("shares")

        # Ensure number of shares was submitted
        if not shares:
            return apology("missing shares", 400)
        else:
            shares = int(shares)

        user_id = session["user_id"]
        quoted = lookup(symbol)

        if not quoted:
            return apology("invalid symbol", 400)
        else:
            symbol = quoted['symbol']

        # Query database for cash
        user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        cash = user[0]["cash"]
        price = quoted['price']
        cost = price * shares

        if cost > cash:
           return apology("can't afford", 400)

        # Add transaction to db
        db.execute("INSERT INTO transactions (user_id, shares, price, symbol) VALUES (?, ?, ?, ?)", user_id, shares, price, symbol)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - cost, user_id)

        # Add or update user's portfolio
        row = db.execute("SELECT shares FROM portfolios WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(row):
            prev_shares = row[0]["shares"]
            total_shares = prev_shares + shares
            db.execute("UPDATE portfolios SET shares  = ? WHERE user_id = ? AND symbol = ?", total_shares, user_id, symbol)
        else:
            db.execute("INSERT INTO portfolios (user_id, symbol, shares) VALUES (?, ?, ?)", user_id, symbol, shares)

        # Redirect user to home page
        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    transactions = db.execute("SELECT shares, price, symbol, date FROM transactions WHERE user_id = ? ORDER BY date DESC", user_id)

    for transaction in transactions:
        transaction['total'] = usd(transaction['price'] * transaction['shares'] * -1)
        transaction['price'] = usd(transaction['price'])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password."""

    if request.method == "POST":

        user_id = session["user_id"]

        current_password = request.form.get("current password")
        new_password = request.form.get("new password")
        confirmation = request.form.get("confirmation")

        # Ensure past password was submitted
        if not current_password:
            return apology("must provide current password", 403)

        # Query database for username
        user = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        if not check_password_hash(user[0]["hash"], current_password):
            return apology("invalid current password", 403)

        # Ensure new password was submitted
        if not new_password:
            return apology("must new provide password", 400)

        # Ensure new password confirmation was submitted
        if not confirmation:
            return apology("must provide new password confirmation", 400)

        # Ensure new passwords match
        if new_password != confirmation:
            return apology("new passwords must match", 400)

        hashed_new_password = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_new_password, user_id)

        # Redirect user to home page
        flash("Password Changed")
        return redirect("/")



    else:
        return render_template("password.html")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("missing symbol", 400)

        quoted = lookup(symbol)

        if not quoted:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", name=quoted["name"], symbol=quoted["symbol"], price=usd(quoted["price"]))

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

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

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 403)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                           username=request.form.get("username"))

        # Ensure username does not exist
        if len(rows) != 0:
            return apology("username already taken", 403)

        username = request.form.get("username")
        hashed_password = generate_password_hash(request.form.get("password"))
        user_id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Remember which user has logged in
        session["user_id"] = user_id

        # Redirect user to home page
        flash("Registered!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]
    portfolio = db.execute("SELECT symbol, shares FROM portfolios WHERE user_id = ? ORDER BY symbol ASC", user_id)

    if request.method == "POST":

        symbol = request.form.get("symbol")

        # Ensure symbol was submitted
        if not symbol:
            return apology("missing symbol", 400)

        row = db.execute("SELECT shares FROM portfolios WHERE user_id = ? AND symbol = ?", user_id, symbol)
        prev_shares = row[0]["shares"]
        if len(row) == 0 or prev_shares == 0:
            return apology("doesn't own shares of that stock", 400)

        shares = request.form.get("shares")

        # Ensure number of shares was submitted
        if not shares:
            return apology("missing shares", 400)
        else:
            shares = int(shares)

        if prev_shares < shares:
            return apology("too many shares")

        quoted = lookup(symbol)

        if not quoted:
            return apology("invalid symbol", 400)
        else:
            symbol = quoted['symbol']

        # Query database for cash
        user = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        cash = user[0]["cash"]
        price = quoted['price']
        cost = price * shares

        # Add transaction to db
        db.execute("INSERT INTO transactions (user_id, shares, price, symbol) VALUES (?, ?, ?, ?)", user_id, -shares, price, symbol)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + cost, user_id)

        # Update user's portfolio
        new_shares = prev_shares - shares
        db.execute("UPDATE portfolios SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, user_id, symbol)

        row = db.execute("SELECT shares FROM portfolios WHERE user_id = ? AND symbol = ?", user_id, symbol)
        shares = row[0]["shares"]

        if shares <= 0:
            db.execute("DELETE FROM portfolios WHERE user_id = ? AND symbol = ?", user_id, symbol)

        # Redirect user to home page
        flash("Sold!")
        return redirect("/")

    else:
        return render_template("sell.html", portfolio=portfolio)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.
    # app.debug = True
    app.run()
