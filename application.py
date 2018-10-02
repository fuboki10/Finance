import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

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
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # select each symbol owned by the user and it's amount
    portfolio_symbols = db.execute("SELECT shares, symbol \
                                    FROM portfolio WHERE id = :id", \
                                    id=session["user_id"])

    # create a temporary variable to store TOTAL worth ( cash + share)
    total_cash = 0

    # update each symbol prices and total
    for portfolio_symbol in portfolio_symbols:
        symbol = portfolio_symbol["symbol"]
        shares = portfolio_symbol["shares"]
        stock = lookup(symbol)
        total = shares * stock["price"]
        total_cash += total
        db.execute("UPDATE portfolio SET price=:price, \
                    total=:total WHERE id=:id AND symbol=:symbol", \
                    price=usd(float(stock["price"])), \
                    total=usd(float(total)), id=session["user_id"], symbol=symbol)

    # update user's cash in portfolio
    updated_cash = db.execute("SELECT cash FROM users \
                               WHERE id=:id", id=session["user_id"])

    # update total cash -> cash + shares worth
    total_cash += float(updated_cash[0]["cash"])

    # print portfolio in index homepage
    updated_portfolio = db.execute("SELECT * from portfolio \
                                    WHERE id=:id", id=session["user_id"])

    return render_template("index.html", stocks=updated_portfolio, \
    cash=usd(float(updated_cash[0]["cash"])), total= usd(float(total_cash)) )



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")
    else:
        # ensure proper symbol
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol",400)

        # ensure proper number of shares
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be positive integer",400)
        except:
            return apology("Shares must be positive integer",400)

        # select user's cash
        money = db.execute("SELECT cash FROM users WHERE id = :id", \
                            id=session["user_id"])

        # check if enough money to buy
        if not money or float(money[0]["cash"]) < stock["price"] * shares:
            return apology("Not enough money",400)

        # update history
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES(:symbol, :shares, :price, :id)", \
                    symbol=stock["symbol"], shares=shares, \
                    price=usd(float(stock["price"])), id=session["user_id"])

        # update user cash
        db.execute("UPDATE users SET cash = cash - :purchase WHERE id = :id", \
                    id=session["user_id"], \
                    purchase=stock["price"] * float(shares))

        # Select user shares of that symbol
        user_shares = db.execute("SELECT shares FROM portfolio \
                           WHERE id = :id AND symbol=:symbol", \
                           id=session["user_id"], symbol=stock["symbol"])

        # if user doesn't has shares of that symbol, create new stock object
        if not user_shares:
            db.execute("INSERT INTO portfolio (name, shares, price, total, symbol, id) \
                        VALUES(:name, :shares, :price, :total, :symbol, :id)", \
                        name=stock["name"], shares=shares, price=usd(float(stock["price"])), \
                        total=usd(shares * float(stock["price"])), \
                        symbol=stock["symbol"], id=session["user_id"])

        # Else increment the shares count
        else:
            shares_total = user_shares[0]["shares"] + shares
            db.execute("UPDATE portfolio SET shares=:shares \
                        WHERE id=:id AND symbol=:symbol", \
                        shares=shares_total, id=session["user_id"], \
                        symbol=stock["symbol"])

        # return to index
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    histories = db.execute("SELECT * from histories WHERE id=:id",id=session["user_id"])

    return render_template("history.html",histories=histories)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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

    # display form
    # retrieve stock quote
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("enter symbol",400)

        quote = lookup(symbol)

        if not quote:
            return apology("invalid symbol",400)

        # display stock quote

        return render_template("quoted.html",stock=quote)

    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""


    if request.method == "POST":

        username = request.form.get("username")

        # check if username aren`t blank
        if not username:
            return apology("Missing username!",400)

        password = request.form.get("password")

        # check if password aren`t blank
        if not password:
            return apology("Missing password!",400)

        confpass = request.form.get("confirmation")

        # check if confpassword aren`t blank
        if not confpass:
            return apology("Missing confirmation password!",400)
        # valid passwords

        if password != confpass:
            return apology("password isn`t valid",400)

        # hash password
        hashed_pass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # check if it is hashed
        if not check_password_hash(hashed_pass, password):
            return apology("Failed hashing password!",400)

        # add user to database

        result = db.execute("INSERT INTO users (username,hash) VALUES(:username,:hash)",username=username,hash=hashed_pass)

        if not result:
            return apology("Username existed",400)
        # log them in

        session["user_id"] = result

        return redirect("/")

    else:

        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # remove stock from user`s portfolio
    if request.method == "GET":
        return render_template("sell.html")
    else:
        # ensure proper symbol
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol",400)

        # ensure proper number of shares
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be positive integer",400)
        except:
            return apology("Shares must be positive integer",400)

        # select the symbol shares of that user
        user_shares = db.execute("SELECT shares FROM portfolio \
                                 WHERE id = :id AND symbol=:symbol", \
                                 id=session["user_id"], symbol=stock["symbol"])

        # check if enough shares to sell
        if not user_shares or int(user_shares[0]["shares"]) < shares:
            return apology("Not enough shares",400)

        # update history of a sell
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES(:symbol, :shares, :price, :id)", \
                    symbol=stock["symbol"], shares=-shares, \
                    price=usd(float(stock["price"])), id=session["user_id"])

        # update user cash (increase)
        db.execute("UPDATE users SET cash = cash + :purchase WHERE id = :id", \
                    id=session["user_id"], \
                    purchase=stock["price"] * float(shares))

        # decrement the shares count
        shares_total = user_shares[0]["shares"] - shares

        # if after decrement is zero, delete shares from portfolio
        if shares_total == 0:
            db.execute("DELETE FROM portfolio \
                        WHERE id=:id AND symbol=:symbol", \
                        id=session["user_id"], \
                        symbol=stock["symbol"])
        # otherwise, update portfolio shares count
        else:
            db.execute("UPDATE portfolio SET shares=:shares \
                    WHERE id=:id AND symbol=:symbol", \
                    shares=shares_total, id=session["user_id"], \
                    symbol=stock["symbol"])

        # return to index
        return redirect("/")

def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


@app.route("/addcash",methods=["GET","POST"])
@login_required
def addCash():
    if request.method == "POST":
        new_cash = request.form.get("cash")
        if not new_cash:
            return apology("Please enter your cash!",400)

        # update cash
        db.execute("UPDATE users SET cash = cash + :new_cash WHERE id =:id",id=session["user_id"],new_cash=usd(float(new_cash)))

    else:

        return render_template("addcash.html")

    # back to home
    return redirect("/")


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
