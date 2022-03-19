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
    name = db.execute("SELECT name FROM portfolio WHERE user_id = ? GROUP BY name ORDER BY symbol ASC", session["user_id"])
    symbol = db.execute("SELECT symbol FROM portfolio WHERE user_id = ? GROUP BY name ORDER BY symbol ASC", session["user_id"])
    #returns [{'name': 'Apple Inc'}, {'name': 'NetFlix Inc'}]
    shares = db.execute("SELECT shares FROM portfolio WHERE user_id = ? GROUP BY name ORDER BY symbol ASC", session["user_id"])
    price = []
    total = []
    portfolio = []
    for i in range(len(name)):
        price.append(lookup(symbol[i]['symbol'])['price'])
        #[155.08, 343.49]
        total.append(shares[i]['shares'] * price[i])
        #[155.08, 4465.37]

    for i in range(len(name)):
        dict = {}
        dict['name'] = name[i]['name']
        dict['symbol'] = symbol[i]['symbol']
        dict['shares'] = shares[i]['shares']
        dict['price'] = usd(price[i])
        dict['total'] = usd(total[i])
        if shares[i]['shares'] > 0:
            portfolio.append(dict)
        #[{'name': ['Apple Inc'], 'symbol': ['AAPL'], 'shares': [2], 'price': [155.09], 'total': [310.18]}, {'name': ['NetFlix Inc'], 'symbol': ['NFLX'], 'shares': [13], 'price': [343.75], 'total': [4468.75]}]

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]['cash']
    end_total = sum(total) + float(cash)

    return render_template("index.html", portfolio=portfolio, cash=usd(cash), end_total=usd(end_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol')
        # error checking for stock

        if not symbol:
            return apology("missing symbol", 400)

        else:
            symbol = lookup(symbol)

        if symbol == None:
            return apology("invalid symbol", 400)

        # error checking for shares
        try:
            shares = int(request.form.get('shares'))
        except:
            return apology("shares must be an integer", 400)

        if not shares:
            return apology("missing number of shares", 400)

        elif shares <= 0:
            return apology("invalid number of shares", 400)

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cost = symbol['price'] * shares
        new_balance = balance[0]['cash'] - float(cost)

        if new_balance < 0:
            return apology("insufficient cash", 400)

        share_no = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], symbol['symbol'])
        if len(share_no) == 0:
            db.execute("INSERT INTO portfolio(symbol, name, price, shares, user_id) VALUES(?, ?, ?, ?, ?)",
                       symbol['symbol'], symbol['name'], symbol['price'], shares, session["user_id"])

        else:
            shares_new = share_no[0]['shares'] + shares
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?",
                       shares_new, session['user_id'], symbol['symbol'])

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])
        db.execute("INSERT INTO history(symbol, shares, price, user_id) VALUES(?, ?, ?, ?)",
                   symbol['symbol'], shares, usd(symbol['price']), session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT symbol, shares, price, time FROM history WHERE user_id = ?', session['user_id'])
    return render_template('history.html', history=history)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
        if (isinstance(request.form.get("symbol"), str) == True):
            stock = lookup(request.form.get("symbol"))

        elif not request.form.get("symbol"):
            return apology("missing symbol", 400)

        else:
            return apology("invalid symbol", 400)

        if stock == None:
            return apology("stock symbol not found", 400)

        else:
            return render_template("quoted.html", name=stock['name'], symbol=stock['symbol'], price=usd(stock['price']))

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("invalid username", 400)

        elif not request.form.get("password"):
            return apology("invalid password", 400)

        elif (request.form.get("password") != request.form.get("confirmation")):
            return apology("password does not match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if (len(rows) != 0):
            return apology("username has already been taken", 400)

        else:
            username = request.form.get("username")
            password = request.form.get("password")

            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, generate_password_hash(password))
            return redirect('/')

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        shares = request.form.get('shares')
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('invalid symbol', 400)

        symbols = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?",
                              session["user_id"], request.form.get('symbol'))

        if int(shares) > symbols[0]['shares']:
            return apology('not enough shares', 400)

        elif int(shares) <= 0:
            return apology('invalid number of shares', 400)

        else:
            new_shares = symbols[0]['shares'] - int(shares)
            db.execute('UPDATE portfolio SET shares = ? WHERE symbol = ? ', new_shares, symbol)
            balance = db.execute('SELECT cash FROM users WHERE id = ?', session["user_id"])[0]['cash']
            new_balance = (lookup(symbol)['price'] * int(shares)) + balance
            db.execute('UPDATE users SET cash = ? WHERE id = ?', new_balance, session["user_id"])
            db.execute("INSERT INTO history(symbol, shares, price, user_id) VALUES(?, ?, ?, ?)",
                       lookup(symbol)['symbol'], -int(shares), usd(lookup(symbol)['price']), session["user_id"])

        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE user_id = ? GROUP BY name ORDER BY symbol ASC", session["user_id"])
        return render_template("sell.html", symbols=symbols)
