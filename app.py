# pip install Flask
# flask run -h localhost -p 5001
import os
import unidecode

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///plaintext.db")


ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/! \"#$%&\'()*,.:;<=>?@[\\]^`{|}~"


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
    """Show search and insert fields"""
    # To get id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    # To know if there are notes or not
    rows = db.execute("SELECT notes FROM id?notes", thisid)
    if len(rows) == 0:
        message = "You have no notes yet"
        img = "cadernonada"
    else:
        message = "You already have notes :)"
        img = "cadernocomcoisa"

    return render_template("index.html", username=username, message=message, img=img)


@app.route("/insert", methods=["GET", "POST"])
@login_required
def insert():
    """Show search and insert fields"""
    # To get id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    if request.method == "POST":

        # Ensure that have anything typed in Place / Keyword
        if not request.form.get("keyword"):
            return apology("You must type anything in Place / keyword", 403)

        # Ensure that have anything typed in Notes
        elif not request.form.get("notes"):
            return apology("You didn't write anything down", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        # Query database for id
        rows = db.execute("SELECT * FROM users WHERE id = ?", thisid)

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid password", 403)

        # To update a the plain notes with ciphered data
        password = request.form.get("password")
        keyword = request.form.get("keyword")
        notes = request.form.get("notes")

        x = ""
        for i in password:
            if i in ALPHABET[56:]:
                x = x + ALPHABET[ALPHABET.index(i) - 50]
            else:
                x = x + ALPHABET[ALPHABET.index(i)]
        x = bytes(x, 'utf-8')

        userkey = list_dict_nakey[0]['userkey']

        f = Fernet(x + userkey)

        db.execute("INSERT INTO id?notes (place_keyword, notes) VALUES (?, ?)", thisid,
                   f.encrypt(keyword.encode()), f.encrypt(notes.encode()))

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("insert.html", username=username)


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Show search and insert fields"""
    # To get id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("Must provide password", 403)

        # Query database for id
        rows = db.execute("SELECT * FROM users WHERE id = ?", thisid)

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid password", 403)

        # To get a password to use with userkey
        password = request.form.get("password")
        x = ""
        for i in password:
            if i in ALPHABET[56:]:
                x = x + ALPHABET[ALPHABET.index(i) - 50]
            else:
                x = x + ALPHABET[ALPHABET.index(i)]
        x = bytes(x, 'utf-8')

        userkey = list_dict_nakey[0]['userkey']

        f = Fernet(x + userkey)

        # To get a list with all notes
        list_dict_notes = db.execute("SELECT place_keyword, notes FROM id?notes", thisid)

        # To get a list with all values
        list_values = []
        for i in list_dict_notes:
            for k, v in i.items():
                list_values.append(f.decrypt(v).decode())

        # To get a list with only places/keywords values, but normalized (without accents - unidecode) and lowercased
        keywords = []
        for i in range(0, len(list_values), 2):
            j = unidecode.unidecode(list_values[i])
            keywords.append(j.lower())

        # To populate the temp column with all data from keywords list
        count_id = 0
        for i in keywords:
            count_id += 1
            db.execute("UPDATE id?notes SET temp = ? WHERE id = ?", thisid, i, count_id)

        # If there is a word for search
        if request.form.get("search"):
            # To get a word that was searched
            search = "%" + unidecode.unidecode(request.form.get("search")) + "%"

            # To set the default list to work with
            list_dict_notes = db.execute(
                "SELECT id, place_keyword, notes FROM id?notes WHERE temp LIKE ? ORDER BY temp", thisid, search)

            # To clean the temp column for security
            db.execute("UPDATE id?notes SET temp = ? WHERE id >= 1", thisid, "")

        # If search is blank, show everything - "else" implicit
        else:
            # To set the default list to work with, but with all data and ordered alphabetically
            list_dict_notes = db.execute("SELECT id, place_keyword, notes FROM id?notes ORDER BY temp", thisid)

            # To clean the temp column for security
            db.execute("UPDATE id?notes SET temp = ? WHERE id >= 1", thisid, "")

        # To get a list with all values, now ordered alphabetically
        list_values = []
        for i in list_dict_notes:
            for k, v in i.items():
                if k == "place_keyword" or k == "notes":
                    list_values.append(f.decrypt(v).decode())
                else:
                    list_values.append(v)

        return render_template("shown.html", username=username, lv=list_values)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("search.html", username=username)


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
            return apology("invalid username or password", 403)

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # A list with all usernames
    USERS = []
    dictusers = db.execute("SELECT username FROM users")
    for i in dictusers:
        for username, v in i.items():
            USERS.append(v)

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        newuser = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not newuser or not password or not confirmation:
            return apology("Didn't you forget something?")
        elif password != confirmation:
            return apology("Password and confirmation aren't the same...")
        elif newuser in USERS:
            return apology("This username already exists")
        else:
            base_key = Fernet.generate_key()

            x = ""
            for i in password:
                if i in ALPHABET[56:]:
                    x = x + ALPHABET[ALPHABET.index(i) - 50]
                else:
                    x = x + ALPHABET[ALPHABET.index(i)]
            x = bytes(x, 'utf-8')

            userkey = base_key[len(x):]

            db.execute("INSERT INTO users (username, hash, userkey) VALUES (?, ?, ?)", newuser,
                       generate_password_hash(request.form.get("password")), userkey)

            # Remember which user has logged in
            rows = db.execute("SELECT * FROM users WHERE username = ?", newuser)
            session["user_id"] = rows[0]["id"]

            db.execute(
                "CREATE TABLE id?notes (id INTEGER PRIMARY KEY NOT NULL, place_keyword TEXT NOT NULL, notes TEXT NOT NULL, temp TEXT)", rows[0]["id"])

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html", users=USERS)


@app.route("/modify", methods=["GET", "POST"])
def modify():
    # Modify a line (place / keywords, notes)
    if request.method == "POST":
        # To get id
        for k, v in session.items():
            thisid = v

        # To get current username and userkey
        list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
        username = list_dict_nakey[0]['username']

        # To get all data which to be modified
        idmodify = request.form.get("idmodify")
        kmodify = request.form.get("kmodify")
        vmodify = request.form.get("vmodify")

        return render_template("modify.html", username=username, id=idmodify, k=kmodify, v=vmodify)

    else:
        return redirect("/")


@app.route("/modified", methods=["POST"])
def modified():
    # Modify a line (place / keywords, notes)
    # To get id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    # To get all data which to be modified
    idinput = request.form.get("idinput")
    kinput = request.form.get("kinput")
    vinput = request.form.get("vinput")

    # Must provide a password
    if not request.form.get("password"):
        return apology("Must provide password", 403)

    # Query database for id
    rows = db.execute("SELECT * FROM users WHERE id = ?", thisid)

    # Ensure password is correct
    if not check_password_hash(rows[0]["hash"], request.form.get("password")):
        return apology("Invalid password", 403)

    # Ensure that there is at least place or keyword
    if not request.form.get("kinput"):
        return apology("Must provide a place or a keyword", 403)

    else:
        # To get a password to use with userkey
        password = request.form.get("password")
        x = ""
        for i in password:
            if i in ALPHABET[56:]:
                x = x + ALPHABET[ALPHABET.index(i) - 50]
            else:
                x = x + ALPHABET[ALPHABET.index(i)]
        x = bytes(x, 'utf-8')

        userkey = list_dict_nakey[0]['userkey']

        f = Fernet(x + userkey)
        db.execute("UPDATE id?notes SET place_keyword = ?, notes = ? WHERE id = ?", thisid,
                   f.encrypt(kinput.encode()), f.encrypt(vinput.encode()), idinput)

    return redirect("/")


@app.route("/delete", methods=["POST"])
def delete():

    # To Certificate that user is shure to delete a row
    if request.method == "POST":
        # To get id
        for k, v in session.items():
            thisid = v

        # To get current username and userkey
        list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
        username = list_dict_nakey[0]['username']

        # To get all data which to be modified
        iddelete = request.form.get("iddelete")
        kdelete = request.form.get("kdelete")
        vdelete = request.form.get("vdelete")

        return render_template("delete.html", username=username, id=iddelete, k=kdelete, v=vdelete)

    else:
        return redirect("/")


@app.route("/deleted", methods=["POST"])
def deleted():
    # To  delete a row

    # To get id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    # Must provide a password
    if not request.form.get("password"):
        return apology("Must provide password", 403)

    # Query database for id
    rows = db.execute("SELECT * FROM users WHERE id = ?", thisid)

    # Ensure password is correct
    if not check_password_hash(rows[0]["hash"], request.form.get("password")):
        return apology("Invalid password", 403)

    # Ensure that user is really shure
    if not request.form.get("shure"):
        return apology("Must select this", 403)

    # To get the id from row that will be deleted
    iddelete = request.form.get("iddelete")
    if iddelete:
        db.execute("DELETE FROM id?notes WHERE id = ?", thisid, iddelete)
        db.execute("UPDATE id?notes SET id = (id - 1) WHERE id > ?", thisid, iddelete)

    return redirect("/")


@app.route("/change", methods=["GET", "POST"])
def change():
    """Change Password"""
    # To get current user's id
    for k, v in session.items():
        thisid = v

    # To get current username and userkey
    list_dict_nakey = db.execute("SELECT username, userkey FROM users WHERE id = ?", thisid)
    username = list_dict_nakey[0]['username']

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("newpassword"):
            return apology("must provide a new password", 403)

        elif not request.form.get("confirmation"):
            return apology("must provide a confirmation", 403)

        elif request.form.get("newpassword") != request.form.get("confirmation"):
            return apology("New password and Confirmation are different", 403)

        # Query database for id
        rows = db.execute("SELECT * FROM users WHERE id = ?", thisid)

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid password", 403)

        # We must decrypt all data that were encrypted with old key and, then, encrypt them with new key

        # To get a password to use with userkey
        password = request.form.get("password")
        x = ""
        for i in password:
            if i in ALPHABET[56:]:
                x = x + ALPHABET[ALPHABET.index(i) - 50]
            else:
                x = x + ALPHABET[ALPHABET.index(i)]
        x = bytes(x, 'utf-8')

        userkey = list_dict_nakey[0]['userkey']

        f = Fernet(x + userkey)

        # To get a list with all notes
        list_dict_notes = db.execute("SELECT place_keyword, notes FROM id?notes", thisid)

        # To get a list with all opened values
        list_values = []
        for i in list_dict_notes:
            for k, v in i.items():
                list_values.append(f.decrypt(v).decode())

        # To also update the userkey
        base_key = Fernet.generate_key()

        newpassword = request.form.get("newpassword")

        x = ""
        for i in newpassword:
            if i in ALPHABET[56:]:
                x = x + ALPHABET[ALPHABET.index(i) - 50]
            else:
                x = x + ALPHABET[ALPHABET.index(i)]
        x = bytes(x, 'utf-8')

        userkey = base_key[len(x):]

        f = Fernet(x + userkey)

        # Here we update the users table
        db.execute("UPDATE users SET hash = ?, userkey = ? WHERE id = ?",
                   generate_password_hash(request.form.get("newpassword")), userkey, thisid)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # Here we update the encrypted data with new key
        for i in range(0, len(list_values), 2):
            db.execute("UPDATE id?notes SET place_keyword = ?, notes = ? WHERE id = id",
                   thisid, f.encrypt(list_values[i].encode()), f.encrypt(list_values[i + 1].encode()))

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change.html", username=username)
