from flask import Flask, render_template
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
app = Flask(__name__)

@app.route('/home')
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/login')
def login():
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)