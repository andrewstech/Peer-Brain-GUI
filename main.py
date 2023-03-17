from flask import Flask, render_template, request, url_for, flash, redirect, Response
from pygtail import Pygtail
from flaskwebgui import FlaskUI # import FlaskUI
from werkzeug.exceptions import abort
import sqlite3
import logging
import datetime
import getpass
import os
import json
import requests
import base64
from typing import List, Union
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from encrypt_data import generate_keypair, load_private_key, detect_private_key, \
    save_private_key, encrypt_message_symmetrical, decrypt_message, generate_sym_key, load_sym_key, \
        detect_sym_key, detect_public_key, save_public_key, load_public_key
import os
import sys
import time
import pyfiglet
from client_functions import check_token, get_all_users, login, log_out, log_in_to_server, get_account_info, reset_password, register_user, upload_keystore, get_user_friends

app = Flask(__name__)

server_url = "https://peerbrain.teckhawk.be/"



LOG_FILE = 'app.log'
log = logging.getLogger('__name__')
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'),404

@app.errorhandler(405)
def not_found_error(error):
    return render_template('405.html'),405

@app.route('/')
def index():
    if check_token(server_url):
        username, email = get_account_info(server_url)
        return redirect("/user/", code=302)
    else:
        return render_template('index.html')
    
@app.route('/account/')
def account():
    if check_token(server_url):
        username, email = get_account_info(server_url)
        return render_template('account.html', user_account=username, user_account_email=email)
    else:
        return redirect("/", code=302)  

@app.route('/friends/')
def friends():
    users = get_all_users(server_url)
    usernames = [username for username in users.keys()]
    return render_template('friend.html', friends=usernames)

@app.route('/profile/<friend>')
def show_profile(friend):
    return render_template('profile.html', Friend=friend)

@app.route('/resetpassword/')
def resetpassword():
    return render_template('reset.html')

@app.route('/password-reset/')
def password():
    return render_template('sent-reset.html')

@app.route('/user/')
def user():
    if check_token(server_url):
        username, email = get_account_info(server_url)
        return render_template('user.html', user_account=username, user_account_email=email)
    else:
        return redirect("/", code=302)

@app.route('/technical-menu/')
def technical():
    if check_token(server_url):
        username, email = get_account_info(server_url)
        return render_template('technical.html', Warning="Warning: This is a technical menu, only use if you know what you are doing!")
    else:
        return redirect("/", code=302)
    
app.route('/genkey/')
def genkey():
    if check_token(server_url):
        username, email = get_account_info(server_url)
        if detect_private_key() and detect_sym_key() and detect_public_key():
                            print()
                            print("Keys already exist, overwriting them will make your account irretrievable!!")
                            print()
                            print("Key creation canceled!")
                            render_template('technical.html', Warning="Keys already exist")
                            
        else:    
            public_key, private_key = generate_keypair()
            save_private_key(private_key)
            save_public_key(public_key)
            symmetric_key = generate_sym_key()
            upload_result = upload_keystore(server_url, public_key, symmetric_key)
            print("------------------------")
            print(upload_result)
            print("------------------------")
        return render_template('technical.html', Warning="New keys generated!")
    else:
        return redirect("/", code=302)    

@app.route('/register/')
def register():
    return render_template('register.html')


@app.route('/registeruser/', methods=['POST'])
def reguser():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        register_user(server_url, username, email, password)
        return render_template('loading-loginreg.html')
        

@app.route('/login/', methods=['POST'])
def create():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        log_in_to_server(username, password, server_url)
        return render_template('loading-loginreg.html')
        


@app.route('/reset/', methods=['POST'])
def reset():
    if request.method == 'POST':
        username = request.form['username']
        reset_password(server_url, username)
        return redirect("/password-reset/", code=302)

@app.route('/logout/')
def logout():
    log_out()
    return redirect("/", code=302)


@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    return render_template('500.html'), 500
 

if __name__ == "__main__":
  # If you are debugging you can do that in the browser:
  # app.run()
  # If you want to view the flaskwebgui window:
  FlaskUI(app=app, server="flask", width=800, height=600).run()