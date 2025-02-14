from flask import Flask, render_template

from config import Config

app=Flask(__name__)

app.config.from_object(Config) # Load the Config object from config.py

import models

import routes



if __name__=='__main__':
    app.run(debug=True)
