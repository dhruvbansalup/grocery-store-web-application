from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

app=Flask(__name__)

app.config.from_object(Config) # Load the Config object from config.py

db=SQLAlchemy(app)

from models import *

from routes import *

if __name__=='__main__':
    app.run(debug=True)
