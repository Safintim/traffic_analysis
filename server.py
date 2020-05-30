import os
import datetime

from flask import Flask, render_template
from sqlalchemy import desc
from flask_sqlalchemy import SQLAlchemy

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlitedb.db'
db = SQLAlchemy(app)


class Statistic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mean = db.Column(db.Float)
    dispersion = db.Column(db.Float)
    standard_deviation = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    path = db.Column(db.String(100))
    statistic_id = db.Column(db.Integer, db.ForeignKey('statistic.id'), nullable=False)
    statistic = db.relationship('Statistic', backref=db.backref('files', lazy=True))


@app.route('/')
def hello_world():
    statistics = Statistic.query.order_by(desc(Statistic.id)).all()
    return render_template('index.html', statistics=statistics)
