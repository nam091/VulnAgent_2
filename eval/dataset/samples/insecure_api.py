"""Evaluation sample: deserialization, SSRF, weak crypto, weak randomness."""

import hashlib
import pickle
import random
import xml.etree.ElementTree as ET

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route('/session/restore', methods=['POST'])
def restore_session():
    blob = request.get_data()
    state = pickle.loads(blob)
    return {'restored': list(state.keys())}


@app.route('/fetch')
def fetch_url():
    target = request.args.get('url')
    response = requests.get(target, timeout=5)
    return response.text


@app.route('/register', methods=['POST'])
def register():
    password = request.form.get('password', '')
    digest = hashlib.md5(password.encode()).hexdigest()
    return {'hash': digest}


@app.route('/token')
def issue_token():
    token = ''.join(random.choice('abcdef0123456789') for _ in range(32))
    return {'token': token}


@app.route('/import', methods=['POST'])
def import_document():
    payload = request.get_data()
    root = ET.fromstring(payload)
    return {'tag': root.tag}
