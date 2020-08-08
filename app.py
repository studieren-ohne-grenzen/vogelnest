from flask import Flask, request
from api import API
import config

app = Flask(__name__)
api = API(config)

@app.route('/guests', methods=['POST'])
def guests():
    return 'Hello, World!'

@app.route('/users', methods=['GET', 'POST'])
def users():
    return 'Hello, World!'

@app.route('/users/<uid>', methods=['GET', 'DELETE'])
def user(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/set_password', methods=['POST'])
def user_set_password(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/reset_password', methods=['POST'])
def user_reset_password(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/activate', methods=['POST'])
def user_activate(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/groups', methods=['GET'])
def user_groups(uid):
    return 'Hello, World!'

@app.route('/users/<uid>/owned_groups', methods=['GET'])
def user_owned_groups(uid):
    return 'Hello, World!'

@app.route('/groups', methods=['GET', 'POST'])
def groups():
    return 'Hello, World!'

@app.route('/groups/<group>', methods=['GET'])
def group(group):
    return 'Hello, World!'

@app.route('/groups/<group>/members', methods=['GET', 'POST'])
def group_members(group):
    return 'Hello, World!'

@app.route('/groups/<group>/members/<uid>', methods=['DELETE'])
def group_member(group, uid):
    return 'Hello, World!'

@app.route('/groups/<group>/pending_members', methods=['GET','POST'])
def group_pending_members(group):
    return 'Hello, World!'

@app.route('/groups/<group>/pending_members/<uid>', methods=['DELETE'])
def group_pending_member(group, uid):
    return 'Hello, World!'

@app.route('/groups/<group>/owners', methods=['GET', 'POST'])
def group_owners(group):
    return 'Hello, World!'

@app.route('/groups/<group>/owners/<uid>', methods=['DELETE'])
def group_owner(group, uid):
    return 'Hello, World!'
