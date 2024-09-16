import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///codesentry.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['GITHUB_APP_CLIENT_ID'] = 'Ov23lillPKobH57kEAu5'
app.config['GITHUB_APP_CLIENT_SECRET'] = 'cc8186d6f2f87a1693b69c502f9333948775e96d'
app.config['GITHUB_OAUTH_REDIRECT_URI'] = 'http://43.204.130.30:7174/github_auth'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'))
    github_access_token = db.Column(db.String(255))  # Store GitHub access token

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', backref='organization', lazy=True)
    repositories = db.relationship('Repository', backref='organization', lazy=True)

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    pull_requests = db.relationship('PullRequest', backref='repository', lazy=True)

class PullRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False)
    repository_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=False)
    ai_comments = db.relationship('AIComment', backref='pull_request', lazy=True)

class AIComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    pull_request_id = db.Column(db.Integer, db.ForeignKey('pull_request.id'), nullable=False)

def create_pull_request_webhook(repo_owner, repo_name, access_token):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/hooks"
    headers = {
        "Authorization": f"token {access_token}",
        "Content-Type": "application/json"
    }
    
    webhook_data = {
        "name": "web",
        "active": True,
        "events": ["pull_request"],
        "config": {
            "url": "https://your-saas-tool.com/github-webhook",
            "content_type": "json",
            "secret": "your_webhook_secret"
        }
    }
    
    response = requests.post(url, json=webhook_data, headers=headers)
    if response.status_code == 201:
        print("Pull request webhook created successfully.")
    else:
        print(f"Failed to create webhook: {response.json()}")

@app.route('/github/login', methods=['GET'])
@jwt_required()
def github_login():
    github_authorize_url = "https://github.com/login/oauth/authorize"
    client_id = app.config['GITHUB_APP_CLIENT_ID']
    redirect_uri = app.config['GITHUB_OAUTH_REDIRECT_URI']
    
    github_login_url = f"{github_authorize_url}?client_id={client_id}&redirect_uri={redirect_uri}&scope=repo"
    
    return jsonify({"url": github_login_url}), 200  

@app.route('/github_auth', methods=['GET'])
def github_auth():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "No code provided"}), 400

    token_url = "https://github.com/login/oauth/access_token"
    client_id = app.config['GITHUB_APP_CLIENT_ID']
    client_secret = app.config['GITHUB_APP_CLIENT_SECRET']
    redirect_uri = app.config['GITHUB_OAUTH_REDIRECT_URI']
    
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri
    }
    
    headers = {'Accept': 'application/json'}
    
    token_response = requests.post(token_url, json=payload, headers=headers)
    token_json = token_response.json()
    
    if 'access_token' in token_json:
        access_token = token_json['access_token']
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        user.github_access_token = access_token
        db.session.commit()
        return jsonify({"msg": "Access token saved successfully"}), 200
    else:
        return jsonify({"error": "Failed to get access token"}), 400

@app.route('/repositories', methods=['POST'])
@jwt_required()
def add_repository():
    data = request.json
    repo = Repository(name=data['name'], url=data['url'], organization_id=data['organization_id'])
    db.session.add(repo)
    db.session.commit()
    
    user = User.query.get(get_jwt_identity())
    access_token = user.github_access_token  # Retrieve stored access token
    create_pull_request_webhook(user.username, data['name'], access_token)

    return jsonify({"msg": "Repository added and webhook created successfully", "id": repo.id}), 201

@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    signature = request.headers.get('X-Hub-Signature')
    
    if not verify_signature(request.data, signature):
        return "Signature verification failed", 403
    
    event = request.headers.get('X-GitHub-Event')
    payload = request.json
    
    if event == 'pull_request':
        action = payload['action']
        pr_number = payload['number']
        pr_title = payload['pull_request']['title']
        pr_user = payload['pull_request']['user']['login']
        
        if action == 'opened':
            print(f"New pull request #{pr_number} by {pr_user}: {pr_title}")
        elif action == 'closed':
            merged = payload['pull_request']['merged']
            if merged:
                print(f"Pull request #{pr_number} has been merged.")
            else:
                print(f"Pull request #{pr_number} has been closed without merging.")
    
    return jsonify({"status": "Webhook received"}), 200

def verify_signature(payload, signature):
    mac = hmac.new(app.config['JWT_SECRET_KEY'].encode(), msg=payload, digestmod=hashlib.sha1)
    return hmac.compare_digest('sha1=' + mac.hexdigest(), signature)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
