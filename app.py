import hmac
import hashlib
import requests
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from flask_migrate import Migrate
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
app.config['WEBHOOK_SECRET'] = 'agshekcm'


import logging
from logging.handlers import RotatingFileHandler

# Set up logging

handler = RotatingFileHandler('github_webhook.log', maxBytes=100000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)



db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

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
            "url": "http://43.204.130.30:7174/github-webhook",
            "content_type": "json",
            "secret": app.config['WEBHOOK_SECRET']
        }
    }
    
    response = requests.post(url, json=webhook_data, headers=headers)
    if response.status_code == 201:
        print("Pull request webhook created successfully.")
    else:
        print(f"Failed to create webhook: {response.json()}")

import uuid

@app.route('/github/login', methods=['GET'])
@jwt_required()
def github_login():
    user_id = get_jwt_identity()
    # state = str(uuid.uuid4())  # Generate a unique state value
    # Save the state and user_id mapping in a temporary store or database
    state=user_id
    
    github_authorize_url = "https://github.com/login/oauth/authorize"
    client_id = app.config['GITHUB_APP_CLIENT_ID']
    redirect_uri = app.config['GITHUB_OAUTH_REDIRECT_URI']
    
    github_login_url = f"{github_authorize_url}?client_id={client_id}&redirect_uri={redirect_uri}&scope=repo&state={state}"
    return jsonify({"url": github_login_url}), 200  



def get_user_id_by_state(state):
    return state

@app.route('/github_auth', methods=['GET'])
def github_auth():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or not state:
        return jsonify({"error": "Missing code or state"}), 400

    # Retrieve the user_id associated with the state from your temporary store or database
    user_id = get_user_id_by_state(state)  # Implement this function based on how you store state

    if not user_id:
        return jsonify({"error": "Invalid state"}), 400

    # Exchange code for access token
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
        user = User.query.get(user_id)
        if user:
            user.github_access_token = access_token
            db.session.commit()
            return jsonify({"msg": "Access token saved successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404
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


def handle_new_pull_request(pr_data):
    try:
        # Extract data from GitHub webhook payload
        pr_id = pr_data.get('id')
        title = pr_data.get('title')
        body = pr_data.get('body')
        repo_name = pr_data['head']['repo']['full_name']
        pr_url = pr_data.get('html_url')
        pr_status = pr_data.get('state')

        # Check if the pull request already exists in the DB
        existing_pr = PullRequest.query.filter_by(id=pr_id).first()

        if existing_pr is None:
            # Save the new pull request to the database
            new_pr = PullRequest(
                id=pr_id,
                title=title,
                description=body,
                repository_name=repo_name,
                status=pr_status,
                github_url=pr_url
            )
            db.session.add(new_pr)
            db.session.commit()

            # Perform AI review on the pull request
            # ai_review_result = perform_ai_review(pr_data)
            
            # Post AI comments to GitHub
            # post_github_comment(pr_data, ai_review_result)

        return jsonify({'message': 'Pull request handled successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    # Log the incoming request
    app.logger.info(f"Received webhook request: {request.data.decode('utf-8')}")
    
    # Verify webhook signature to ensure it's from GitHub
    signature = request.headers.get('X-Hub-Signature-256')
    if not is_github_signature_valid(request.data, signature):
        app.logger.warning('Invalid signature detected.')
        return jsonify({'error': 'Invalid signature'}), 400

    # Handle the GitHub PR event
    event = request.headers.get('X-GitHub-Event')
    if event == 'pull_request':
        payload = request.json
        action = payload.get('action')
        
        # Only handle "opened" PRs for now
        if action == 'opened':
            pr_data = payload.get('pull_request', {})
            try:
                response = handle_new_pull_request(pr_data)
                # Log the response from handling the PR
                app.logger.info(f"Handled pull request. Response: {response.get_json()}")
                return response
            except Exception as e:
                app.logger.error(f"Error handling pull request: {str(e)}")
                return jsonify({'error': 'Internal server error'}), 500
    
    return jsonify({'message': 'Event not handled'}), 200


def is_github_signature_valid(payload, signature):
    if signature is None:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
    mac = hmac.new(app.config['WEBHOOK_SECRET'].encode(), payload, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

@app.route('/repositories', methods=['GET'])
@jwt_required()
def get_repositories():
    try:
        repositories = Repository.query.all()
        repo_list = [{"id": repo.id, "name": repo.name, "url": repo.url, "organization_id": repo.organization_id} for repo in repositories]
        return jsonify({"repositories": repo_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pullrequests', methods=['GET'])
def get_pull_requests():
    try:
        # Retrieve all pull requests from the database
        pull_requests = PullRequest.query.all()
        pr_list = [{
            'id': pr.id,
            'title': pr.title,
            'repository_name': pr.repository.name,
            'status': pr.status
        } for pr in pull_requests]

        return jsonify(pr_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def verify_signature(payload, signature):
    mac = hmac.new(app.config['WEBHOOK_SECRET'].encode(), msg=payload, digestmod=hashlib.sha1)
    return hmac.compare_digest('sha1=' + mac.hexdigest(), signature)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
