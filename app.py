import hmac
import hashlib
import requests
from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from flask_cors import CORS
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from dotenv import load_dotenv
import os
import json
import openai
import datetime
import humanize
from sqlalchemy import func


load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600')))
app.config['GITHUB_APP_CLIENT_ID'] = os.getenv('GITHUB_APP_CLIENT_ID')
app.config['GITHUB_APP_CLIENT_SECRET'] = os.getenv('GITHUB_APP_CLIENT_SECRET')
app.config['GITHUB_OAUTH_REDIRECT_URI'] = os.getenv('GITHUB_OAUTH_REDIRECT_URI')
app.config['WEBHOOK_SECRET'] = os.getenv('WEBHOOK_SECRET')
app.config['GITHUB_API_BASE'] = os.getenv('GITHUB_API_BASE')
app.config['FRONTEND_URL'] = os.getenv('FRONTEND_URL')


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
    is_email_verified = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    git_org_id = db.Column(db.String(80), nullable=True) #org id from github
    name = db.Column(db.String(80), nullable=True)
    users = db.relationship('User', backref='organization', lazy=True)
    repositories = db.relationship('Repository', backref='organization', lazy=True)
    installation_id = db.Column(db.String(80), nullable=True)
    type = db.Column(db.String(80), nullable=True)

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    repo_id = db.Column(db.Integer, nullable=True) 
    name = db.Column(db.String(80), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    pull_requests = db.relationship('PullRequest', backref='repository', lazy=True)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    installation_id = db.Column(db.String(80), nullable=True)

class PullRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pr_id = db.Column(db.Integer, nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False)
    repository_id = db.Column(db.Integer, db.ForeignKey('repository.id'), nullable=False)
    ai_comments = db.relationship('AIComment', backref='pull_request', lazy=True)
    url = db.Column(db.String(200), nullable=True)
    pull_request_diff = db.Column(db.Text, nullable=True)
    llm_response = db.Column(db.Text, nullable=True)
    llm_response_time = db.Column(db.DateTime, nullable=True)

class AIComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=True)
    content = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    pull_request_id = db.Column(db.Integer, db.ForeignKey('pull_request.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    severity = db.Column(db.String(20), nullable=True)
    category = db.Column(db.String(20), nullable=True)


import uuid

@app.route('/github/app_install_url', methods=['GET'])
@jwt_required()
def github_app_install_url():
    user_id = get_jwt_identity()
    # state = str(uuid.uuid4())  # Generate a unique state value
    # Save the state and user_id mapping in a temporary store or database
    state=user_id
    
    github_app_install_url = "https://github.com/apps/agnicodeaitest/installations/new"

    github_login_url = f"{github_app_install_url}?&state={state}"
    return jsonify({"url": github_login_url}), 200  

def get_jwt_from_private_key():
    private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAw90xbMYEjdlDRurEVN8BwbRSWN21Llh5YF3JRlVRs1Bc8F7u
7Rwh9ytBld0W0h2XUYtVE8Y8ma3mYxAi7Q2BKwdWzuBngVTAsb9MsanAZdslPXE9
muo3ueCG1u0Dkjx8gLMp854d+74EhhVKpTzadtPTfyCATbkysCKrEoUDcVRNZmKk
JUShjKHRG5DSOn3sAE+TERf4nqG7YhmmE5HsoS4AJ24bPc9I3kf9SzLkas4TvFk6
LrexeLkypZvi8rU/BhEcQI9/gN6MW/ycB3yF1x0RSkTOPrjziTUN8l09ipCgSWfS
FhNY85OdPj2puMc0mTXyI9+O4BX9spQuDID9AwIDAQABAoIBAQCjyMzyy6e1QnAa
1mi1HALpCzQtMcC3b66X4fVUxjXav6HoM0qSporUmKxweIAD1lDaFKxhK80zKZNV
VYIPPtK7u5hgyJBlOw0j1fd5PZ0wz4+VkKNWbvOIkPPQuEPbPo9SRAAZwygJgn1f
7mAMSxXYdgwO64u+8tYrKeJqSyZ01fZ/oRrIwbM5/tpGgTfG28Ph/an8Efr8Fbb/
Akm5Pe84pc4RucAdp9WJ8On3c5RLDSTuAZFGIZnWotjHYc0L4edAzepP/AlzPQaA
apWIVDVYpbzW8pcDQ6wsKssK7WfwIMyMtCk63bSuKZan1/3NvNjrL1G8CCV6st59
4UeIvIrRAoGBAOXCwRm18gTrOOYYXm1K//d8CFliGAyvSLQgSrqHtgg5mQwHVVRh
B13Vjv9ykRKQffF9Bc9QbSX3FhI8RD042r2J1KXsOCnvNTvnzL+1eYFxy7iQF8cm
ODpbVW6RvGY6su6hbFfwJcGmt/8xzQkVedMbJcvMz56ZrJu3X6hFwEa7AoGBANo7
cKY0zHZRb+x1e2VLex7ycp8hhor7d2olBcWAP2z1FFJtOGzqQzEzzvE9zNHt42e8
kKzexd3m5eCRbbZlA5f+LSKdsBrsq257wjnajyEEccW223Z1qxI0hChxgOZFhmc/
7lUdOJvy4haDnrFOaHnQzLTMYvkKAXgjaEFJOdJZAoGBAJ7bCKe+JJdCCxULxD3M
nS1/lEY4jGg4yQvBR+mv6yvEpwyqBVVRwMYf4b68d5FeVbWhu2KbONwG+juhb4zk
wlhJ87zElhBoU2YX3niuAFR/WVtCRS5sPnQasfbAzIHiE9Tpxv8GCxTZMF5BEII3
VwOewYMnGGWP2sfPAVRW5ZoBAoGATcNqg79CsFKamF7Qpqq7564rC+tNXw72YVtp
8BOgBjpakHic56qeYNT+Q9Zqus+S/e8ieoczaLwTY+9OcfUSz8Fh4fjgvOdiuw7c
ifMIl5JW3EYpc8/AMs+F3Ed90BAsMXSFf8zW1DM7PxyNms6+ydGOcEp4ZhebqGyt
hL4MHZkCgYEAqXxJuSFtbvjXDOK1suSX7s/fyRSHMREtP56LA3tq+BULiBPz9YK9
YgH+s3lNk0Z7pdHJcjtjnUJqjr2gq28VDkiFOF5pW+55N+R8bv7ZUu+2+PU6Qb+a
9wuYvYEJfnomCDY2G/gVyjR+42dTlHr6hSPVrpgTHGyTFltL/+iU3DE=
-----END RSA PRIVATE KEY-----
"""
    app_id = "999410"

    import time
    # Create JWT payload
    payload = {
        "iat": int(time.time()),  # Issued at time
        "exp": int(time.time()) + (10 * 60),  # Expiration time (10 minutes)
        "iss": app_id  # GitHub App's ID
    }

    # Encode JWT
    import jwt as jwt2
    jwt_token = jwt2.encode(payload, private_key, algorithm="RS256")
    return jwt_token

def get_installation_token_from_jwt_token(installation_id):
    # installation_id = 54973076
    jwt_token = get_jwt_from_private_key()
    headers = {'Accept': 'application/vnd.github+json', "Authorization": f"Bearer {jwt_token}"}
    token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    payload = {}
    token_response = requests.post(token_url, json=payload, headers=headers)
    token_json = token_response.json()
    return token_json['token']

def github_request(method, url, installation_id, data=None, ):
    """Make a request to the GitHub API."""
    headers = {
        "Authorization": f"token {get_installation_token_from_jwt_token(installation_id)}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.request(method, url, headers=headers, json=data)
    response.raise_for_status()
    return response.json()

def fetch_pr_details(repo_owner, repo_name, pr_number, installation_id):
    """Fetch pull request details from GitHub."""
    url = f"{app.config['GITHUB_API_BASE']}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}"
    return github_request("GET", url, installation_id)

def get_pr_files(repo_owner, repo_name, pr_number, installation_id):
    """Get the files changed in the pull request."""
    url = f"{app.config['GITHUB_API_BASE']}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files"
    return github_request("GET", url, installation_id)

def analyze_code_changes(file_patch):
    """Analyze code changes using OpenAI's GPT API and generate line-specific comments."""
    
    import openai
    import os

    # Use your OpenAI API key
    openai_api_key = os.getenv("OPENAI_API_KEY")
    
    # Set up OpenAI API key
    openai.api_key = openai_api_key

    # Define the prompt to be used for GPT model
    prompt = f"""You are a Senior Software Engineer conducting a code review. Analyze the following code changes and provide a code review with line-specific comments (get line number from code diff). Provide specific, actionable feedback. Format your response as a list of JSON objects, each containing 'line_number', 'category', 'severity', and 'comment' fields. Category should be one of these - Security, Functionality, Performance, Maintainability, Scalability, Compatibility, Accessibility, Internationalization and Localization, Testing, Code Style, Regulatory Compliance. Severity should be one of these - Critical, High, Medium, Low, Informational. Response should only contain list of JSON objects. List can be empty if no issues are found but still return list in every case : {file_patch} Code Review:"""

    # Call OpenAI API using the ChatCompletion endpoint
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a Senior Software Engineer and an expert code reviewer."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1000,
        temperature=0.7,
    )

    # Extract and clean up the response
    message_content = response['choices'][0]['message']['content']

    # Print the raw message content for debugging
    print("Raw response content:\n", message_content)

    # Split the content to separate the JSON part
    # parts = message_content.split('```json')

    # If the JSON block is present, extract it
    # if len(parts) > 1:
    #     json_part = parts[1].split('```')[0].strip()  # Remove any trailing markers like ```
    # else:
    #     # raise ValueError("No JSON part found in the content.")
    #     return json.dumps([])

    # Load and pretty-print the cleaned JSON content
    try:
        cleaned_json = json.loads(message_content)
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        raise ValueError("The extracted content is not a valid JSON.") from e

    # Return a properly formatted JSON string for display
    return json.dumps(cleaned_json)


def post_review_comment(repo_owner, repo_name, pr_number, commit_id, path, body, line, category, severity, installation_id):
    """Post a review comment to the GitHub PR."""
    url = f"{app.config['GITHUB_API_BASE']}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/comments"
    data = {
        "body": f"[{severity} - {category}] {body}",
        "commit_id": commit_id,
        "path": path,
        "line": line
    }

    github_response = github_request("POST", url, installation_id, data)
    # print("github_response for ai comment")
    # print(github_response)
    return github_response

def process_pull_request(repo_owner, repo_name, pr_number, db_pull_request, installation_id):
    try:
        pr = fetch_pr_details(repo_owner, repo_name, pr_number, installation_id)
        commit_id = pr['head']['sha']
        
        files = get_pr_files(repo_owner, repo_name, pr_number, installation_id)

        all_review_comments = []
        
        for file in files:
            review_comments = analyze_code_changes(file['patch'])
            all_review_comments.append(review_comments)

            try:
                comments_list = json.loads(review_comments)
                for comment in comments_list:
                    # Post comment to GitHub
                    github_comment = post_review_comment(
                        repo_owner,
                        repo_name,
                        pr_number,
                        commit_id,
                        file['filename'],
                        comment['comment'],
                        comment['line_number'],
                        comment['category'],
                        comment['severity'],
                        installation_id
                    )
                    
                    # Save comment to database
                    db_comment = AIComment(
                        content=comment['comment'],
                        file_name=file['filename'],
                        line_number=comment['line_number'],
                        category=comment['category'],
                        severity=comment['severity'],
                        pull_request_id=db_pull_request.id,
                        url=github_comment['html_url']
                    )
                    db.session.add(db_comment)
                
                db.session.commit()
                app.logger.info(f"Posted and saved review comments for file: {file['filename']}")
            except json.JSONDecodeError:
                app.logger.error(f"Error parsing AI response for file: {file['filename']}")
                app.logger.error(f"Raw response: {review_comments}")
        
        db_pull_request.status='AI Reviewed'
        db_pull_request.llm_response = json.dumps(all_review_comments)
        db_pull_request.llm_response_time = datetime.datetime.now()
        db.session.commit()

    except Exception as e:
        app.logger.error(f"Error processing pull request: {str(e)}")
        db.session.rollback()

@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email').lower()
    password = data.get('password')
    organizationName = data.get('organizationName')  # Ensure this matches your field name
    organizationType = data.get('organizationType')

    # Check if all details are provided
    if not username or not password or not email or not organizationName or not organizationType:
        return jsonify(message='All details are required'), 400

    # Check if the username already exists
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify(message='Username already exists'), 400

    # Create a new organization
    new_org = Organization(name=organizationName, type=organizationType)
    db.session.add(new_org)
    db.session.commit()  # Commit to get the organization ID

    # Create a new user
    new_user = User(username=username, email=email, organization=new_org)  # Use the organization instance
    new_user.set_password(password)

    # Add and commit the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message='User created successfully'), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    else:
        return jsonify(message='Invalid credentials'), 401

# blacklist = set()

@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # jti = get_jwt_identity()['jti']  # Get the unique token identifier
    # blacklist.add(jti)  # Add the token to the blacklist
    response = jsonify({'msg': 'Successfully logged out'})
    # unset_jwt_cookies(response)
    return response

@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify(access_token=access_token), 200

@app.route('/github/afterAuthCode', methods=['GET'])
def github_after_auth_code():
    # https://063e-223-233-85-238.ngrok-free.app/github/afterAuthCode?installation_id=54963627&setup_action=install
    installation_id = request.args.get('installation_id')
    setup_action = request.args.get('setup_action')
    user_id = request.args.get('state')
    
    if not installation_id or not setup_action or not user_id:
        return jsonify({"error": "Missing installation_id or setup_action or user_id"}), 400

    # Retrieve the user_id associated with the state from your temporary store or database
    # user_id = get_user_id_by_state(state)  # Implement this function based on how you store state


    # Exchange code for access token
    token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    
    payload = {}
    

    jwt_from_private_key = get_jwt_from_private_key()
    headers = {'Accept': 'application/vnd.github+json', "Authorization": f"Bearer {jwt_from_private_key}"}
    token_response = requests.post(token_url, json=payload, headers=headers)
    token_json = token_response.json()
    # print(token_json)
#    
    #  'permissions': {'metadata': 'read', 'pull_requests': 'write'}, 'repository_selection': 'selected'}
    
    # call for repo data
    authorised_repos_url = "https://api.github.com/installation/repositories"
    authorised_repos_headers = {'Accept': 'application/vnd.github+json', "Authorization": f"Bearer {token_json['token']}"}
    authorised_repos_response = requests.get(authorised_repos_url, headers=authorised_repos_headers)

    repository_data = authorised_repos_response.json()["repositories"]
    user = User.query.get(user_id)
    # organization = Organization.query.filter_by(id=user.organization_id).first()
    # organization.installation_id = installation_id
    for repo in repository_data:
        if Repository.query.filter_by(repo_id=repo["id"]).first() is None:
            repo_obj = Repository(name=repo["name"], url=repo["html_url"], repo_id=repo["id"], added_by=user_id, organization_id=user.organization_id, installation_id=installation_id)
            db.session.add(repo_obj)
        else:
            repo_obj = Repository.query.filter_by(repo_id=repo["id"]).first()
            repo_obj.is_deleted = False
            repo_obj.installation_id = installation_id

    db.session.commit()

    # return jsonify({"msg": "Repositories added successfully"}), 200
    frontend_url = app.config['FRONTEND_URL']  # Replace with your actual frontend URL
    return redirect(frontend_url)

@app.route('/github/webhook', methods=['POST'])
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
        
        # Only handle "opened" or "reopened" PRs
        if action in ['opened', 'reopened']:
            pr_data = payload.get('pull_request', {})
            repo_data = payload.get('repository', {})
            try:
                # Create entries in PullRequest table
                repo = Repository.query.filter_by(repo_id=repo_data.get('id'), is_deleted=False).first()
                # organization = Organization.query.filter_by(id=repo.organization_id).first()
                installation_id = repo.installation_id
                new_pr = PullRequest(
                    pr_id=pr_data.get('id'),
                    title=pr_data.get('title'),
                    description=pr_data.get('body'),
                    repository_id=repo.id,
                    status='Pending',
                    url=pr_data.get('html_url')
                )
                db.session.add(new_pr)
                db.session.commit()

                # Process the pull request (analyze and post comments)
                process_pull_request(
                    repo_data.get('owner', {}).get('login'),
                    repo_data.get('name'),
                    pr_data.get('number'), 
                    new_pr,
                    installation_id
                )

                return jsonify({'message': 'Pull request handled and reviewed successfully'}), 200
                
            except Exception as e:
                app.logger.error(f"Error handling pull request: {str(e)}")
                return jsonify({'error': 'Internal server error'}), 500
    
    return jsonify({'message': 'Event Ignored'}), 200


def is_github_signature_valid(payload, signature):
    if signature is None:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
    mac = hmac.new(app.config['WEBHOOK_SECRET'].encode(), payload, hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)



# def get_user_id_by_state(state):
#     return state



@app.route('/repositories', methods=['GET'])
@jwt_required()
def get_repositories():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        # Get all repositories for the user's organization
        repositories = Repository.query.filter_by(organization_id=user.organization_id, is_deleted=False).all()

        repo_list = []
        
        for repo in repositories:
            # Query the latest llm_response_time for the repository's pull requests
            last_reviewed_pr = PullRequest.query.filter_by(repository_id=repo.id).order_by(PullRequest.llm_response_time.desc()).first()
            count_reviewed_pr = PullRequest.query.filter_by(repository_id=repo.id, status='AI Reviewed').count()

            if last_reviewed_pr and last_reviewed_pr.llm_response_time:
                # Convert llm_response_time to a human-readable format
                last_reviewed_time = last_reviewed_pr.llm_response_time
                now = datetime.datetime.now()
                last_reviewed = humanize.naturaltime(now - last_reviewed_time)
            else:
                last_reviewed = "Not Reviewed"

            repo_list.append({
                "id": repo.id,
                "name": repo.name,
                "url": repo.url,
                "organization_id": repo.organization_id,
                "last_reviewed": last_reviewed,
                "reviewed_prs": count_reviewed_pr
            })

        return jsonify({"repositories": repo_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pullrequests', methods=['GET'])
@jwt_required()
def get_pull_requests():
    try:
        # Retrieve all pull requests from the database
        repo_id = request.args.get('repo_id', None)
        user = User.query.get(get_jwt_identity())
        if repo_id is None or repo_id == "" or repo_id == "null":
            pull_requests = PullRequest.query.join(Repository).filter(
                Repository.organization_id == user.organization_id,
                Repository.is_deleted == False
            ).all()
        else:
            pull_requests = PullRequest.query.join(Repository).filter(
                Repository.id == repo_id,
                Repository.organization_id == user.organization_id,
                Repository.is_deleted == False
            ).all()
        
        pr_list = [{
            'id': pr.id,
            'title': pr.title,
            'repository_name': pr.repository.name,
            'status': pr.status,
            'url': pr.url
        } for pr in pull_requests]

        return jsonify(pr_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/ai_comments/<int:pr_id>', methods=['GET'])
def get_ai_comments(pr_id):
    try:
        # Fetch AI comments for the given pull request ID
        ai_comments = AIComment.query.filter_by(pull_request_id=pr_id).all()
        
        if not ai_comments:
            return jsonify({"error": "No AI comments found for this pull request."}), 404
        
        # Format the AI comments
        comments_list = [{
            "content": comment.content,
            "file_name": comment.file_name,
            "line_number": comment.line_number,
            "created_at": comment.created_at.isoformat(),
            "url": comment.url

        } for comment in ai_comments]
        
        return jsonify(comments_list), 200

    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": str(e)}), 500

@app.route('/api/metrics', methods=['GET'])
@jwt_required()
def get_metrics():
    from_date = request.args.get('from', default=(datetime.datetime.now() - datetime.timedelta(days=365)).strftime('%Y-%m-%d'))
    to_date = request.args.get('to', default=datetime.datetime.now().strftime('%Y-%m-%d'))

    try:
        from_date = datetime.datetime.strptime(from_date, '%Y-%m-%d')
        to_date = datetime.datetime.strptime(to_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    metrics = db.session.query(
        func.strftime('%Y-%m', AIComment.created_at).label('month'),
        func.count(AIComment.id).label('count')
    ).join(PullRequest).join(Repository).filter(
        Repository.organization_id == user.organization_id,
        AIComment.created_at.between(from_date, to_date)
    ).group_by(func.strftime('%Y-%m', AIComment.created_at)).all()

    result = [
        {
            'date': f"{month}-01",  # Add day to make it a valid date
            'count': count
        }
        for month, count in metrics
    ]

    return jsonify(result)

@app.route('/test_openai', methods=['GET'])
def test_openai():
    patch = """
def myfun(a, b):
    return a/0
"""
    response = analyze_code_changes(patch)
    print(response)

    return jsonify(response)


@app.route('/manual_review/<int:pr_id>', methods=['GET'])
def manual_review(pr_id):
    db_pull_request = PullRequest.query.get(pr_id)
    repo = Repository.query.get(db_pull_request.repository_id)
    installation_id = "55267967" #repo.installation_id
    repo_owner = "grozafry" #repo.owner
    repo_name = repo.name
    pr_number = 6

    process_pull_request(repo_owner, repo_name, pr_number, db_pull_request, installation_id)

@app.route('/test_anthropic', methods=['GET'])
def test_anthropic():
    """Analyze code changes using Anthropic's Claude and generate line-specific comments."""
    
    file_patch = "print(2/0)"
    prompt = f"""Analyze the following code changes and provide a code review with line-specific comments. 
    Format your response as a list of JSON objects, each containing 'line_number' and 'comment' fields:\n\n{file_patch}\n\nCode Review:"""
    
    # Set the API key from environment variable
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    import anthropic
    # Create an Anthropic client
    client = anthropic.Client(api_key=anthropic_api_key)
    
    # Create the prompt and send the request
    response = client.completions.create(
        model="claude-v1",  # Specify the Claude model
        prompt=f"{anthropic.HUMAN_PROMPT} {prompt} {anthropic.AI_PROMPT}",
        max_tokens_to_sample=1000,
        temperature=0.7,
    )
    
    # Return the generated content (strip any extra spaces or newlines)
    return response['completion'].strip()

@app.route('/test_gemini', methods=['GET'])
def test_gemini():
    """Analyze code changes using Anthropic's Claude and generate line-specific comments."""
    

    file_patch = """
def myfun(a, b):
    return a/0
"""
    prompt = f"""Analyze the following code changes and provide a code review with line-specific comments. 
    Format your response as a list of JSON objects, each containing 'line_number' and 'comment' fields:{file_patch}Code Review:"""
    
    # Set the API key from environment variable
    import os 
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    import google.generativeai as genai
    

    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    print(response.text)
    cleaned_response = response.text.strip().strip('```json').strip('```').strip()
    return cleaned_response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=7000)








# ##test code for posting comments to github after review by OPEN AI API
# import os
# import requests
# import json
# import openai

# # GitHub API base URL
# GITHUB_API_BASE = "https://api.github.com"

# # Set up API tokens
# github_token = get_installation_token_from_jwt_token()

# def github_request(method, url, data=None):
#     """Make a request to the GitHub API."""
#     headers = {
#         "Authorization": f"token {github_token}",
#         "Accept": "application/vnd.github.v3+json"
#     }
#     print(headers)
#     response = requests.request(method, url, headers=headers, json=data)
#     # response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     print(response.json())
#     return response.json()

# def fetch_pr_details(repo_owner, repo_name, pr_number):
#     """Fetch pull request details from GitHub."""
#     url = f"{GITHUB_API_BASE}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}"
#     print(url)
#     return github_request("GET", url)

# def get_pr_files(repo_owner, repo_name, pr_number):
#     """Get the files changed in the pull request."""
#     url = f"{GITHUB_API_BASE}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files"
#     return github_request("GET", url)

# def analyze_code_changes(file_patch):
#     return json.dumps([
#     {
#         "line_number": 21,
#         "comment": "Consider removing comments that do not provide meaningful information or are irrelevant to the functionality of the repository. Comments like this can clutter the code and reduce readability."
#     },
#     {
#         "line_number": 22,
#         "comment": "Avoid leaving comments such as 'These comments are of no consequence.' It's best practice to add comments that explain why certain code exists, describe complex logic, or note important details, rather than trivial remarks."
#     }
# ]
# )
#     """Analyze code changes using OpenAI's GPT-3.5 and generate line-specific comments."""
#     prompt = f"Analyze the following code changes and provide a code review with line-specific comments. Format your response as a list of JSON objects, each containing 'line_number' and 'comment' fields:\n\n{file_patch}\n\nCode Review:"
    
#     response = openai.ChatCompletion.create(
#         model="gpt-3.5-turbo",
#         messages=[
#             {"role": "system", "content": "You are a senior software engineer conducting a code review. Provide specific, actionable feedback."},
#             {"role": "user", "content": prompt}
#         ],
#         max_tokens=1000,
#         n=1,
#         stop=None,
#         temperature=0.7,
#     )
    
#     return response.choices[0].message['content'].strip()

# def post_review_comment(repo_owner, repo_name, pr_number, commit_id, path, body, line):
#     """Post a review comment to the GitHub PR."""
#     url = f"{GITHUB_API_BASE}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/comments"
#     data = {
#         "body": body,
#         "commit_id": commit_id,
#         "path": path,
#         "line": line
#     }
#     return github_request("POST", url, data)

# def main(repo_owner, repo_name, pr_number):
#     # Fetch PR details
#     pr = fetch_pr_details(repo_owner, repo_name, pr_number)
#     commit_id = pr['head']['sha']
    
#     # Get PR files
#     files = get_pr_files(repo_owner, repo_name, pr_number)
    
#     for file in files:
#         # Analyze code changes for each file
#         review_comments = analyze_code_changes(file['patch'])
        
#         # Parse and post review comments
#         try:
#             comments_list = json.loads(review_comments)
#             for comment in comments_list:
#                 post_review_comment(
#                     repo_owner,
#                     repo_name,
#                     pr_number,
#                     commit_id,
#                     file['filename'],
#                     comment['comment'],
#                     comment['line_number']
#                 )
#             print(f"Posted review comments for file: {file['filename']}")
#         except json.JSONDecodeError:
#             print(f"Error parsing AI response for file: {file['filename']}")
#             print(f"Raw response: {review_comments}")

# if __name__ == "__main__":
#     repo_owner = "grozafry"  # Replace with the repository owner
#     repo_name = "RedditCrawler"    # Replace with the repository name
#     pr_number = 6       # Replace with the PR number you want to review
#     main(repo_owner, repo_name, pr_number)