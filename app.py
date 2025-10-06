import os
import logging
from flask import Flask, render_template, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-here")

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

@app.route('/')
def home():
    if 'user' in session:
        user = session['user']
        return render_template('index.html', user=user)
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/google/login')
def google_login():
    try:
        redirect_uri = url_for('google_auth_callback', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        logger.error(f"Google login initiation error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/google/auth/callback')
def google_auth_callback():
    try:
        token = google.authorize_access_token()
        user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        
        # Store user information in session
        session['user'] = {
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'picture': user_info.get('picture'),
            'google_id': user_info.get('sub')
        }
        
        logger.info(f"User logged in: {user_info.get('name')} ({user_info.get('email')})")
        return redirect(url_for('home'))
       
    except Exception as e:
        logger.error(f"Google OAuth callback error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/user')
def api_user():
    if 'user' in session:
        return jsonify(session['user'])
    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# For Vercel serverless deployment
def create_app():
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("Starting Flask Google Auth App...")
    print(f"Google OAuth: {'✓ Configured' if os.environ.get('GOOGLE_CLIENT_ID') else '✗ Missing'}")
    print(f"Server running on http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
