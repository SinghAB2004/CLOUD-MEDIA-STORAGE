from flask import Flask, request, send_file, render_template, g, redirect, url_for, session, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import google.oauth2.credentials
import google_auth_oauthlib.flow
import google.auth.transport.requests
from google.oauth2 import id_token
from pip._vendor import cachecontrol
from models import User, init_user_db, get_user
from auth import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
import os
import pathlib
import requests
import sqlite3
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure secret key

DATABASE = "files.db"

# Configure Google OAuth
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secrets.json")

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/callback"  # Make sure this matches exactly
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Create table if not exists
def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_file_id INTEGER,
                user_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                filedata BLOB NOT NULL,
                mimetype TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, user_file_id)
            )
        """)
        conn.commit()

# Add this function to initialize database on first run
def initialize_app():
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()

@app.before_request
def before_request():
    init_db()

# Add login routes
@app.route("/start-auth", methods=['POST'])
def start_auth():
    try:
        # Verify reCAPTCHA first
        recaptcha_response = request.json.get('g-recaptcha-response')
        if not recaptcha_response:
            return jsonify({'error': 'Please complete the reCAPTCHA verification'}), 400

        # Add remote IP to verification
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        response = requests.post(verify_url, data={
            'secret': '6LdcIgUrAAAAACRDr3O0mfpvr1R3qgNo1n7Rqub_',
            'response': recaptcha_response,
            'remoteip': request.remote_addr  # Add client IP
        })
        
        verification_response = response.json()
        
        if not verification_response.get('success'):
            app.logger.error(f"reCAPTCHA verification failed: {verification_response}")
            return jsonify({'error': 'reCAPTCHA verification failed'}), 400

        # Continue with OAuth flow
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        return jsonify({'auth_url': authorization_url})
        
    except Exception as e:
        app.logger.error(f"Auth error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/login")
def login():
    if request.args.get('code'):
        # Handle OAuth callback
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            
            request_session = requests.session()
            cached_session = cachecontrol.CacheControl(request_session)
            token_request = google.auth.transport.requests.Request(session=cached_session)

            # Add clock_skew_in_seconds parameter to handle minor time differences
            id_info = id_token.verify_oauth2_token(
                id_token=credentials._id_token,
                request=token_request,
                audience=GOOGLE_CLIENT_ID,
                clock_skew_in_seconds=10
            )

            user = User(
                id_=id_info.get("sub"),
                name=id_info.get("name"),
                email=id_info.get("email"),
                profile_pic=id_info.get("picture")
            )

            # Store user in database
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                            VALUES (?, ?, ?, ?)''', 
                        (user.id, user.name, user.email, user.profile_pic))
                conn.commit()

            login_user(user)
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(f"Auth error: {str(e)}")
            return render_template('login.html', error="Authentication failed")
    
    return render_template('login.html')

@app.route("/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        # Add clock_skew_in_seconds parameter to handle minor time differences
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )

        user = User(
            id_=id_info.get("sub"),
            name=id_info.get("name"),
            email=id_info.get("email"),
            profile_pic=id_info.get("picture")
        )

        # Store user in database
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                        VALUES (?, ?, ?, ?)''', 
                    (user.id, user.name, user.email, user.profile_pic))
            conn.commit()

        login_user(user)
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Authentication error: {str(e)}")
        return render_template("login.html", error="Authentication failed. Please try again."), 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Upload file route
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file[]" not in request.files:
        return jsonify({"error": "No files selected"}), 400

    files = request.files.getlist("file[]")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    uploaded_files = []
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            for file in files:
                # Get the next user_file_id
                cur.execute(
                    "SELECT COALESCE(MAX(user_file_id), 0) + 1 FROM files WHERE user_id = ?", 
                    (current_user.id,)
                )
                next_file_id = cur.fetchone()[0]
                
                # Handle duplicate filenames
                filename, ext = os.path.splitext(file.filename)
                counter = 0
                new_filename = file.filename
                
                while True:
                    cur.execute("""
                        SELECT COUNT(*) FROM files 
                        WHERE user_id = ? AND filename = ?
                    """, (current_user.id, new_filename))
                    
                    exists = cur.fetchone()[0] > 0
                    if not exists:
                        break
                        
                    counter += 1
                    new_filename = f"{filename}_{counter}{ext}"

                # Save file
                file_data = file.read()
                filesize = len(file_data)
                
                cur.execute(
                    """INSERT INTO files 
                       (user_file_id, user_id, filename, filedata, mimetype, filesize) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (next_file_id, current_user.id, new_filename, file_data, file.mimetype, filesize)
                )
                uploaded_files.append(new_filename)
            
            conn.commit()
            
        return jsonify({
            "message": f"Successfully uploaded {len(uploaded_files)} file(s)",
            "files": uploaded_files
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Retrieve file route
@app.route("/file/<int:file_id>")
@login_required
def get_file(file_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT filename, filedata, mimetype 
            FROM files 
            WHERE user_file_id = ? AND user_id = ?
        """, (file_id, current_user.id))
        file = cur.fetchone()
        
    if file is None:
        abort(404)
        
    return send_file(
        io.BytesIO(file[1]),
        mimetype=file[2],
        as_attachment=True,
        download_name=file[0]
    )

# List files route
@app.route("/files")
@login_required
def list_files():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT user_file_id, filename, mimetype, filesize, upload_timestamp 
            FROM files 
            WHERE user_id = ? 
            ORDER BY upload_timestamp ASC
        """, (current_user.id,))
        files = [dict(zip(['user_file_id', 'filename', 'mimetype', 'size', 'upload_date'], row)) 
                for row in cur.fetchall()]
    return render_template("files.html", files=files)

# Delete files route
@app.route("/delete-files", methods=["POST"])
@login_required
def delete_files():
    data = request.get_json()
    file_ids = data.get('file_ids', [])
    
    if not file_ids:
        return jsonify({'error': 'No files selected'}), 400
        
    with get_db() as conn:
        for file_id in file_ids:
            conn.execute("""
                DELETE FROM files 
                WHERE user_file_id = ? AND user_id = ?
            """, (file_id, current_user.id))
        conn.commit()
        
    return jsonify({'message': 'Files deleted successfully'})

# Basic HTML form for testing
@app.route("/")
def index():
    if not current_user.is_authenticated:
        return render_template("login.html")
    return render_template("index.html")

if __name__ == "__main__":
    initialize_app()
    init_user_db()  # Initialize user database
    app.run(debug=True)
