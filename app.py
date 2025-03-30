from flask import Flask, request, send_file, render_template, g
import sqlite3
import io
import os

app = Flask(__name__)

DATABASE = "files.db"

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
                filename TEXT NOT NULL,
                filedata BLOB NOT NULL,
                mimetype TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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

# Upload file route
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return render_template("index.html", error="No file part"), 400

    file = request.files["file"]
    if file.filename == "":
        return render_template("index.html", error="No selected file"), 400

    # Read file data
    file_data = file.read()
    filesize = len(file_data)
    mimetype = file.mimetype

     # Store in DB
    with get_db() as conn:
        conn.execute(
            "INSERT INTO files (filename, filedata, mimetype, filesize) VALUES (?, ?, ?, ?)", 
            (file.filename, file_data, mimetype, filesize)
        )
        conn.commit()
    
    return render_template("index.html", success=f"File '{file.filename}' uploaded successfully")

# Retrieve file route
@app.route("/file/<int:file_id>")
def get_file(file_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT filename, filedata, mimetype FROM files WHERE id=?", (file_id,))
        row = cur.fetchone()
    
    if row is None:
        return "File not found", 404
    
    filename, file_data, mimetype = row
    return send_file(io.BytesIO(file_data), mimetype=mimetype, as_attachment=True, download_name=filename)

# List files route
@app.route("/files")
def list_files():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, filename, mimetype, filesize, upload_timestamp FROM files ORDER BY upload_timestamp DESC")
        files = cur.fetchall()
    
    return render_template("files.html", files=files)

# Basic HTML form for testing
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    initialize_app()
    app.run(debug=True)
