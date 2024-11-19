from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Load token from environment variable
TOKEN = os.environ['TOKEN']

@app.route('/validate', methods=['GET', 'POST'])
def validate_token():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token_from_header = auth_header[7:]
        if token_from_header == TOKEN:
            return jsonify({'message': 'Token is valid'}), 200
        else:
            return jsonify({'message': 'Token is invalid'}), 401
    else:
        return jsonify({'message': 'No Bearer token provided'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
