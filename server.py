from flask import Flask, request, jsonify, render_template_string, send_file, send_from_directory
from flask_cors import CORS
import json
import sys
import os
import io
from PIL import Image
import base64

# Ajustar la ruta para incluir el directorio 'scripts'
scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
sys.path.append(scripts_path)

import encrypt
import decrypt
import analyze

app = Flask(__name__)
CORS(app)

# Página principal con información del proyecto
@app.route('/', methods=['GET'])
def home():
    project_title = "Backend API for Crypto Text Management"
    team_members = ["Juan Sebastián Rueda Segura, David Camilo Cortes Salazar"]
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ project_title }}</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 20px;
                    background-color: #f4f4f9;
                    color: #333;
                }
                h1 {
                    color: #007BFF;
                }
                ul {
                    list-style-type: none;
                    padding: 0;
                }
                li {
                    margin: 5px 0;
                }
            </style>
        </head>
        <body>
            <h1>{{ project_title }}</h1>
            <p>Welcome to the backend project. Here are the team members involved:</p>
            <ul>
                {% for member in team_members %}
                    <li>{{ member }}</li>
                {% endfor %}
            </ul>
        </body>
        </html>
    ''', project_title=project_title, team_members=team_members)

@app.route('/api/python/<script_name>', methods=['POST'])
def handle_python_script(script_name):
    try:
        data = request.json

        if script_name == 'encrypt':
            result = encrypt.main(json.dumps(data))
        elif script_name == 'decrypt':
            result = decrypt.main(json.dumps(data))
        elif script_name == 'analyze':
            result = analyze.main(json.dumps(data))
        else:
            return 'Invalid script name', 400

        return result

    except Exception as e:
        return str(e), 500

@app.route('/encrypt-image', methods=['POST'])
def encrypt_image_route():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        image_file = request.files['image']
        key = request.form.get('key', '')
        
        if not key:
            return jsonify({'error': 'No encryption key provided'}), 400
            
        # Save the uploaded file temporarily
        temp_input = os.path.join('crypto', 'uploads', 'image.jpg')
        temp_output = os.path.join('crypto', 'uploads', 'encrypted_image.jpg')

        
        image_file.save(temp_input)
        
        # Encrypt the image
        output_path, iv = encrypt.encrypt_image(temp_input, temp_output, key)
        
        # Convert IV to base64 for safe transmission
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        
        # Create a URL for the encrypted file
        encrypted_image_url = f'https://dacortess.pythonanywhere.com/download/{os.path.basename(output_path)}'
        
        return jsonify({
            'encrypted_image_url': encrypted_image_url,
            'iv': iv_b64
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt-image', methods=['POST'])
def decrypt_image_route():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        image_file = request.files['image']
        key = request.form.get('key', '')
        iv_b64 = request.form.get('iv', '')
        
        if not key:
            return jsonify({'error': 'No encryption key provided'}), 400
        if not iv_b64:
            return jsonify({'error': 'No IV provided'}), 400
            
        try:
            # Decode the base64 IV back to bytes
            iv = base64.b64decode(iv_b64)
        except Exception as e:
            return jsonify({'error': 'Invalid IV format'}), 400
            
        # Save the uploaded file temporarily
        temp_input = os.path.join('crypto', 'uploads', 'image2.jpg')
        temp_output = os.path.join('crypto', 'uploads', 'decrypted_image.jpg')
        
        image_file.save(temp_input)
        
        # Decrypt the image
        output_path = decrypt.decrypt_image(temp_input, temp_output, key, iv)
        
        # Create a URL for the decrypted file
        decrypted_image_url = f'https://dacortess.pythonanywhere.com/download/{os.path.basename(output_path)}'
        
        return jsonify({
            'decrypted_image_url': decrypted_image_url,
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sign-file', methods=['POST'])
def sign_file_route():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        
        # Save the uploaded file temporarily
        temp_file = os.path.join('crypto', 'uploads', 'dsa_file')
        file.save(temp_file)
        
        # Sign the file using DSA
        signature, public_key, private_key = encrypt.sign_file_DSA(temp_file)
        
        # Remove temporary file
        os.remove(temp_file)
        
        if signature is None or public_key is None:
            return jsonify({'error': 'Error signing file'}), 500
            
        return jsonify({
            'signature': signature,
            'publicKey': public_key,
            'privateKey': private_key
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify-file', methods=['POST'])
def verify_file_route():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        if 'signature' not in request.form:
            return jsonify({'error': 'No signature provided'}), 400
            
        if 'public_key' not in request.form:
            return jsonify({'error': 'No public key provided'}), 400
            
        file = request.files['file']
        signature = request.form['signature']
        public_key = request.form['public_key']
        
        # Save the uploaded file temporarily
        temp_file = os.path.join('crypto', 'uploads', 'dsa_file')
        file.save(temp_file)
        
        # Verify the file signature
        verification_result, _ = decrypt.verify_file_DSA(temp_file, signature, public_key)
        
        # Remove temporary file
        os.remove(temp_file)
        
        return jsonify({
            'verification_result': verification_result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory('uploads', filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
