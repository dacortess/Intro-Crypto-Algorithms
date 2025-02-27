from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import json
import sys
import os
import io
from PIL import Image
from werkzeug.utils import secure_filename

# Ajustar la ruta para incluir el directorio 'scripts'
scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
sys.path.append(scripts_path)

import encrypt
import decrypt
import analyze

app = Flask(__name__)
CORS(app)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
        temp_input = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image_file.filename))
        temp_output = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{secure_filename(image_file.filename)}')
        
        image_file.save(temp_input)
        
        # Encrypt the image
        output_path, iv = encrypt.encrypt_image(temp_input, temp_output, key)
        
        # Read the encrypted file and prepare for sending
        with open(output_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Clean up temporary files
        os.remove(temp_input)
        os.remove(temp_output)
        
        # Create response with file download
        return send_file(
            io.BytesIO(encrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=f'encrypted_{secure_filename(image_file.filename)}'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
