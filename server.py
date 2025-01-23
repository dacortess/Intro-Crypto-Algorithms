from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import sys
import os

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

        best = ''

        if script_name == 'encrypt':
            result = encrypt.main(json.dumps(data))
        elif script_name == 'decrypt':
            result, best = decrypt.main(json.dumps(data))
        elif script_name == 'analyze':
            result = analyze.main(json.dumps(data))
        else:
            return 'Invalid script name', 400

        if best != '': return [result, best]
        return result
    except Exception as e:
        return str(e), 500

# Eliminar app.run() ya que PythonAnywhere se encarga de ejecutarlo.
