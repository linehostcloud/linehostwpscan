from flask import Flask, render_template, request, jsonify, redirect, url_for
from wpscan import WordPressScanner
import os
import json
from datetime import datetime

app = Flask(__name__)

# Cria o diretório de templates se não existir
os.makedirs(os.path.join(os.path.dirname(__file__), 'templates'), exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('url')
    if not target_url:
        return redirect(url_for('index'))

    # Cria uma instância do scanner e executa a análise
    scanner = WordPressScanner(target_url)
    results = scanner.scan()

    # Salva os resultados em um arquivo JSON com timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"resultado_scan_{timestamp}.json"
    filepath = os.path.join(os.path.dirname(__file__), 'resultados', filename)

    # Cria o diretório de resultados se não existir
    os.makedirs(os.path.join(os.path.dirname(__file__), 'resultados'), exist_ok=True)

    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)

    return render_template('results.html', results=results, scan_time=timestamp)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL é obrigatória'}), 400

    target_url = data['url']
    scanner = WordPressScanner(target_url)
    results = scanner.scan()

    return jsonify(results)

@app.route('/resultados/<timestamp>')
def view_results(timestamp):
    filepath = os.path.join(os.path.dirname(__file__), 'resultados', f"resultado_scan_{timestamp}.json")

    try:
        with open(filepath, 'r') as f:
            results = json.load(f)
        return render_template('results.html', results=results, scan_time=timestamp)
    except FileNotFoundError:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
