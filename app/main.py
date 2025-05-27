from flask import Flask, render_template, request, jsonify
import whois
import requests
from datetime import datetime
import base64
import ssl
from urllib.parse import urlparse

app = Flask(__name__)

VIRUSTOTAL_API_KEY = "0ee49f23180bda51cc9fad71b9e609ed2db58c776d83edf427ef3594f4759cef"


def format_date(d):
    if isinstance(d, list):
        d = d[0] if d else None
    if d is None:
        return 'N/A'
    if hasattr(d, 'strftime'):
        return d.strftime('%Y-%m-%d %H:%M:%S')
    return str(d)


def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        return {
            "domain_name": info.domain_name if info.domain_name else 'N/A',
            "creation_date": format_date(info.creation_date),
            "expiration_date": format_date(info.expiration_date),
            "registrar": info.registrar if info.registrar else 'N/A',
            "name_servers": info.name_servers if info.name_servers else 'N/A',
            "emails": info.emails if info.emails else 'N/A'
        }
    except Exception as e:
        return {"error": str(e)}


def check_ssl(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc if parsed.netloc else parsed.path
        context = ssl.create_default_context()
        with ssl.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Se conectar com sucesso, tem SSL válido
                return True
    except Exception:
        return False


def url_to_id(url):
    url_bytes = url.encode()
    b64_bytes = base64.urlsafe_b64encode(url_bytes)
    b64_str = b64_bytes.decode().strip("=")
    return b64_str


def get_virustotal_report(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url_id = url_to_id(url)
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL não fornecida"}), 400

    domain = url.replace('https://', '').replace('http://', '').split('/')[0]

    whois_info = get_whois_info(domain)
    https_status = check_ssl(url)
    vt_data = get_virustotal_report(url)

    if vt_data and 'data' in vt_data:
        stats = vt_data['data']['attributes']['last_analysis_stats']
        vt_summary = {
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "total": sum(stats.values())
        }
    else:
        vt_summary = {
            "error": "Erro ao consultar VirusTotal ou URL não encontrada"}

    result = {
        "url": url,
        "https": https_status,
        "whois": whois_info,
        "virustotal": vt_summary,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
