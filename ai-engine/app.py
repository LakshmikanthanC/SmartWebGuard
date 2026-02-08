from flask import Flask, request, jsonify
from flask_cors import CORS
from url_analyzer import analyze_url as scan_url_func
from predict import NIDSPredictor
import traceback

app = Flask(__name__)
CORS(app)

predictor = NIDSPredictor()

@app.route("/api/url/scan", methods=["POST"])
def scan_url_route():
    """Deep scan a URL for malware, phishing, viruses."""
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        deep = data.get("deep_scan", True)
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        result = scan_url_func(url, deep_scan=deep)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/url/quick", methods=["POST"])
def quick_scan():
    """Quick scan — URL pattern analysis only, no content fetch."""
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        result = scan_url_func(url, deep_scan=False)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/url/batch", methods=["POST"])
def batch_scan():
    """Scan multiple URLs."""
    try:
        data = request.get_json()
        urls = data.get("urls", [])
        deep = data.get("deep_scan", False)
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400
        results = [scan_url_func(u, deep_scan=deep) for u in urls[:20]]
        return jsonify({"results": results})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
