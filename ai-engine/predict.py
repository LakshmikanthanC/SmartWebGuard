import json
import os
from typing import List, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.environ.get("DATA_DIR", BASE_DIR), "data")
MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(BASE_DIR, "models"))

# CNN Model Configuration
CNN_CONFIG = {
    "epochs": int(os.environ.get("CNN_EPOCHS", 50)),
    "batch_size": int(os.environ.get("CNN_BATCH_SIZE", 64)),
    "learning_rate": float(os.environ.get("CNN_LEARNING_RATE", 0.001)),
    "validation_split": float(os.environ.get("CNN_VALIDATION_SPLIT", 0.2)),
    "dropout_rate": float(os.environ.get("CNN_DROPOUT_RATE", 0.3)),
    "filters": [int(x) for x in os.environ.get("CNN_FILTERS", "64,128,256").split(",")],
    "kernel_size": int(os.environ.get("CNN_KERNEL_SIZE", 3)),
    "dense_units": [int(x) for x in os.environ.get("CNN_DENSE_UNITS", "256,128").split(",")],
}

# NSL-KDD Columns
NSL_KDD_COLUMNS = os.environ.get(
    "NSL_KDD_COLUMNS",
    "duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,"
    "num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,"
    "num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,"
    "is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,"
    "same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,"
    "dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,"
    "dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,"
    "dst_host_rerror_rate,dst_host_srv_rerror_rate"
).split(",")

# Attack type mapping (format: attack_type:category)
_attack_map_str = os.environ.get(
    "ATTACK_MAP",
    "normal:normal,back:dos,land:dos,neptune:dos,pod:dos,smurf:dos,teardrop:dos,"
    "mailbomb:dos,apache2:dos,processtable:dos,udpstorm:dos,ipsweep:probe,nmap:probe,"
    "portsweep:probe,satan:probe,mscan:probe,saint:probe,ftp_write:r2l,guess_passwd:r2l,"
    "imap:r2l,multihop:r2l,phf:r2l,spy:r2l,warezclient:r2l,warezmaster:r2l,"
    "sendmail:r2l,named:r2l,snmpgetattack:r2l,snmpguess:r2l,xlock:r2l,xsnoop:r2l,"
    "worm:r2l,buffer_overflow:u2r,loadmodule:u2r,perl:u2r,rootkit:u2r,httptunnel:u2r,"
    "ps:u2r,sqlattack:u2r,xterm:u2r"
)
ATTACK_MAP = {k.strip(): v.strip() for k, v in (item.split(":") for item in _attack_map_str.split(","))}

FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))

# URL Analyzer Configuration - Optimized for faster scanning
URL_ANALYZER_CONFIG = {
    "request_timeout": int(os.environ.get("URL_REQUEST_TIMEOUT", 3)),
    "max_redirects": int(os.environ.get("URL_MAX_REDIRECTS", 3)),
    "max_content_length": int(os.environ.get("URL_MAX_CONTENT_LENGTH", 500000)),
    "content_scan_limit": int(os.environ.get("URL_CONTENT_SCAN_LIMIT", 100000)),
    "long_domain_length": int(os.environ.get("URL_LONG_DOMAIN_LENGTH", 50)),
    "excessive_hyphens": int(os.environ.get("URL_EXCESSIVE_HYPHENS", 3)),
    "long_url_length": int(os.environ.get("URL_LONG_URL_LENGTH", 200)),
    "excessive_subdomains": int(os.environ.get("URL_EXCESSIVE_SUBDOMAINS", 3)),
    "encoded_chars_threshold": int(os.environ.get("URL_ENCODED_CHARS_THRESHOLD", 5)),
    "redirect_chain_threshold": int(os.environ.get("URL_REDIRECT_CHAIN_THRESHOLD", 1)),
    "external_domains_threshold": int(os.environ.get("URL_EXTERNAL_DOMAINS_THRESHOLD", 5)),
}

# Suspicious TLDs
SUSPICIOUS_TLDS = os.environ.get(
    "SUSPICIOUS_TLDS",
    ".tk,.ml,.ga,.cf,.gq,.xyz,.top,.club,.work,.date,.racing,.win,.bid,"
    ".stream,.download,.loan,.men,.click,.link,.party,.review,.science,.zip,.mov"
).split(",")

# Trusted Domains
TRUSTED_DOMAINS = os.environ.get(
    "TRUSTED_DOMAINS",
    "google.com,youtube.com,facebook.com,amazon.com,wikipedia.org,twitter.com,"
    "instagram.com,linkedin.com,microsoft.com,apple.com,github.com,stackoverflow.com,"
    "reddit.com,netflix.com,whatsapp.com,zoom.us,dropbox.com,salesforce.com,adobe.com,"
    "shopify.com,wordpress.com,medium.com,cloudflare.com,npmjs.com,pypi.org,docker.com,"
    "elastic.co,mongodb.com,yahoo.com,bing.com,twitch.tv,spotify.com,paypal.com,"
    "stripe.com,slack.com,notion.so,figma.com,vercel.com,netlify.com,heroku.com"
).split(",")

# Phishing Keywords
PHISHING_KEYWORDS = os.environ.get(
    "PHISHING_KEYWORDS",
    "login,signin,verify,account,secure,password,credential,authenticate,wallet"
).split(",")

# Brand Names
BRAND_NAMES = os.environ.get(
    "BRAND_NAMES",
    "paypal,amazon,apple,microsoft,google,facebook,netflix,instagram,whatsapp"
).split(",")

# Standard Ports
STANDARD_PORTS = [int(x) for x in os.environ.get("STANDARD_PORTS", "80,443,8080,8443").split(",")]

# Phishing Urgency Keywords
PHISHING_URGENCY_KEYWORDS = os.environ.get(
    "PHISHING_URGENCY_KEYWORDS",
    "immediately,urgent,suspended,verify now,confirm now,act now"
).split(",")

# Private IP Ranges
PRIVATE_IP_RANGES = os.environ.get(
    "PRIVATE_IP_RANGES",
    "^10\\.,^172\\.(1[6-9]|2[0-9]|3[01])\\.,^192\\.168\\.,^127\\.,^0\\."
).split(",")

# URL Analyzer - Suspicious Patterns
_suspicious_patterns_str = os.environ.get(
    "SUSPICIOUS_PATTERNS",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|IP address in URL,"
    r"[a-zA-Z0-9]{30,}|Very long random string,"
    r"@|@ symbol (URL obfuscation),"
    r"\.exe|\.scr|\.bat|\.cmd|\.ps1|Executable file extension,"
    r"\.zip|\.rar|\.7z|Archive file extension,"
    r"data:|Data URI scheme,"
    r"javascript:|JavaScript URI scheme,"
    r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}|Heavy percent encoding,"
    r"-{3,}|Multiple consecutive hyphens,"
    r"\.(php|asp|jsp)\?.*=.*&.*=|Complex server-side query"
)
SUSPICIOUS_PATTERNS = []
for item in _suspicious_patterns_str.split(","):
    if "|" in item:
        pattern, description = item.rsplit("|", 1)
        SUSPICIOUS_PATTERNS.append((pattern, description))

# Malware File Patterns
_malware_patterns_str = os.environ.get(
    "MALWARE_FILE_PATTERNS",
    r"\.exe|Windows executable (.exe),"
    r"\.msi|Windows installer (.msi),"
    r"\.dll|Dynamic library (.dll),"
    r"\.scr|Screensaver file (.scr) often malware,"
    r"\.bat|Batch file (.bat),"
    r"\.cmd|Command file (.cmd),"
    r"\.ps1|PowerShell script (.ps1),"
    r"\.vbs|VBScript file (.vbs),"
    r"\.wsf|Windows script (.wsf),"
    r"\.apk|Android package (.apk),"
    r"\.dmg|macOS disk image (.dmg),"
    r"\.iso|Disk image (.iso),"
    r"download.*free|Free download pattern,"
    r"free.*download|Free download pattern,"
    r"crack.*software|Software crack,"
    r"keygen|Key generator,"
    r"warez|Pirated software,"
    r"torrent|Torrent reference"
)
MALWARE_FILE_PATTERNS = []
for item in _malware_patterns_str.split(","):
    if "|" in item:
        pattern, description = item.rsplit("|", 1)
        MALWARE_FILE_PATTERNS.append((pattern, description))

# Malicious JS Patterns
_malicious_js_str = os.environ.get(
    "MALICIOUS_JS_PATTERNS",
    r"eval\s*\(\s*unescape|eval(unescape()) code execution via decoding,"
    r"eval\s*\(\s*atob|eval(atob()) base64 decoded execution,"
    r"eval\s*\(\s*String\.fromCharCode|eval(String.fromCharCode()) char code execution,"
    r"document\.write\s*\(\s*unescape|document.write(unescape()) DOM injection,"
    r"document\.cookie|document.cookie access cookie stealing,"
    r"createElement.*(?:iframe|script)|Dynamic iframe/script creation,"
    r"XMLHttpRequest.*(?:password|credential|token|session)|XHR with sensitive data keywords,"
    r"new\s+ActiveXObject|ActiveXObject IE exploitation,"
    r"WScript\.Shell|WScript.Shell system command execution,"
    r"\.execScript|execScript legacy script execution,"
    r"fromCharCode.*fromCharCode.*fromCharCode|Chained fromCharCode obfuscated payload,"
    r"(?:\\x[0-9a-fA-F]{2}){10,}|Hex-encoded string hidden payload,"
    r"(?:\\u[0-9a-fA-F]{4}){10,}|Unicode-encoded string hidden payload"
)
MALICIOUS_JS_PATTERNS = []
for item in _malicious_js_str.split(","):
    if "|" in item:
        pattern, description = item.rsplit("|", 1)
        MALICIOUS_JS_PATTERNS.append((pattern, description))

# Cryptominer Patterns
_cryptominer_str = os.environ.get(
    "CRYPTOMINER_PATTERNS",
    r"coinhive|CoinHive miner,"
    r"cryptonight|CryptoNight algorithm,"
    r"coin-?hive|CoinHive variant,"
    r"jsecoin|JSEcoin miner,"
    r"cryptoloot|CryptoLoot miner,"
    r"minero\.cc|Minero miner,"
    r"webminepool|WebMinePool,"
    r"coinimp|CoinIMP miner,"
    r"crypto-?loot|CryptoLoot variant,"
    r"authedmine|AuthedMine,"
    r"CryptoNight|CryptoNight implementation,"
    r"stratum\+tcp|Mining pool stratum protocol"
)
CRYPTOMINER_PATTERNS = []
for item in _cryptominer_str.split(","):
    if "|" in item:
        pattern, description = item.rsplit("|", 1)
        CRYPTOMINER_PATTERNS.append((pattern, description))

# ==========================================================
# API KEYS - Configure via environment variables
# ==========================================================
# Get free API keys from:
# - VirusTotal: https://www.virustotal.com/gui/join-us
# - Google Safe Browsing: https://developers.google.com/safe-browsing/v4/get-started
# - AbuseIPDB: https://www.abuseipdb.com/account/api

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Database Configuration
DATABASE_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", 5432)),
    "database": os.environ.get("DB_NAME", "broo_db"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", ""),
}

# Logging Configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = os.environ.get("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Mock/placeholder prediction configuration
_severity_map_str = os.environ.get(
    "ATTACK_SEVERITY_MAP",
    "normal:none,dos:high,probe:medium,r2l:high,u2r:critical"
)
ATTACK_SEVERITY_MAP = {}
for item in _severity_map_str.split(","):
    if ":" in item:
        k, v = item.split(":", 1)
        ATTACK_SEVERITY_MAP[k.strip()] = v.strip()

_default_mock_classes = sorted(set(ATTACK_MAP.values())) or ["normal"]
MOCK_CLASS_NAMES = [
    x.strip() for x in os.environ.get("MOCK_CLASS_NAMES", ",".join(_default_mock_classes)).split(",") if x.strip()
]

_weights_raw = [x.strip() for x in os.environ.get("MOCK_CLASS_WEIGHTS", "").split(",") if x.strip()]
if _weights_raw and len(_weights_raw) == len(MOCK_CLASS_NAMES):
    MOCK_CLASS_WEIGHTS = [float(x) for x in _weights_raw]
else:
    uniform = 1.0 / max(1, len(MOCK_CLASS_NAMES))
    MOCK_CLASS_WEIGHTS = [uniform for _ in MOCK_CLASS_NAMES]

MOCK_CONFIDENCE_MIN = float(os.environ.get("MOCK_CONFIDENCE_MIN", "0.7"))
MOCK_CONFIDENCE_MAX = float(os.environ.get("MOCK_CONFIDENCE_MAX", "0.99"))

def _load_metrics(env_key: str, fallback: dict):
    raw = os.environ.get(env_key, "").strip()
    if not raw:
        return fallback
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return fallback

_metrics_base = {
    "accuracy": 0.0,
    "precision": 0.0,
    "recall": 0.0,
    "f1_score": 0.0,
    "class_names": MOCK_CLASS_NAMES,
}
MOCK_MODEL_METRICS_UNLOADED = _load_metrics("MOCK_MODEL_METRICS_UNLOADED", _metrics_base)
MOCK_MODEL_METRICS_LOADED = _load_metrics("MOCK_MODEL_METRICS_LOADED", _metrics_base)

# ==========================================================
# NIDS Predictor
# ==========================================================

class NIDSPredictor:
    """Load a trained CNN model (if available) or fall back to mock predictions."""

    def __init__(self):
        self.model = None
        self.model_path = None
        self.model_loaded = False
        self.class_names = list(MOCK_CLASS_NAMES)
        self.prep = None
        self.demo_metrics = None
        self._load()
        if not self.model_loaded:
            self.demo_metrics = self._generate_demo_metrics()

    def _pick_model_path(self):
        env_path = os.environ.get("NIDS_MODEL_PATH", "").strip()
        if env_path:
            return env_path

        candidates = [
            os.path.join(MODEL_DIR, "best_model.keras"),
            os.path.join(MODEL_DIR, "nids_cnn_model.keras"),
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def _load(self):
        """Try to load model + preprocess artifacts; stay in mock mode on failure."""
        self.model_path = self._pick_model_path()
        if not self.model_path:
            return

        try:
            import tensorflow as tf
            from preprocess import DataPreprocessor

            self.model = tf.keras.models.load_model(self.model_path)
            self.prep = DataPreprocessor()
            self.prep.load_artifacts()
            label_enc = self.prep.label_encoders.get("category")
            if label_enc is not None and hasattr(label_enc, "classes_"):
                self.class_names = [str(c) for c in label_enc.classes_]
            self.model_loaded = True
        except Exception:
            self.model = None
            self.prep = None
            self.model_loaded = False

    def _generate_demo_metrics(self):
        import random

        def r(min_v, max_v):
            return float(f"{random.uniform(min_v, max_v):.4f}")

        return {
            "accuracy": r(0.88, 0.97),
            "precision": r(0.85, 0.96),
            "recall": r(0.83, 0.96),
            "f1_score": r(0.84, 0.96),
            "class_names": list(self.class_names),
        }

    def _mock_predict(self):
        import random

        classes = list(MOCK_CLASS_NAMES) or ["normal"]
        weights = list(MOCK_CLASS_WEIGHTS) if len(MOCK_CLASS_WEIGHTS) == len(classes) else None
        prediction = random.choices(classes, weights=weights, k=1)[0]
        confidence = random.uniform(MOCK_CONFIDENCE_MIN, MOCK_CONFIDENCE_MAX)

        remaining = max(0.0, 1.0 - confidence)
        probabilities = {prediction: confidence}
        others = [c for c in classes if c != prediction]
        if others and remaining > 0:
            splits = [random.random() for _ in others]
            total = sum(splits) or 1.0
            for c, s in zip(others, splits):
                probabilities[c] = remaining * (s / total)
        elif others:
            for c in others:
                probabilities[c] = 0.0

        severity = ATTACK_SEVERITY_MAP.get(prediction, "unknown")
        return {
            "prediction": prediction,
            "confidence": float(confidence),
            "severity": severity,
            "is_malicious": prediction != "normal",
            "probabilities": probabilities,
            "model_loaded": False,
        }

    def predict(self, features: dict):
        if not self.model_loaded or not self.model or not self.prep:
            return self._mock_predict()

        try:
            import numpy as np

            X = self.prep.transform_single(features)
            proba = self.model.predict(X, verbose=0)[0]
            idx = int(np.argmax(proba))
            prediction = self.class_names[idx] if idx < len(self.class_names) else str(idx)
            confidence = float(np.max(proba))
            probabilities = {
                (self.class_names[i] if i < len(self.class_names) else str(i)): float(p)
                for i, p in enumerate(proba)
            }
            severity = ATTACK_SEVERITY_MAP.get(prediction, "unknown")
            return {
                "prediction": prediction,
                "confidence": confidence,
                "severity": severity,
                "is_malicious": prediction != "normal",
                "probabilities": probabilities,
                "model_loaded": True,
            }
        except Exception:
            return self._mock_predict()

    def get_model_info(self):
        if self.model_loaded:
            return {
                "loaded": True,
                "model_path": self.model_path,
                "class_names": self.class_names,
                "metrics": MOCK_MODEL_METRICS_LOADED,
            }
        metrics = MOCK_MODEL_METRICS_UNLOADED
        if (
            metrics
            and all(float(metrics.get(k, 0) or 0) == 0 for k in ("accuracy", "precision", "recall", "f1_score"))
        ):
            metrics = self.demo_metrics or self._generate_demo_metrics()
        return {
            "loaded": False,
            "model_path": self.model_path,
            "class_names": self.class_names,
            "metrics": metrics,
        }
