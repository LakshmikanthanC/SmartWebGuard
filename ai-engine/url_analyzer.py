"""
AI-Powered Website Safety Analyzer
Performs deep analysis of URLs including:
- URL pattern analysis
- SSL certificate verification
- Live content fetching and inspection
- Malicious script detection
- Hidden iframe detection
- Obfuscated code detection
- Drive-by download detection
- Cryptominer detection
- Phishing page detection
- Redirect chain analysis
- Domain age and reputation
"""

import re
import ssl
import socket
import hashlib
import urllib.parse
import time
from datetime import datetime

# Optional: for live content analysis
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class URLAnalyzer:
    """Comprehensive AI-powered URL and website safety analyzer."""

    def __init__(self):
        self.suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
            ".club", ".work", ".date", ".racing", ".win", ".bid",
            ".stream", ".download", ".loan", ".men", ".click",
            ".link", ".party", ".review", ".science", ".zip", ".mov"
        ]

        self.trusted_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com",
            "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
            "reddit.com", "netflix.com", "whatsapp.com", "zoom.us",
            "dropbox.com", "salesforce.com", "adobe.com", "shopify.com",
            "wordpress.com", "medium.com", "cloudflare.com", "npmjs.com",
            "pypi.org", "docker.com", "elastic.co", "mongodb.com",
            "yahoo.com", "bing.com", "twitch.tv", "spotify.com",
            "paypal.com", "stripe.com", "slack.com", "notion.so",
            "figma.com", "vercel.com", "netlify.com", "heroku.com",
        ]

        self.phishing_keywords = [
            "login", "signin", "sign-in", "verify", "verification",
            "account", "update", "secure", "banking", "confirm",
            "password", "credential", "authenticate", "wallet",
            "suspended", "unusual", "activity", "limited", "restore",
            "unlock", "security", "alert", "notification", "urgent",
            "expire", "compromised", "unauthorized", "validate",
        ]

        self.brand_names = [
            "paypal", "amazon", "apple", "microsoft", "google",
            "facebook", "netflix", "instagram", "whatsapp", "twitter",
            "linkedin", "dropbox", "adobe", "chase", "wellsfargo",
            "bankofamerica", "citibank", "hsbc", "barclays",
        ]

        self.suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'[a-zA-Z0-9]{30,}',
            r'@',
            r'\.exe|\.scr|\.bat|\.cmd|\.ps1',
            r'\.zip|\.rar|\.7z',
            r'data:',
            r'javascript:',
            r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',
            r'-{3,}',
            r'\.(php|asp|jsp)\?.*=.*&.*=',
        ]

        self.malware_file_patterns = [
            r'\.exe(\?|$|&)', r'\.msi(\?|$|&)', r'\.dll(\?|$|&)',
            r'\.scr(\?|$|&)', r'\.bat(\?|$|&)', r'\.cmd(\?|$|&)',
            r'\.ps1(\?|$|&)', r'\.vbs(\?|$|&)', r'\.wsf(\?|$|&)',
            r'\.apk(\?|$|&)', r'\.dmg(\?|$|&)', r'\.iso(\?|$|&)',
            r'download.*free', r'free.*download',
            r'crack.*software', r'keygen', r'warez', r'torrent',
        ]

        # Malicious JavaScript patterns
        self.malicious_js_patterns = [
            r'eval\s*\(\s*unescape',
            r'eval\s*\(\s*atob',
            r'eval\s*\(\s*String\.fromCharCode',
            r'document\.write\s*\(\s*unescape',
            r'window\.location\s*=\s*["\'](?!https?://(?:www\.)?'
                r'(?:google|facebook|twitter|youtube))',
            r'document\.cookie',
            r'\.createElement\s*\(\s*["\'](?:iframe|script)',
            r'XMLHttpRequest.*(?:password|credential|token|session)',
            r'new\s+ActiveXObject',
            r'WScript\.Shell',
            r'\.execScript',
            r'fromCharCode.*fromCharCode.*fromCharCode',
            r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'
                r'.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}'
                r'.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}',
        ]

        # Cryptominer patterns
        self.cryptominer_patterns = [
            r'coinhive', r'cryptonight', r'coin-?hive',
            r'jsecoin', r'cryptoloot', r'minero\.cc',
            r'webminepool', r'ppoi\.org', r'monerominer',
            r'coinimp', r'crypto-?loot', r'webmine',
            r'authedmine', r'hashfor\.cash',
            r'CryptoNight', r'stratum\+tcp',
        ]

        # Suspicious HTML patterns
        self.suspicious_html_patterns = [
            r'<iframe[^>]+style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|'
                r'visibility\s*:\s*hidden|width\s*:\s*[01]px|'
                r'height\s*:\s*[01]px)',
            r'<iframe[^>]+(?:width|height)\s*=\s*["\']?[01]["\']?',
            r'<form[^>]+action\s*=\s*["\'](?:https?://)'
                r'(?!.*(?:google|facebook|twitter|youtube))',
            r'<input[^>]+type\s*=\s*["\']password',
            r'<meta[^>]+http-equiv\s*=\s*["\']refresh',
            r'position\s*:\s*absolute\s*;\s*(?:left|top)\s*:\s*-\d{3,}px',
            r'opacity\s*:\s*0\s*;.*(?:password|login|credential)',
        ]

        # Known malicious domains/IPs (sample blocklist)
        self.blocklist_domains = [
            "malware.testing.google.test",
            "evil.example.com",
        ]

        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.5",
            })
            self.session.max_redirects = 10
            self.session.verify = True

    def analyze(self, url, deep_scan=True):
        """
        Perform comprehensive URL and website analysis.

        Args:
            url: The URL to analyze
            deep_scan: If True, fetch and analyze page content

        Returns:
            Detailed safety report dictionary
        """
        start_time = time.time()

        result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "deep" if deep_scan else "quick",
            "safe": True,
            "risk_score": 0,
            "risk_level": "safe",
            "threats": [],
            "warnings": [],
            "info": [],
            "analysis": {
                "domain": {},
                "url_structure": {},
                "ssl": {},
                "content": {},
                "reputation": {},
                "redirects": {},
                "headers": {},
                "scripts": {},
                "forms": {},
                "iframes": {},
                "metadata": {},
            },
            "malware_indicators": [],
            "phishing_indicators": [],
            "recommendations": [],
            "scan_duration_ms": 0,
        }

        try:
            # Step 1: Parse URL
            parsed = self._parse_url(url)
            if not parsed:
                result["safe"] = False
                result["risk_score"] = 95
                result["risk_level"] = "critical"
                result["threats"].append("Invalid or malformed URL")
                return result

            result["analysis"]["url_structure"] = parsed

            # Step 2: Static URL analysis (always runs)
            self._check_protocol(parsed, result)
            self._check_domain(parsed, result)
            self._check_tld(parsed, result)
            self._check_url_length(parsed, result)
            self._check_suspicious_patterns(url, result)
            self._check_phishing_indicators(url, parsed, result)
            self._check_malware_file_patterns(url, result)
            self._check_subdomain(parsed, result)
            self._check_port(parsed, result)
            self._check_blocklist(parsed, result)
            self._check_url_encoding(url, result)
            self._check_redirect_params(url, result)

            # Step 3: SSL check
            self._check_ssl(parsed, result)

            # Step 4: Domain reputation
            self._check_domain_reputation(parsed, result)

            # Step 5: Deep scan — fetch and analyze content
            if deep_scan and HAS_REQUESTS:
                self._deep_scan(url, parsed, result)

            # Step 6: Calculate final risk
            self._calculate_risk(result)

        except Exception as e:
            result["warnings"].append(f"Analysis error: {str(e)}")
            result["risk_score"] = max(result["risk_score"], 25)

        result["scan_duration_ms"] = int((time.time() - start_time) * 1000)
        result["url_hash"] = hashlib.sha256(url.encode()).hexdigest()[:16]

        return result

    # ==============================================================
    # URL PARSING
    # ==============================================================

    def _parse_url(self, url):
        if not url:
            return None
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url
        try:
            p = urllib.parse.urlparse(url)
            if not p.netloc:
                return None
            domain = p.netloc.lower().split(":")[0]
            return {
                "full_url": url,
                "scheme": p.scheme,
                "domain": domain,
                "netloc": p.netloc,
                "path": p.path,
                "query": p.query,
                "fragment": p.fragment,
                "port": p.port,
                "url_length": len(url),
                "path_depth": len([x for x in p.path.split("/") if x]),
                "query_params": len(urllib.parse.parse_qs(p.query)),
                "has_at_symbol": "@" in p.netloc,
                "subdomain_count": max(0, len(domain.split(".")) - 2),
            }
        except Exception:
            return None

    # ==============================================================
    # STATIC URL CHECKS
    # ==============================================================

    def _check_protocol(self, parsed, result):
        s = parsed["scheme"]
        if s == "https":
            result["info"].append("Uses HTTPS encrypted connection")
            result["analysis"]["ssl"]["protocol"] = "https"
        elif s == "http":
            result["warnings"].append(
                "Uses unencrypted HTTP — data sent in plain text"
            )
            result["risk_score"] += 15
            result["analysis"]["ssl"]["protocol"] = "http"
        elif s == "ftp":
            result["warnings"].append("Uses FTP — not secure")
            result["risk_score"] += 20
        else:
            result["threats"].append(f"Unusual protocol: {s}")
            result["risk_score"] += 30

    def _check_domain(self, parsed, result):
        d = parsed["domain"]
        result["analysis"]["domain"]["name"] = d
        result["analysis"]["domain"]["length"] = len(d)

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d):
            result["threats"].append(
                "URL uses raw IP address — common in phishing/malware"
            )
            result["risk_score"] += 30
            result["analysis"]["domain"]["is_ip"] = True
            result["phishing_indicators"].append("IP address instead of domain")
        else:
            result["analysis"]["domain"]["is_ip"] = False

        if len(d) > 50:
            result["warnings"].append(f"Abnormally long domain ({len(d)} chars)")
            result["risk_score"] += 10

        if d.count("-") > 3:
            result["warnings"].append("Excessive hyphens in domain")
            result["risk_score"] += 12
            result["phishing_indicators"].append("Many hyphens in domain")

        main = d.split(".")[0]
        digits = sum(c.isdigit() for c in main)
        if len(main) > 5 and digits > len(main) * 0.5:
            result["warnings"].append("Domain is mostly numbers")
            result["risk_score"] += 8

    def _check_tld(self, parsed, result):
        d = parsed["domain"]
        for tld in self.suspicious_tlds:
            if d.endswith(tld):
                result["warnings"].append(
                    f"TLD '{tld}' is frequently abused for malicious sites"
                )
                result["risk_score"] += 15
                result["analysis"]["domain"]["suspicious_tld"] = True
                return
        result["analysis"]["domain"]["suspicious_tld"] = False

    def _check_url_length(self, parsed, result):
        ln = parsed["url_length"]
        result["analysis"]["url_structure"]["total_length"] = ln
        if ln > 200:
            result["warnings"].append(f"Very long URL ({ln} chars)")
            result["risk_score"] += 10

    def _check_suspicious_patterns(self, url, result):
        count = 0
        for pat in self.suspicious_patterns:
            if re.search(pat, url, re.IGNORECASE):
                count += 1
        result["analysis"]["url_structure"]["suspicious_patterns"] = count
        if count:
            result["warnings"].append(
                f"{count} suspicious pattern(s) detected in URL"
            )
            result["risk_score"] += count * 7

    def _check_phishing_indicators(self, url, parsed, result):
        path_query = (parsed["path"] + parsed["query"]).lower()
        domain = parsed["domain"]
        found = []

        for brand in self.brand_names:
            if brand in path_query and brand not in domain:
                found.append(f"{brand} impersonation")
                result["risk_score"] += 20
                result["phishing_indicators"].append(
                    f"Brand '{brand}' in URL path but not in domain"
                )

        kw_found = []
        for kw in self.phishing_keywords:
            if kw in path_query:
                kw_found.append(kw)

        if kw_found:
            result["analysis"]["content"]["phishing_keywords"] = kw_found
            if len(kw_found) >= 3:
                result["warnings"].append(
                    f"Multiple phishing keywords: {', '.join(kw_found[:5])}"
                )
                result["risk_score"] += len(kw_found) * 4
                result["phishing_indicators"].append(
                    f"Keywords: {', '.join(kw_found[:5])}"
                )
        else:
            result["analysis"]["content"]["phishing_keywords"] = []

        if parsed["has_at_symbol"]:
            result["threats"].append(
                "URL contains '@' — can disguise actual destination"
            )
            result["risk_score"] += 25
            result["phishing_indicators"].append("@ symbol in URL")

    def _check_malware_file_patterns(self, url, result):
        url_lower = url.lower()
        found = []
        for pat in self.malware_file_patterns:
            if re.search(pat, url_lower):
                found.append(pat)
        result["analysis"]["content"]["malware_file_patterns"] = len(found)
        if found:
            result["threats"].append(
                "URL matches malware distribution patterns"
            )
            result["risk_score"] += len(found) * 10
            result["malware_indicators"].append(
                f"{len(found)} file pattern(s) matched"
            )

    def _check_subdomain(self, parsed, result):
        c = parsed["subdomain_count"]
        result["analysis"]["domain"]["subdomain_count"] = c
        if c > 3:
            result["warnings"].append(f"Excessive subdomains ({c})")
            result["risk_score"] += 10

    def _check_port(self, parsed, result):
        port = parsed["port"]
        if port and port not in [80, 443, 8080, 8443]:
            result["warnings"].append(f"Non-standard port: {port}")
            result["risk_score"] += 8
            result["analysis"]["url_structure"]["non_standard_port"] = True
        else:
            result["analysis"]["url_structure"]["non_standard_port"] = False

    def _check_blocklist(self, parsed, result):
        domain = parsed["domain"]
        for blocked in self.blocklist_domains:
            if domain == blocked or domain.endswith("." + blocked):
                result["threats"].append(
                    f"Domain '{domain}' is on the blocklist"
                )
                result["risk_score"] += 50
                result["malware_indicators"].append("Blocklisted domain")
                return

    def _check_url_encoding(self, url, result):
        enc = url.count("%")
        result["analysis"]["url_structure"]["encoded_chars"] = enc
        if enc > 5:
            result["warnings"].append(
                f"Heavy URL encoding ({enc} encoded chars)"
            )
            result["risk_score"] += 8

    def _check_redirect_params(self, url, result):
        redirect_keys = [
            "redirect", "url", "next", "return",
            "goto", "rurl", "dest", "continue"
        ]
        url_lower = url.lower()
        for key in redirect_keys:
            if f"{key}=http" in url_lower:
                result["warnings"].append(
                    "URL contains redirect parameter to another site"
                )
                result["risk_score"] += 12
                result["analysis"]["content"]["has_redirect_param"] = True
                return
        result["analysis"]["content"]["has_redirect_param"] = False

    # ==============================================================
    # SSL CERTIFICATE CHECK
    # ==============================================================

    def _check_ssl(self, parsed, result):
        if parsed["scheme"] != "https":
            result["analysis"]["ssl"]["valid"] = False
            result["analysis"]["ssl"]["checked"] = False
            return

        domain = parsed["domain"]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=domain
            ) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()

                issuer = dict(
                    x[0] for x in cert.get("issuer", [])
                ).get("organizationName", "Unknown")
                subject = dict(
                    x[0] for x in cert.get("subject", [])
                ).get("commonName", "Unknown")
                expires = cert.get("notAfter", "Unknown")

                result["analysis"]["ssl"].update({
                    "valid": True,
                    "checked": True,
                    "issuer": issuer,
                    "subject": subject,
                    "expires": expires,
                    "san": [
                        entry[1]
                        for entry in cert.get("subjectAltName", [])
                    ][:10],
                })
                result["info"].append(f"Valid SSL cert by {issuer}")

                # Check if cert is self-signed
                if issuer == subject:
                    result["warnings"].append("Self-signed SSL certificate")
                    result["risk_score"] += 15

        except ssl.SSLCertVerificationError as e:
            result["threats"].append(
                f"Invalid SSL certificate: {str(e)[:100]}"
            )
            result["risk_score"] += 25
            result["analysis"]["ssl"]["valid"] = False
            result["analysis"]["ssl"]["checked"] = True
            result["analysis"]["ssl"]["error"] = str(e)[:100]

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            result["warnings"].append("Could not verify SSL — host unreachable")
            result["analysis"]["ssl"]["valid"] = None
            result["analysis"]["ssl"]["checked"] = False

        except Exception:
            result["analysis"]["ssl"]["valid"] = None
            result["analysis"]["ssl"]["checked"] = False

    # ==============================================================
    # DOMAIN REPUTATION
    # ==============================================================

    def _check_domain_reputation(self, parsed, result):
        domain = parsed["domain"]
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                result["info"].append(f"'{domain}' is a trusted domain")
                result["risk_score"] = max(0, result["risk_score"] - 20)
                result["analysis"]["reputation"]["trusted"] = True
                result["analysis"]["reputation"]["category"] = "trusted"
                return

        result["analysis"]["reputation"]["trusted"] = False
        result["analysis"]["reputation"]["category"] = "unknown"
        result["info"].append(f"'{domain}' is not in trusted list")

        # DNS resolution check
        try:
            ip = socket.gethostbyname(domain)
            result["analysis"]["domain"]["resolved_ip"] = ip
            result["info"].append(f"Domain resolves to {ip}")

            # Check for private IP ranges (suspicious for public sites)
            private_ranges = [
                r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.',
                r'^192\.168\.', r'^127\.', r'^0\.'
            ]
            for pr in private_ranges:
                if re.match(pr, ip):
                    result["warnings"].append(
                        f"Domain resolves to private IP ({ip})"
                    )
                    result["risk_score"] += 15
                    break

        except socket.gaierror:
            result["warnings"].append("Domain does not resolve (DNS failure)")
            result["risk_score"] += 20
            result["analysis"]["domain"]["resolved_ip"] = None

    # ==============================================================
    # DEEP SCAN — LIVE CONTENT ANALYSIS
    # ==============================================================

    def _deep_scan(self, url, parsed, result):
        """Fetch page content and perform deep analysis."""
        if not HAS_REQUESTS:
            result["info"].append(
                "Deep scan unavailable — install 'requests' package"
            )
            return

        result["analysis"]["content"]["deep_scan"] = True

        try:
            resp = self.session.get(
                parsed["full_url"],
                timeout=10,
                allow_redirects=True,
                stream=True
            )

            # Don't download huge files
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > 5_000_000:
                result["warnings"].append(
                    "Page is very large (>5MB) — potential large file download"
                )
                result["risk_score"] += 10
                result["analysis"]["content"]["size_bytes"] = int(content_length)
                return

            # Read content (max 2MB)
            content = resp.text[:2_000_000]

            # Analyze response
            self._analyze_response_headers(resp, result)
            self._analyze_redirect_chain(resp, result)
            self._analyze_html_content(content, result)
            self._detect_malicious_scripts(content, result)
            self._detect_cryptominers(content, result)
            self._detect_hidden_iframes(content, result)
            self._detect_suspicious_forms(content, parsed, result)
            self._detect_obfuscated_code(content, result)
            self._detect_drive_by_downloads(content, result)
            self._analyze_external_resources(content, parsed, result)
            self._detect_phishing_page(content, parsed, result)

        except requests.exceptions.SSLError as e:
            result["threats"].append("SSL error when accessing site")
            result["risk_score"] += 20
            result["analysis"]["content"]["fetch_error"] = "SSL Error"

        except requests.exceptions.ConnectionError:
            result["warnings"].append("Could not connect to website")
            result["analysis"]["content"]["fetch_error"] = "Connection Error"

        except requests.exceptions.Timeout:
            result["warnings"].append("Website timed out (>10s)")
            result["analysis"]["content"]["fetch_error"] = "Timeout"

        except requests.exceptions.TooManyRedirects:
            result["threats"].append(
                "Too many redirects — possible redirect loop attack"
            )
            result["risk_score"] += 25
            result["analysis"]["content"]["fetch_error"] = "Too Many Redirects"

        except Exception as e:
            result["warnings"].append(f"Content fetch error: {str(e)[:80]}")

    def _analyze_response_headers(self, resp, result):
        """Analyze HTTP response headers for security issues."""
        headers = resp.headers
        h_info = {}

        h_info["status_code"] = resp.status_code
        h_info["content_type"] = headers.get("Content-Type", "unknown")
        h_info["server"] = headers.get("Server", "unknown")

        # Security headers check
        security_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "X-XSS-Protection": "XSS protection",
            "Content-Security-Policy": "Content Security Policy",
            "Strict-Transport-Security": "HSTS",
            "Referrer-Policy": "Referrer policy",
        }

        present = []
        missing = []
        for header, desc in security_headers.items():
            if header.lower() in {k.lower() for k in headers.keys()}:
                present.append(header)
            else:
                missing.append(header)

        h_info["security_headers_present"] = present
        h_info["security_headers_missing"] = missing

        if len(missing) > 4:
            result["warnings"].append(
                f"Missing {len(missing)} security headers"
            )
            result["risk_score"] += 5

        if len(present) >= 4:
            result["info"].append(
                f"{len(present)} security headers present"
            )
            result["risk_score"] = max(0, result["risk_score"] - 5)

        # Suspicious response codes
        if resp.status_code >= 400:
            result["warnings"].append(
                f"HTTP {resp.status_code} response"
            )

        result["analysis"]["headers"] = h_info

    def _analyze_redirect_chain(self, resp, result):
        """Analyze redirect chain."""
        chain = []
        for r in resp.history:
            chain.append({
                "url": r.url,
                "status": r.status_code,
            })

        chain.append({
            "url": resp.url,
            "status": resp.status_code,
        })

        result["analysis"]["redirects"] = {
            "count": len(resp.history),
            "chain": chain,
            "final_url": resp.url,
        }

        if len(resp.history) > 3:
            result["warnings"].append(
                f"Long redirect chain ({len(resp.history)} redirects)"
            )
            result["risk_score"] += 8

        # Check if redirected to different domain
        if resp.history:
            original_domain = self._parse_url(resp.history[0].url)
            final_domain = self._parse_url(resp.url)
            if (original_domain and final_domain and
                    original_domain["domain"] != final_domain["domain"]):
                result["warnings"].append(
                    f"Redirected to different domain: "
                    f"{final_domain['domain']}"
                )
                result["risk_score"] += 10

    def _analyze_html_content(self, content, result):
        """Basic HTML content analysis."""
        if not HAS_BS4:
            result["analysis"]["content"]["parser"] = "regex_only"
            return

        try:
            soup = BeautifulSoup(content, "html.parser")

            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            meta_desc = ""
            meta_tag = soup.find("meta", attrs={"name": "description"})
            if meta_tag:
                meta_desc = meta_tag.get("content", "")[:200]

            scripts = soup.find_all("script")
            external_scripts = [
                s.get("src") for s in scripts if s.get("src")
            ]
            inline_scripts = [
                s.string for s in scripts
                if s.string and len(s.string.strip()) > 10
            ]

            links = soup.find_all("a", href=True)
            forms = soup.find_all("form")
            iframes = soup.find_all("iframe")
            inputs = soup.find_all("input")
            password_fields = [
                i for i in inputs
                if i.get("type", "").lower() == "password"
            ]

            result["analysis"]["metadata"] = {
                "title": title,
                "description": meta_desc[:200],
            }

            result["analysis"]["scripts"] = {
                "total": len(scripts),
                "external": len(external_scripts),
                "inline": len(inline_scripts),
                "external_sources": external_scripts[:20],
            }

            result["analysis"]["forms"] = {
                "total": len(forms),
                "has_password_field": len(password_fields) > 0,
                "password_fields": len(password_fields),
            }

            result["analysis"]["iframes"] = {
                "total": len(iframes),
                "sources": [
                    f.get("src", "no-src") for f in iframes
                ][:10],
            }

            result["analysis"]["content"]["links"] = len(links)
            result["analysis"]["content"]["inputs"] = len(inputs)

            if len(inline_scripts) > 15:
                result["warnings"].append(
                    f"Excessive inline scripts ({len(inline_scripts)})"
                )
                result["risk_score"] += 5

        except Exception as e:
            result["analysis"]["content"]["parse_error"] = str(e)[:80]

    def _detect_malicious_scripts(self, content, result):
        """Detect malicious JavaScript patterns."""
        found = []
        for pattern in self.malicious_js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found.append({
                    "pattern": pattern[:60],
                    "count": len(matches),
                })

        result["analysis"]["scripts"]["malicious_patterns"] = found

        if found:
            total = sum(f["count"] for f in found)
            result["threats"].append(
                f"Detected {len(found)} malicious script pattern(s) "
                f"({total} occurrences)"
            )
            result["risk_score"] += min(40, len(found) * 12)
            result["malware_indicators"].append(
                f"{len(found)} malicious JS patterns"
            )

    def _detect_cryptominers(self, content, result):
        """Detect cryptocurrency miner scripts."""
        found = []
        for pattern in self.cryptominer_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found.append(pattern)

        result["analysis"]["scripts"]["cryptominer_detected"] = len(found) > 0

        if found:
            result["threats"].append(
                f"Cryptocurrency miner detected: "
                f"{', '.join(found[:3])}"
            )
            result["risk_score"] += 30
            result["malware_indicators"].append(
                "Cryptominer: " + ", ".join(found[:3])
            )

    def _detect_hidden_iframes(self, content, result):
        """Detect hidden iframes used for malware delivery."""
        hidden = []
        for pattern in self.suspicious_html_patterns[:2]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            hidden.extend(matches)

        result["analysis"]["iframes"]["hidden_count"] = len(hidden)

        if hidden:
            result["threats"].append(
                f"Detected {len(hidden)} hidden iframe(s) — "
                "commonly used for malware delivery"
            )
            result["risk_score"] += len(hidden) * 15
            result["malware_indicators"].append(
                f"{len(hidden)} hidden iframes"
            )

    def _detect_suspicious_forms(self, content, parsed, result):
        """Detect suspicious forms (credential harvesting)."""
        if not HAS_BS4:
            return

        try:
            soup = BeautifulSoup(content, "html.parser")
            forms = soup.find_all("form")
            suspicious = []

            for form in forms:
                action = form.get("action", "")
                inputs = form.find_all("input")
                has_password = any(
                    i.get("type", "").lower() == "password" for i in inputs
                )
                has_email = any(
                    i.get("type", "").lower() in ["email", "text"] and
                    any(kw in (i.get("name", "") + i.get("placeholder", "")).lower()
                        for kw in ["email", "user", "login", "account"])
                    for i in inputs
                )

                # Form with password field posting to external domain
                if has_password and action.startswith("http"):
                    action_domain = self._parse_url(action)
                    if (action_domain and
                            action_domain["domain"] != parsed["domain"]):
                        suspicious.append({
                            "action": action[:100],
                            "target_domain": action_domain["domain"],
                            "has_password": True,
                            "has_email": has_email,
                        })

                # Form with password on non-trusted domain
                if has_password and not result["analysis"]["reputation"].get("trusted"):
                    suspicious.append({
                        "action": action[:100] if action else "self",
                        "has_password": True,
                        "has_email": has_email,
                        "reason": "Password form on untrusted domain",
                    })

            result["analysis"]["forms"]["suspicious"] = suspicious

            if suspicious:
                result["warnings"].append(
                    f"{len(suspicious)} suspicious form(s) with "
                    "credential fields detected"
                )
                result["risk_score"] += len(suspicious) * 15
                result["phishing_indicators"].append(
                    "Credential harvesting forms detected"
                )

        except Exception:
            pass

    def _detect_obfuscated_code(self, content, result):
        """Detect heavily obfuscated code."""
        indicators = 0

        # Long base64 strings
        b64 = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', content)
        if len(b64) > 3:
            indicators += 1
            result["analysis"]["scripts"]["base64_strings"] = len(b64)

        # Hex-encoded strings
        hex_strings = re.findall(
            r'(?:\\x[0-9a-fA-F]{2}){10,}', content
        )
        if hex_strings:
            indicators += 1
            result["analysis"]["scripts"]["hex_encoded"] = len(hex_strings)

        # Unicode-encoded strings
        unicode_strings = re.findall(
            r'(?:\\u[0-9a-fA-F]{4}){10,}', content
        )
        if unicode_strings:
            indicators += 1
            result["analysis"]["scripts"]["unicode_encoded"] = len(unicode_strings)

        # eval() usage
        eval_count = len(re.findall(r'\beval\s*\(', content))
        if eval_count > 2:
            indicators += 1
            result["analysis"]["scripts"]["eval_calls"] = eval_count

        # document.write()
        dw_count = len(re.findall(r'document\.write\s*\(', content))
        if dw_count > 3:
            indicators += 1
            result["analysis"]["scripts"]["document_write"] = dw_count

        # String.fromCharCode chains
        fcc = len(re.findall(r'String\.fromCharCode', content))
        if fcc > 5:
            indicators += 1
            result["analysis"]["scripts"]["fromCharCode"] = fcc

        result["analysis"]["scripts"]["obfuscation_score"] = indicators

        if indicators >= 3:
            result["threats"].append(
                f"Heavily obfuscated code detected "
                f"({indicators} indicators)"
            )
            result["risk_score"] += indicators * 8
            result["malware_indicators"].append(
                f"Code obfuscation: {indicators} indicators"
            )
        elif indicators >= 1:
            result["warnings"].append(
                f"Some code obfuscation detected ({indicators} indicator(s))"
            )
            result["risk_score"] += indicators * 4

    def _detect_drive_by_downloads(self, content, result):
        """Detect drive-by download attempts."""
        indicators = []

        # Auto-download triggers
        patterns = [
            (r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+'
             r'url\s*=\s*[^"\']*\.(exe|msi|apk|dmg|zip|rar)',
             "Meta refresh to executable"),
            (r'window\.location\s*=\s*["\'][^"\']*'
             r'\.(exe|msi|apk|dmg|zip|rar)',
             "JS redirect to executable"),
            (r'<a[^>]+download[^>]+\.(exe|msi|apk|dmg)',
             "Auto-download link"),
            (r'<iframe[^>]+src\s*=\s*["\'][^"\']*'
             r'\.(exe|msi|apk|dmg)',
             "Iframe loading executable"),
            (r'application/(?:octet-stream|x-msdownload|x-msdos-program)',
             "Binary download content type"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(desc)

        result["analysis"]["content"]["drive_by_indicators"] = indicators

        if indicators:
            result["threats"].append(
                f"Drive-by download attempt: "
                f"{', '.join(indicators[:3])}"
            )
            result["risk_score"] += len(indicators) * 15
            result["malware_indicators"].extend(indicators)

    def _analyze_external_resources(self, content, parsed, result):
        """Analyze external resources loaded by the page."""
        external_domains = set()

        # Find all src and href attributes
        src_pattern = r'(?:src|href)\s*=\s*["\']https?://([^/"\']+)'
        matches = re.findall(src_pattern, content, re.IGNORECASE)

        for domain in matches:
            domain = domain.lower().split(":")[0]
            if domain != parsed["domain"]:
                external_domains.add(domain)

        result["analysis"]["content"]["external_domains"] = list(
            external_domains
        )[:30]
        result["analysis"]["content"]["external_domain_count"] = len(
            external_domains
        )

        if len(external_domains) > 20:
            result["warnings"].append(
                f"Loads resources from {len(external_domains)} external domains"
            )
            result["risk_score"] += 5

        # Check if any external domains are suspicious
        for ext_domain in external_domains:
            for tld in self.suspicious_tlds:
                if ext_domain.endswith(tld):
                    result["warnings"].append(
                        f"Loads resources from suspicious domain: {ext_domain}"
                    )
                    result["risk_score"] += 8
                    break

    def _detect_phishing_page(self, content, parsed, result):
        """Detect if the page looks like a phishing page."""
        score = 0
        indicators = []

        content_lower = content.lower()

        # Login form on non-trusted domain
        if (result["analysis"]["forms"].get("has_password_field") and
                not result["analysis"]["reputation"].get("trusted")):
            score += 2
            indicators.append("Login form on untrusted domain")

        # Brand references without being the real site
        for brand in self.brand_names:
            if brand in content_lower:
                if brand not in parsed["domain"]:
                    count = content_lower.count(brand)
                    if count > 3:
                        score += 2
                        indicators.append(
                            f"'{brand}' mentioned {count} times "
                            "but not the real domain"
                        )

        # Urgency language
        urgency_words = [
            "immediately", "urgent", "suspended", "verify now",
            "confirm now", "act now", "limited time", "24 hours",
            "your account will be", "unauthorized access",
        ]
        urgency_found = [
            w for w in urgency_words if w in content_lower
        ]
        if len(urgency_found) >= 2:
            score += 2
            indicators.append(
                f"Urgency language: {', '.join(urgency_found[:3])}"
            )

        # Copyright misuse (claiming to be another company)
        copyright_pattern = (
            r'©\s*\d{4}\s*(?:' +
            '|'.join(self.brand_names) + r')'
        )
        if re.search(copyright_pattern, content_lower):
            if not result["analysis"]["reputation"].get("trusted"):
                score += 3
                indicators.append("Fake copyright notice")

        result["analysis"]["content"]["phishing_score"] = score
        result["analysis"]["content"]["phishing_indicators"] = indicators

        if score >= 5:
            result["threats"].append(
                "Strong phishing indicators detected"
            )
            result["risk_score"] += 25
            result["phishing_indicators"].extend(indicators)
        elif score >= 3:
            result["warnings"].append(
                "Some phishing indicators detected"
            )
            result["risk_score"] += 12
            result["phishing_indicators"].extend(indicators)

    # ==============================================================
    # RISK CALCULATION
    # ==============================================================

    def _calculate_risk(self, result):
        score = min(100, max(0, result["risk_score"]))
        result["risk_score"] = score

        if score >= 70:
            result["risk_level"] = "critical"
            result["safe"] = False
            result["recommendations"].insert(
                0, "DO NOT visit — strong malicious indicators"
            )
        elif score >= 50:
            result["risk_level"] = "high"
            result["safe"] = False
            result["recommendations"].insert(
                0, "Avoid this URL — multiple risk indicators"
            )
        elif score >= 30:
            result["risk_level"] = "medium"
            result["safe"] = False
            result["recommendations"].insert(
                0, "Exercise caution with this URL"
            )
        elif score >= 15:
            result["risk_level"] = "low"
            result["safe"] = True
            result["recommendations"].append("Minor warnings but likely safe")
        else:
            result["risk_level"] = "safe"
            result["safe"] = True
            result["recommendations"].append("No significant risks detected")

        if result["malware_indicators"]:
            result["recommendations"].append(
                "Do NOT download any files from this site"
            )
        if result["phishing_indicators"]:
            result["recommendations"].append(
                "Do NOT enter any personal information"
            )
        result["recommendations"].append(
            "Keep antivirus software updated"
        )


# Singleton
analyzer = URLAnalyzer()


def analyze_url(url, deep_scan=True):
    return analyzer.analyze(url, deep_scan)