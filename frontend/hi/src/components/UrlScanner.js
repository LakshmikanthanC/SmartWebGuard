import React, { useState, useEffect, useCallback } from "react";
import {
  scanUrl,
  getUrlHistory,
  getUrlStats,
  deleteUrlScan,
} from "../services/api";
import {
  fmtDate,
  sevColor,
  sevBg,
} from "../utils/formatters";
import "./UrlScanner.css";

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPg, setHistoryPg] = useState({});
  const [activeTab, setActiveTab] = useState("scan"); // scan | history

  // Load history
  const loadHistory = useCallback(async () => {
    try {
      const { data } = await getUrlHistory({
        page: historyPage,
        limit: 10,
      });
      setHistory(data.scans);
      setHistoryPg(data.pagination);
    } catch (e) {
      console.error(e);
    }
  }, [historyPage]);

  // Load stats
  const loadStats = useCallback(async () => {
    try {
      const { data } = await getUrlStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    loadHistory();
    loadStats();
  }, [loadHistory, loadStats]);

  // Handle scan
  const handleScan = async () => {
    if (!url.trim()) {
      setError("Please enter a URL to scan");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const { data } = await scanUrl(url.trim());
      setResult(data);
      loadHistory();
      loadStats();
    } catch (e) {
      setError(
        e.response?.data?.error || e.message || "Scan failed"
      );
    }

    setLoading(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !loading) handleScan();
  };

  const handleDeleteScan = async (id) => {
    try {
      await deleteUrlScan(id);
      setHistory((h) => h.filter((s) => s._id !== id));
      loadStats();
    } catch (e) {
      console.error(e);
    }
  };

  // Quick test URLs
  const quickUrls = [
    { label: "✅ Google", url: "https://www.google.com" },
    { label: "✅ GitHub", url: "https://github.com" },
    { label: "⚠️ Suspicious", url: "http://192.168.1.1/admin/login.php?user=admin" },
    { label: "🚨 Phishing", url: "http://secure-paypal-login.tk/verify?account=locked" },
    { label: "🚨 Malware", url: "http://free-crack-download.xyz/photoshop-crack.exe" },
  ];

  // Risk score visual helpers
  const getRiskGradient = (score) => {
    if (score >= 70) return "linear-gradient(90deg, #ff4757, #ff6b81)";
    if (score >= 50) return "linear-gradient(90deg, #ff9800, #ffb74d)";
    if (score >= 30) return "linear-gradient(90deg, #fbbf24, #fcd34d)";
    if (score >= 15) return "linear-gradient(90deg, #8bc34a, #aed581)";
    return "linear-gradient(90deg, #00e67a, #69f0ae)";
  };

  const getRiskEmoji = (level) => {
    return {
      safe: "✅",
      low: "🟢",
      medium: "🟡",
      high: "🟠",
      critical: "🔴",
    }[level] || "❓";
  };

  return (
    <div className="us-container">
      {/* Header */}
      <div className="us-header">
        <h2 className="us-title">🔗 URL Safety Scanner</h2>
        <p className="us-subtitle">
          Analyze any URL for phishing, malware, and security threats
        </p>
      </div>

      {/* Stats Bar */}
      {stats && (
        <div className="us-stats-bar">
          <div className="us-stat">
            <span className="us-stat-val">{stats.total}</span>
            <span className="us-stat-label">Total Scans</span>
          </div>
          <div className="us-stat">
            <span className="us-stat-val" style={{ color: "var(--green)" }}>
              {stats.safe}
            </span>
            <span className="us-stat-label">Safe</span>
          </div>
          <div className="us-stat">
            <span className="us-stat-val" style={{ color: "var(--red)" }}>
              {stats.unsafe}
            </span>
            <span className="us-stat-label">Unsafe</span>
          </div>
          {stats.riskDistribution &&
            Object.entries(stats.riskDistribution).map(([level, count]) => (
              <div key={level} className="us-stat">
                <span
                  className="us-stat-val"
                  style={{ color: sevColor(level) }}
                >
                  {count}
                </span>
                <span className="us-stat-label">{level}</span>
              </div>
            ))}
        </div>
      )}

      {/* Tabs */}
      <div className="us-tabs">
        <button
          className={`us-tab ${activeTab === "scan" ? "us-tab-active" : ""}`}
          onClick={() => setActiveTab("scan")}
        >
          🔍 Scan URL
        </button>
        <button
          className={`us-tab ${activeTab === "history" ? "us-tab-active" : ""}`}
          onClick={() => setActiveTab("history")}
        >
          📜 Scan History ({stats?.total || 0})
        </button>
      </div>

      {/* SCAN TAB */}
      {activeTab === "scan" && (
        <div className="us-scan-section">
          {/* Input Area */}
          <div className="card us-input-card">
            <div className="us-input-row">
              <div className="us-input-icon">🌐</div>
              <input
                type="text"
                className="us-input"
                placeholder="Enter URL to scan (e.g., https://example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={loading}
              />
              <button
                className="btn btn-primary us-scan-btn"
                onClick={handleScan}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="us-spinner" /> Scanning...
                  </>
                ) : (
                  "🔍 Scan"
                )}
              </button>
            </div>

            {/* Quick Test URLs */}
            <div className="us-quick">
              <span className="us-quick-label">Quick Test:</span>
              {quickUrls.map((q) => (
                <button
                  key={q.url}
                  className="us-quick-btn"
                  onClick={() => {
                    setUrl(q.url);
                    setResult(null);
                    setError(null);
                  }}
                >
                  {q.label}
                </button>
              ))}
            </div>

            {error && <div className="us-error">❌ {error}</div>}
          </div>

          {/* Results */}
          {result && (
            <div className="us-result anim-up">
              {/* Verdict */}
              <div
                className="card us-verdict-card"
                style={{
                  borderColor: result.safe ? "var(--green)" : "var(--red)",
                }}
              >
                <div className="us-verdict-top">
                  <div className="us-verdict-icon-wrap">
                    <span className="us-verdict-emoji">
                      {result.safe ? "✅" : "🚨"}
                    </span>
                  </div>
                  <div className="us-verdict-info">
                    <div
                      className="us-verdict-status"
                      style={{
                        color: result.safe ? "var(--green)" : "var(--red)",
                      }}
                    >
                      {result.safe ? "SAFE" : "UNSAFE"}
                    </div>
                    <div className="us-verdict-url">{result.url}</div>
                    {result.cached && (
                      <span className="us-cached-badge">📦 Cached Result</span>
                    )}
                  </div>
                  <div className="us-risk-circle">
                    <svg viewBox="0 0 120 120" className="us-risk-svg">
                      <circle cx="60" cy="60" r="50" className="us-risk-bg" />
                      <circle
                        cx="60"
                        cy="60"
                        r="50"
                        className="us-risk-fill"
                        style={{
                          strokeDasharray: `${result.riskScore * 3.14} ${314 - result.riskScore * 3.14}`,
                          stroke: sevColor(result.riskLevel),
                        }}
                      />
                    </svg>
                    <div className="us-risk-label">
                      <span
                        className="us-risk-num"
                        style={{ color: sevColor(result.riskLevel) }}
                      >
                        {result.riskScore}
                      </span>
                      <span className="us-risk-text">/ 100</span>
                    </div>
                  </div>
                </div>

                {/* Risk Level Badge */}
                <div className="us-risk-bar-section">
                  <div className="us-risk-bar-track">
                    <div
                      className="us-risk-bar-fill"
                      style={{
                        width: `${result.riskScore}%`,
                        background: getRiskGradient(result.riskScore),
                      }}
                    />
                    <div
                      className="us-risk-bar-marker"
                      style={{ left: `${result.riskScore}%` }}
                    />
                  </div>
                  <div className="us-risk-bar-labels">
                    <span style={{ color: "var(--green)" }}>Safe</span>
                    <span style={{ color: "var(--yellow)" }}>Low</span>
                    <span style={{ color: "var(--orange)" }}>Medium</span>
                    <span style={{ color: "var(--red)" }}>High</span>
                    <span style={{ color: "var(--purple)" }}>Critical</span>
                  </div>
                </div>
              </div>

              {/* Details Grid */}
              <div className="us-details-grid">
                {/* Threats */}
                {result.threats?.length > 0 && (
                  <div className="card us-detail-card us-threats">
                    <div className="card-hdr">
                      <span className="card-title">🚨 Threats Detected</span>
                      <span
                        className="badge"
                        style={{
                          background: "rgba(255,71,87,0.12)",
                          color: "var(--red)",
                        }}
                      >
                        {result.threats.length}
                      </span>
                    </div>
                    <div className="us-list">
                      {result.threats.map((t, i) => (
                        <div key={i} className="us-list-item us-item-threat">
                          <span className="us-item-icon">🔴</span>
                          <span>{t}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Warnings */}
                {result.warnings?.length > 0 && (
                  <div className="card us-detail-card us-warnings">
                    <div className="card-hdr">
                      <span className="card-title">⚠️ Warnings</span>
                      <span
                        className="badge"
                        style={{
                          background: "rgba(255,152,0,0.12)",
                          color: "var(--orange)",
                        }}
                      >
                        {result.warnings.length}
                      </span>
                    </div>
                    <div className="us-list">
                      {result.warnings.map((w, i) => (
                        <div key={i} className="us-list-item us-item-warning">
                          <span className="us-item-icon">🟡</span>
                          <span>{w}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Info */}
                {result.info?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">ℹ️ Information</span>
                    </div>
                    <div className="us-list">
                      {result.info.map((info, i) => (
                        <div key={i} className="us-list-item us-item-info">
                          <span className="us-item-icon">🔵</span>
                          <span>{info}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {result.recommendations?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">💡 Recommendations</span>
                    </div>
                    <div className="us-list">
                      {result.recommendations.map((r, i) => (
                        <div key={i} className="us-list-item us-item-rec">
                          <span className="us-item-icon">💡</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Technical Analysis */}
              {result.analysis && (
                <div className="card us-tech-card">
                  <div className="card-hdr">
                    <span className="card-title">🔬 Technical Analysis</span>
                  </div>

                  <div className="us-tech-grid">
                    {/* Domain Analysis */}
                    {result.analysis.domain && (
                      <div className="us-tech-section">
                        <h4>🌐 Domain</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Domain</span>
                            <span className="us-tech-val us-mono us-cyan">
                              {result.analysis.domain.name}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Length</span>
                            <span className="us-tech-val">
                              {result.analysis.domain.length} chars
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>IP Address</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.domain.is_ip
                                  ? "var(--red)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.domain.is_ip ? "Yes ⚠️" : "No ✓"}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Subdomains</span>
                            <span className="us-tech-val">
                              {result.analysis.domain.subdomain_count}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Suspicious TLD</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.domain.suspicious_tld
                                  ? "var(--red)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.domain.suspicious_tld
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Trusted</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.reputation?.trusted
                                  ? "var(--green)"
                                  : "var(--text-dim)",
                              }}
                            >
                              {result.analysis.reputation?.trusted
                                ? "Yes ✓"
                                : "Unknown"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* SSL Analysis */}
                    {result.analysis.ssl && (
                      <div className="us-tech-section">
                        <h4>🔒 SSL / Security</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Protocol</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color:
                                  result.analysis.ssl.protocol === "https"
                                    ? "var(--green)"
                                    : "var(--red)",
                              }}
                            >
                              {result.analysis.ssl.protocol?.toUpperCase()}
                            </span>
                          </div>
                          {result.analysis.ssl.checked && (
                            <>
                              <div className="us-tech-row">
                                <span>Certificate</span>
                                <span
                                  className="us-tech-val"
                                  style={{
                                    color: result.analysis.ssl.valid
                                      ? "var(--green)"
                                      : "var(--red)",
                                  }}
                                >
                                  {result.analysis.ssl.valid
                                    ? "Valid ✓"
                                    : "Invalid ✖"}
                                </span>
                              </div>
                              {result.analysis.ssl.issuer && (
                                <div className="us-tech-row">
                                  <span>Issuer</span>
                                  <span className="us-tech-val">
                                    {result.analysis.ssl.issuer}
                                  </span>
                                </div>
                              )}
                              {result.analysis.ssl.expires && (
                                <div className="us-tech-row">
                                  <span>Expires</span>
                                  <span className="us-tech-val">
                                    {result.analysis.ssl.expires}
                                  </span>
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    {/* URL Structure */}
                    {result.analysis.url_structure && (
                      <div className="us-tech-section">
                        <h4>🔗 URL Structure</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Total Length</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.total_length || result.analysis.url_structure.url_length} chars
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Path Depth</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.path_depth}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Query Params</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.query_params}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Encoded Chars</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.encoded_chars}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Non-std Port</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.url_structure
                                  .non_standard_port
                                  ? "var(--orange)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.url_structure.non_standard_port
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Content Indicators */}
                    {result.analysis.content_indicators && (
                      <div className="us-tech-section">
                        <h4>📋 Content Analysis</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Suspicious Patterns</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color:
                                  result.analysis.content_indicators
                                    .suspicious_patterns > 0
                                    ? "var(--orange)"
                                    : "var(--green)",
                              }}
                            >
                              {result.analysis.content_indicators.suspicious_patterns}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Malware Patterns</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color:
                                  result.analysis.content_indicators
                                    .malware_patterns > 0
                                    ? "var(--red)"
                                    : "var(--green)",
                              }}
                            >
                              {result.analysis.content_indicators.malware_patterns}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Has Redirect</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.content_indicators
                                  .has_redirect
                                  ? "var(--orange)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.content_indicators.has_redirect
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                          {result.analysis.content_indicators.phishing_keywords
                            ?.length > 0 && (
                            <div className="us-tech-row">
                              <span>Phishing Keywords</span>
                              <span className="us-tech-val" style={{ color: "var(--red)" }}>
                                {result.analysis.content_indicators.phishing_keywords.join(", ")}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Scan Meta */}
                  <div className="us-scan-meta">
                    <span>
                      Scan Duration:{" "}
                      <strong>{result.scanDuration || "N/A"}ms</strong>
                    </span>
                    <span>
                      Scanned: <strong>{fmtDate(result.timestamp)}</strong>
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Empty State */}
          {!result && !loading && !error && (
            <div className="card">
              <div className="empty">
                <div className="empty-icon">🔗</div>
                <p>Enter a URL above to scan for security threats</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* HISTORY TAB */}
      {activeTab === "history" && (
        <div className="card">
          <div className="card-hdr">
            <span className="card-title">📜 Scan History</span>
            <button className="btn btn-ghost btn-sm" onClick={loadHistory}>
              ↻ Refresh
            </button>
          </div>

          {!history.length ? (
            <div className="empty">
              <div className="empty-icon">📜</div>
              <p>No scan history yet. Scan a URL to get started.</p>
            </div>
          ) : (
            <>
              <div className="us-history-list">
                {history.map((scan, i) => (
                  <div
                    key={scan._id}
                    className="us-history-item anim-up"
                    style={{ animationDelay: `${i * 40}ms` }}
                  >
                    <div className="us-hist-left">
                      <span className="us-hist-emoji">
                        {getRiskEmoji(scan.riskLevel)}
                      </span>
                      <div>
                        <div className="us-hist-url">{scan.url}</div>
                        <div className="us-hist-meta">
                          <span>{fmtDate(scan.createdAt)}</span>
                          {scan.scanDuration && (
                            <span>{scan.scanDuration}ms</span>
                          )}
                          {scan.threats?.length > 0 && (
                            <span style={{ color: "var(--red)" }}>
                              {scan.threats.length} threat(s)
                            </span>
                          )}
                          {scan.warnings?.length > 0 && (
                            <span style={{ color: "var(--orange)" }}>
                              {scan.warnings.length} warning(s)
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="us-hist-right">
                      <div className="us-hist-score">
                        <span
                          className="us-hist-score-num"
                          style={{ color: sevColor(scan.riskLevel) }}
                        >
                          {scan.riskScore}
                        </span>
                        <span className="us-hist-score-label">/100</span>
                      </div>
                      <span
                        className="badge"
                        style={{
                          background: sevBg(scan.riskLevel),
                          color: sevColor(scan.riskLevel),
                        }}
                      >
                        {scan.riskLevel}
                      </span>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDeleteScan(scan._id)}
                      >
                        ✕
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {historyPg.pages > 1 && (
                <div className="at-pag">
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={historyPage <= 1}
                    onClick={() => setHistoryPage((p) => p - 1)}
                  >
                    ← Prev
                  </button>
                  <span className="at-pag-info">
                    Page {historyPg.page} of {historyPg.pages}
                  </span>
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={historyPage >= historyPg.pages}
                    onClick={() => setHistoryPage((p) => p + 1)}
                  >
                    Next →
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
