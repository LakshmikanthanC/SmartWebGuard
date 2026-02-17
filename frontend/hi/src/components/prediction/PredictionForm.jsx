import React, { useState } from "react";
import "./PredictionForm.css";

const TEMPLATES = {
  normal: {
    duration: 12, protocol_type: "tcp", service: "http", flag: "SF",
    src_bytes: 520, dst_bytes: 1032, land: 0, wrong_fragment: 0, urgent: 0,
    hot: 0, num_failed_logins: 0, logged_in: 1, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 0,
    num_shells: 0, num_access_files: 0, num_outbound_cmds: 0,
    is_host_login: 0, is_guest_login: 0, count: 12, srv_count: 10,
    serror_rate: 0.0, srv_serror_rate: 0.0, rerror_rate: 0.0,
    srv_rerror_rate: 0.0, same_srv_rate: 1.0, diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0, dst_host_count: 120, dst_host_srv_count: 60,
    dst_host_same_srv_rate: 0.9, dst_host_diff_srv_rate: 0.04,
    dst_host_same_src_port_rate: 0.1, dst_host_srv_diff_host_rate: 0.02,
    dst_host_serror_rate: 0.0, dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.01, dst_host_srv_rerror_rate: 0.01,
  },
  dos: {
    duration: 0, protocol_type: "tcp", service: "http", flag: "S0",
    src_bytes: 0, dst_bytes: 0, land: 0, wrong_fragment: 0, urgent: 0,
    hot: 0, num_failed_logins: 0, logged_in: 0, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 0,
    num_shells: 0, num_access_files: 0, num_outbound_cmds: 0,
    is_host_login: 0, is_guest_login: 0, count: 500, srv_count: 2,
    serror_rate: 1.0, srv_serror_rate: 1.0, rerror_rate: 0.0,
    srv_rerror_rate: 0.0, same_srv_rate: 0.08, diff_srv_rate: 0.92,
    srv_diff_host_rate: 0.85, dst_host_count: 255, dst_host_srv_count: 4,
    dst_host_same_srv_rate: 0.03, dst_host_diff_srv_rate: 0.95,
    dst_host_same_src_port_rate: 0.98, dst_host_srv_diff_host_rate: 0.85,
    dst_host_serror_rate: 1.0, dst_host_srv_serror_rate: 1.0,
    dst_host_rerror_rate: 0.0, dst_host_srv_rerror_rate: 0.0,
  },
  probe: {
    duration: 0, protocol_type: "icmp", service: "ecr_i", flag: "SF",
    src_bytes: 8, dst_bytes: 0, land: 0, wrong_fragment: 0, urgent: 0,
    hot: 0, num_failed_logins: 0, logged_in: 0, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 0,
    num_shells: 0, num_access_files: 0, num_outbound_cmds: 0,
    is_host_login: 0, is_guest_login: 0, count: 300, srv_count: 300,
    serror_rate: 0.0, srv_serror_rate: 0.0, rerror_rate: 0.0,
    srv_rerror_rate: 0.0, same_srv_rate: 1.0, diff_srv_rate: 0.0,
    srv_diff_host_rate: 1.0, dst_host_count: 255, dst_host_srv_count: 255,
    dst_host_same_srv_rate: 1.0, dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 1.0, dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0, dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0, dst_host_srv_rerror_rate: 0.0,
  },
  r2l: {
    duration: 200, protocol_type: "tcp", service: "ftp", flag: "SF",
    src_bytes: 300, dst_bytes: 4500, land: 0, wrong_fragment: 0, urgent: 0,
    hot: 3, num_failed_logins: 4, logged_in: 1, num_compromised: 0,
    root_shell: 0, su_attempted: 0, num_root: 0, num_file_creations: 2,
    num_shells: 0, num_access_files: 1, num_outbound_cmds: 0,
    is_host_login: 0, is_guest_login: 0, count: 5, srv_count: 5,
    serror_rate: 0.0, srv_serror_rate: 0.0, rerror_rate: 0.0,
    srv_rerror_rate: 0.0, same_srv_rate: 1.0, diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0, dst_host_count: 50, dst_host_srv_count: 25,
    dst_host_same_srv_rate: 0.5, dst_host_diff_srv_rate: 0.1,
    dst_host_same_src_port_rate: 0.2, dst_host_srv_diff_host_rate: 0.05,
    dst_host_serror_rate: 0.0, dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0, dst_host_srv_rerror_rate: 0.0,
  },
};

export default function PredictionForm({ onSubmit, loading }) {
  const [json, setJson] = useState(JSON.stringify(TEMPLATES.normal, null, 2));
  const [error, setError] = useState(null);

  const handleSubmit = () => {
    setError(null);
    try {
      const parsed = JSON.parse(json);
      onSubmit(parsed);
    } catch {
      setError("Invalid JSON format. Please fix and try again.");
    }
  };

  const loadTemplate = (key) => {
    setJson(JSON.stringify(TEMPLATES[key], null, 2));
    setError(null);
  };

  return (
    <div className="card pf-card">
      <div className="card-hdr">
        <span className="card-title">📝 Traffic Features (JSON)</span>
      </div>

      <div className="pf-templates">
        <span className="pf-tpl-label">Load Template:</span>
        <button className="btn btn-ghost btn-sm" onClick={() => loadTemplate("normal")}>
          ✅ Normal
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => loadTemplate("dos")}>
          🔥 DoS
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => loadTemplate("probe")}>
          🔍 Probe
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => loadTemplate("r2l")}>
          🔓 R2L
        </button>
      </div>

      <textarea
        className="pf-textarea"
        value={json}
        onChange={(e) => setJson(e.target.value)}
        spellCheck={false}
        rows={22}
      />

      {error && (
        <div className="pf-error">❌ {error}</div>
      )}

      <div className="pf-actions">
        <button
          className="btn btn-primary"
          onClick={handleSubmit}
          disabled={loading}
        >
          {loading ? "⏳ Analyzing..." : "🚀 Run Prediction"}
        </button>
      </div>
    </div>
  );
}