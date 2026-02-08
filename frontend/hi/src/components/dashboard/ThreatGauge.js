import React from "react";
import "./ThreatGauge.css";

export default function ThreatGauge({ level, stats }) {
  const levels = { low: 25, medium: 50, high: 75, critical: 95 };
  const pct = levels[level] || 10;
  const colors = { low: "var(--green)", medium: "var(--orange)", high: "var(--red)", critical: "var(--purple)" };
  const color = colors[level] || "var(--green)";

  return (
    <div className="card threat-gauge-card">
      <div className="card-header"><span className="card-title"><span className="icon">🔥</span>Threat Level</span></div>
      <div className="gauge-container">
        <div className="gauge-ring">
          <svg viewBox="0 0 120 120" className="gauge-svg">
            <circle cx="60" cy="60" r="50" className="gauge-bg" />
            <circle
              cx="60" cy="60" r="50"
              className="gauge-fill"
              style={{
                strokeDasharray: `${pct * 3.14} ${314 - pct * 3.14}`,
                stroke: color,
                filter: `drop-shadow(0 0 8px ${color})`,
              }}
            />
          </svg>
          <div className="gauge-label">
            <span className="gauge-value" style={{ color }}>{pct}%</span>
            <span className="gauge-text">{(level || "low").toUpperCase()}</span>
          </div>
        </div>
      </div>
      <div className="gauge-details">
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--red)" }} /><span>Critical</span><span className="gd-val">{stats?.severityDistribution?.critical || 0}</span></div>
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--orange)" }} /><span>High</span><span className="gd-val">{stats?.severityDistribution?.high || 0}</span></div>
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--yellow)" }} /><span>Medium</span><span className="gd-val">{stats?.severityDistribution?.medium || 0}</span></div>
      </div>
    </div>
  );
}