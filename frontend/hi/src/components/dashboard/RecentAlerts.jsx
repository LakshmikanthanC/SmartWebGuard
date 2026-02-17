import React from "react";
import { fmtDate, sevColor, sevBg, atkIcon, fmtPct } from "../../utils/formatters";
import "./RecentAlerts.css";

export default function RecentAlerts({ alerts }) {
  if (!alerts?.length) {
    return <div className="card"><div className="card-header"><span className="card-title"><span className="icon">🚨</span>Recent Alerts</span></div><div className="empty-state"><div className="empty-icon">🚨</div><p>No alerts yet</p></div></div>;
  }

  return (
    <div className="card recent-alerts-card">
      <div className="card-header"><span className="card-title"><span className="icon">🚨</span>Recent Alerts</span></div>
      <div className="ra-list">
        {alerts.map((a, i) => (
          <div key={a._id || i} className="ra-item anim-fade-up" style={{ animationDelay: `${i * 60}ms` }}>
            <div className="ra-left">
              <span className="ra-icon">{atkIcon(a.attackType)}</span>
              <div>
                <div className="ra-type">{a.attackType?.toUpperCase()} Attack</div>
                <div className="ra-meta">
                  <span className="ra-ip">{a.sourceIP}</span>
                  <span className="ra-time">{fmtDate(a.timestamp)}</span>
                </div>
              </div>
            </div>
            <div className="ra-right">
              <span className="badge" style={{ background: sevBg(a.severity), color: sevColor(a.severity) }}>
                {a.severity}
              </span>
              <span className="ra-conf">{fmtPct(a.confidence)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}