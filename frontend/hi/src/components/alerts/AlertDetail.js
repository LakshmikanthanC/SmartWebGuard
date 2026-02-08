import React from "react";
import { fmtDate, fmtPct, sevColor, sevBg, atkIcon, atkColor } from "../../utils/formatters";
import "./AlertDetail.css";

export default function AlertDetail({ alert, onClose, onAck }) {
  if (!alert) return null;

  return (
    <div className="detail-overlay anim-fade-in" onClick={onClose}>
      <div className="detail-modal anim-scale-in" onClick={(e) => e.stopPropagation()}>
        <div className="detail-header">
          <h3>{atkIcon(alert.attackType)} {alert.attackType?.toUpperCase()} Attack</h3>
          <button className="detail-close" onClick={onClose}>✕</button>
        </div>

        <div className="detail-body">
          <div className="detail-grid">
            <div className="dg-item">
              <span className="dg-label">Severity</span>
              <span className="badge" style={{ background: sevBg(alert.severity), color: sevColor(alert.severity) }}>{alert.severity}</span>
            </div>
            <div className="dg-item">
              <span className="dg-label">Confidence</span>
              <span className="dg-val">{fmtPct(alert.confidence)}</span>
            </div>
            <div className="dg-item">
              <span className="dg-label">Timestamp</span>
              <span className="dg-val">{fmtDate(alert.timestamp)}</span>
            </div>
            <div className="dg-item">
              <span className="dg-label">Protocol</span>
              <span className="dg-val">{alert.protocol?.toUpperCase()}</span>
            </div>
            <div className="dg-item">
              <span className="dg-label">Source</span>
              <span className="dg-val mono cyan">{alert.sourceIP}:{alert.sourcePort}</span>
            </div>
            <div className="dg-item">
              <span className="dg-label">Destination</span>
              <span className="dg-val mono cyan">{alert.destinationIP}:{alert.destinationPort}</span>
            </div>
          </div>

          {alert.probabilities && (
            <div className="detail-probs">
              <h4>Classification Probabilities</h4>
              {Object.entries(alert.probabilities).map(([k, v]) => (
                <div key={k} className="prob-row">
                  <span className="prob-label">{k.toUpperCase()}</span>
                  <div className="prob-bar-wrap">
                    <div className="prob-bar" style={{ width: `${v * 100}%`, background: atkColor(k) }} />
                  </div>
                  <span className="prob-val">{(v * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="detail-footer">
          {!alert.acknowledged && <button className="btn btn-primary" onClick={() => { onAck(alert._id); onClose(); }}>Acknowledge Alert</button>}
          <button className="btn btn-ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}