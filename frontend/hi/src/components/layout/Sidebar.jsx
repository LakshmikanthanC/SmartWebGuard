import React from "react";
import { useSocket } from "../../context/SocketContext";
import "./Sidebar.css";

const nav = [
  { id: "urlscanner", icon: "🔗", label: "URL Scanner" },
  { id: "alerts", icon: "🚨", label: "Alerts" },
  { id: "analytics", icon: "📈", label: "Analytics" },
  { id: "dashboard", icon: "📊", label: "Dashboard" },
  { id: "prediction", icon: "🤖", label: "Prediction" },
  { id: "settings", icon: "⚙️", label: "Settings" },  
];

export default function Sidebar({ active, onChange }) {
  const { connected, liveStats } = useSocket();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">🛡️</div>
        <div>
          <div className="brand-name">AI-NIDS</div>
          <div className="brand-sub">Intrusion Detection</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {nav.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? "nav-active" : ""}`}
            onClick={() => onChange(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {item.id === "alerts" && liveStats.malicious > 0 && (
              <span className="nav-badge">{liveStats.malicious}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <div className="status-row">
            <span className={`dot ${connected ? "dot-green" : "dot-red"}`} />
            <span>WebSocket</span>
            <span className="status-val">{connected ? "Live" : "Down"}</span>
          </div>
          <div className="status-row">
            <span className="dot dot-blue pulse" />
            <span>Packets</span>
            <span className="status-val mono">{liveStats.total}</span>
          </div>
          <div className="status-row">
            <span className="dot dot-red" />
            <span>Threats</span>
            <span className="status-val mono">{liveStats.malicious}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}