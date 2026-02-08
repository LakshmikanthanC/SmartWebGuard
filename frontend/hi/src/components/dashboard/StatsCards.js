import React from "react";
import { fmtNum, sevColor } from "../../utils/formatters";
import { useSocket } from "../../context/SocketContext";
import "./StatsCards.css";

export default function StatsCards({ stats }) {
  const { liveStats } = useSocket();

  const cards = [
    { icon: "🚨", label: "Total Alerts", value: fmtNum(stats?.overview?.totalAlerts), color: "var(--red)", sub: "All time" },
    { icon: "⚡", label: "Last 24 Hours", value: fmtNum(stats?.overview?.alerts24h), color: "var(--orange)", sub: "Recent activity" },
    { icon: "📡", label: "Live Packets", value: fmtNum(liveStats.total), color: "var(--cyan)", sub: `${liveStats.normal} normal / ${liveStats.malicious} threats` },
    {
      icon: "🎯", label: "Threat Level",
      value: (stats?.overview?.threatLevel || "low").toUpperCase(),
      color: sevColor(stats?.overview?.threatLevel || "low"),
      sub: `${fmtNum(stats?.overview?.unacknowledged)} unacknowledged`,
    },
  ];

  return (
    <div className="grid-4 mb-md">
      {cards.map((c, i) => (
        <div key={i} className="stat-card anim-fade-up" style={{ animationDelay: `${i * 80}ms` }}>
          <div className="stat-icon-wrap" style={{ background: c.color + "18" }}>
            <span className="stat-icon">{c.icon}</span>
          </div>
          <div className="stat-body">
            <span className="stat-value" style={{ color: c.color }}>{c.value || "0"}</span>
            <span className="stat-label">{c.label}</span>
            <span className="stat-sub">{c.sub}</span>
          </div>
          <div className="stat-glow" style={{ background: c.color }} />
        </div>
      ))}
    </div>
  );
}