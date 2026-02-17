import React from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, Filler,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler);

const COLORS = { dos: "#ff4757", probe: "#ff9800", r2l: "#4d8dff", u2r: "#a855f7" };

export default function TrafficChart({ timeline }) {
  if (!timeline?.length) {
    return <div className="card"><div className="card-header"><span className="card-title"><span className="icon">📈</span>Attack Timeline</span></div><div className="empty-state"><div className="empty-icon">📉</div><p>No timeline data yet — start the simulation</p></div></div>;
  }

  const labels = timeline.map((t) => t.time || "");
  const types = ["dos", "probe", "r2l", "u2r"];
  const datasets = types.map((t) => ({
    label: t.toUpperCase(),
    data: timeline.map((r) => r[t] || 0),
    borderColor: COLORS[t],
    backgroundColor: COLORS[t] + "15",
    fill: true,
    tension: .4,
    pointRadius: 2,
    pointHoverRadius: 6,
    borderWidth: 2,
  }));

  const opts = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: { position: "top", labels: { color: "#8f96b8", usePointStyle: true, padding: 16, font: { family: "Inter", size: 11 } } },
      tooltip: { backgroundColor: "#1a2055", titleColor: "#e4e7f1", bodyColor: "#8f96b8", borderColor: "#2a3370", borderWidth: 1, cornerRadius: 8, padding: 10 },
    },
    scales: {
      x: { grid: { color: "rgba(30,37,90,0.5)" }, ticks: { color: "#5c6490", font: { family: "JetBrains Mono", size: 10 } } },
      y: { grid: { color: "rgba(30,37,90,0.5)" }, ticks: { color: "#5c6490", font: { family: "JetBrains Mono", size: 10 } }, beginAtZero: true },
    },
  };

  return (
    <div className="card">
      <div className="card-header"><span className="card-title"><span className="icon">📈</span>Attack Timeline</span></div>
      <div style={{ height: 320 }}><Line data={{ labels, datasets }} options={opts} /></div>
    </div>
  );
}