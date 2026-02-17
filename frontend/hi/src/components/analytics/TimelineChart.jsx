import React, { useState, useEffect } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { getTimeline } from "../../services/api";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

const COLORS = {
  dos: "#ff4757",
  probe: "#ff9800",
  r2l: "#4d8dff",
  u2r: "#a855f7",
};

export default function TimelineChart() {
  const [data, setData] = useState([]);
  const [period, setPeriod] = useState("24h");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const { data: d } = await getTimeline(period);
        setData(d);
      } catch (e) {
        console.error(e);
      }
      setLoading(false);
    };
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  }, [period]);

  if (loading && !data.length) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">📈 Attack Timeline</span>
        </div>
        <div className="empty">
          <p>Loading timeline...</p>
        </div>
      </div>
    );
  }

  if (!data.length) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">📈 Attack Timeline</span>
          <div className="card-actions">
            {["1h", "24h", "7d", "30d"].map((p) => (
              <button
                key={p}
                className={`btn btn-sm ${period === p ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setPeriod(p)}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
        <div className="empty">
          <div className="empty-icon">📉</div>
          <p>No data for this period</p>
        </div>
      </div>
    );
  }

  const labels = data.map((d) => d.time);
  const types = ["dos", "probe", "r2l", "u2r"];
  const datasets = types.map((t) => ({
    label: t.toUpperCase(),
    data: data.map((r) => r[t] || 0),
    borderColor: COLORS[t],
    backgroundColor: COLORS[t] + "18",
    fill: true,
    tension: 0.4,
    pointRadius: 3,
    pointHoverRadius: 7,
    borderWidth: 2.5,
    pointBackgroundColor: COLORS[t],
    pointBorderColor: "#111640",
    pointBorderWidth: 2,
  }));

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: {
        position: "top",
        labels: {
          color: "#8f96b8",
          usePointStyle: true,
          padding: 16,
          font: { family: "Inter", size: 11.5 },
        },
      },
      tooltip: {
        backgroundColor: "#1a2055",
        titleColor: "#e4e7f1",
        bodyColor: "#8f96b8",
        borderColor: "#2a3370",
        borderWidth: 1,
        cornerRadius: 10,
        padding: 12,
        titleFont: { weight: "bold" },
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(30,37,90,0.4)", lineWidth: 0.5 },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 10 },
          maxRotation: 45,
        },
      },
      y: {
        grid: { color: "rgba(30,37,90,0.4)", lineWidth: 0.5 },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 10 },
        },
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="card">
      <div className="card-hdr">
        <span className="card-title">📈 Attack Timeline</span>
        <div className="card-actions">
          {["1h", "24h", "7d", "30d"].map((p) => (
            <button
              key={p}
              className={`btn btn-sm ${period === p ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setPeriod(p)}
            >
              {p}
            </button>
          ))}
        </div>
      </div>
      <div style={{ height: 380 }}>
        <Line data={{ labels, datasets }} options={options} />
      </div>
    </div>
  );
}