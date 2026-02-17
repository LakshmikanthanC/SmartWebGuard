import React, { useState, useEffect } from "react";
import { getDashboard } from "../../services/api";
import { sevColor } from "../../utils/formatters";

export default function SeverityHeatmap() {
  const [data, setData] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const { data: d } = await getDashboard();
        setData(d);
      } catch (e) {
        console.error(e);
      }
    };
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  }, []);

  const severities = ["critical", "high", "medium", "low", "none"];
  const dist = data?.severityDistribution || {};
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="card">
      <div className="card-hdr">
        <span className="card-title">🌡️ Severity Distribution</span>
      </div>

      {!data ? (
        <div className="empty">
          <p>Loading...</p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {severities.map((sev) => {
            const count = dist[sev] || 0;
            const pct = ((count / total) * 100).toFixed(1);
            const color = sevColor(sev);

            return (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span
                  style={{
                    minWidth: 65,
                    fontSize: "0.78rem",
                    fontWeight: 600,
                    textTransform: "uppercase",
                    color: color,
                  }}
                >
                  {sev}
                </span>
                <div
                  style={{
                    flex: 1,
                    height: 24,
                    background: "var(--border)",
                    borderRadius: 6,
                    overflow: "hidden",
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      width: `${pct}%`,
                      height: "100%",
                      background: `linear-gradient(90deg, ${color}55, ${color})`,
                      borderRadius: 6,
                      transition: "width 0.6s ease",
                      minWidth: count > 0 ? 4 : 0,
                    }}
                  />
                  <span
                    style={{
                      position: "absolute",
                      right: 8,
                      top: "50%",
                      transform: "translateY(-50%)",
                      fontSize: "0.7rem",
                      fontFamily: "var(--mono)",
                      fontWeight: 600,
                      color: "var(--text)",
                    }}
                  >
                    {count} ({pct}%)
                  </span>
                </div>
              </div>
            );
          })}

          <div
            style={{
              marginTop: 12,
              padding: "12px 16px",
              background: "rgba(0,0,0,0.15)",
              borderRadius: "var(--radius-sm)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
              Total Alerts (7 days)
            </span>
            <span
              style={{
                fontSize: "1.2rem",
                fontWeight: 800,
                fontFamily: "var(--mono)",
                color: "var(--text)",
              }}
            >
              {Object.values(dist)
                .reduce((a, b) => a + b, 0)
                .toLocaleString()}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}