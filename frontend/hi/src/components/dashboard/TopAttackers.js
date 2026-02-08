import React, { useState, useEffect } from "react";
import { getTopSources } from "../../services/api";
import { fmtDate } from "../../utils/formatters";
import "./TopAttackers.css";

export default function TopAttackers() {
  const [data, setData] = useState([]);

  useEffect(() => {
    const load = async () => {
      try { const { data: d } = await getTopSources(8); setData(d); } catch {}
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  if (!data.length) return null;

  const max = data[0]?.count || 1;

  return (
    <div className="card">
      <div className="card-header"><span className="card-title"><span className="icon">🏴‍☠️</span>Top Threat Sources</span></div>
      <div className="ta-list">
        {data.map((s, i) => (
          <div key={i} className="ta-row anim-fade-up" style={{ animationDelay: `${i * 50}ms` }}>
            <div className="ta-rank">#{i + 1}</div>
            <div className="ta-info">
              <div className="ta-ip">{s._id}</div>
              <div className="ta-types">{s.types?.join(", ")}</div>
            </div>
            <div className="ta-bar-wrap">
              <div className="ta-bar" style={{ width: `${(s.count / max) * 100}%` }} />
            </div>
            <div className="ta-count">{s.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}