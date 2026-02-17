import React from "react";
import { useSocket } from "../../context/SocketContext";
import { fmtTime, atkIcon } from "../../utils/formatters";
import "./LiveFeed.css";

export default function LiveFeed() {
  const { feed, connected, clearFeed } = useSocket();

  return (
    <div className="card live-feed-card">
      <div className="card-header">
        <span className="card-title">
          <span className="icon">📡</span>Live Traffic Feed
          {connected && <span className="live-badge pulse">● LIVE</span>}
        </span>
        <button className="btn btn-ghost btn-sm" onClick={clearFeed}>Clear</button>
      </div>
      <div className="feed-scroll">
        {feed.length === 0 ? (
          <div className="empty-state"><div className="empty-icon">📡</div><p>Waiting for traffic data...</p></div>
        ) : (
          feed.slice(0, 40).map((item, i) => (
            <div key={i} className={`feed-row anim-slide-right ${item.is_malicious ? "feed-mal" : "feed-ok"}`}
                 style={{ animationDelay: `${Math.min(i * 30, 300)}ms` }}>
              <span className="fr-icon">{atkIcon(item.prediction)}</span>
              <span className="fr-time">{fmtTime(item.timestamp)}</span>
              <span className="fr-ip">{item.sourceIP}</span>
              <span className="fr-arrow">→</span>
              <span className="fr-ip">{item.destinationIP}</span>
              <span className="fr-proto">{item.protocol?.toUpperCase()}</span>
              <span className={`fr-tag ${item.is_malicious ? "tag-mal" : "tag-ok"}`}>
                {item.prediction?.toUpperCase()}
              </span>
              <span className="fr-conf">{(item.confidence * 100).toFixed(0)}%</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}