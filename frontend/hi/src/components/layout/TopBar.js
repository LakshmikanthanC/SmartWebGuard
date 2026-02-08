import React, { useEffect, useState } from "react";
import { useSocket } from "../../context/SocketContext";
import { getHealth } from "../../services/api";
import "./TopBar.css";

const titles = {
  dashboard: "Dashboard", alerts: "Intrusion Alerts",
  analytics: "Analytics", prediction: "AI Prediction", settings: "Settings",
  urlscanner: "URL Safety Scanner",
};

export default function TopBar({ currentPage }) {
  const { connected } = useSocket();
  const [aiOnline, setAiOnline] = useState(false);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const check = async () => {
      try {
        const { data } = await getHealth();
        setAiOnline(data.ai_engine?.status === "healthy");
      } catch { setAiOnline(false); }
    };
    check();
    const t = setInterval(check, 30000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <h1 className="topbar-title">{titles[currentPage] || "Dashboard"}</h1>
      </div>
      <div className="topbar-right">
        <div className="topbar-clock">
          <span className="clock-date">{time.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" })}</span>
          <span className="clock-time">{time.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
        </div>
        <div className="topbar-divider" />
        <div className="topbar-indicators">
          <div className="indicator" title="WebSocket Connection">
            <span className={`dot ${connected ? "dot-green" : "dot-red"}`} />
            <span>{connected ? "Connected" : "Offline"}</span>
          </div>
          <div className="indicator" title="AI Engine">
            <span className={`dot ${aiOnline ? "dot-green" : "dot-red"}`} />
            <span>AI {aiOnline ? "Online" : "Offline"}</span>
          </div>
        </div>
      </div>
    </header>
  );
}