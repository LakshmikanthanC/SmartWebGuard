import React, { useEffect, useState } from "react";
import { useSocket } from "../../context/SocketContext";
import { useTheme } from "../../context/ThemeContext";
import { getHealth } from "../../services/api";
import AiChatbot from "../AiChatbot/AiChatbot";
import "./TopBar.css";

const titles = {
  dashboard: "Dashboard", alerts: "Intrusion Alerts",
  analytics: "Analytics", prediction: "AI Prediction", settings: "Settings",
  urlscanner: "URL Safety Scanner",
};

export default function TopBar({ currentPage }) {
  const { connected } = useSocket();
  const { isDarkMode, toggleTheme } = useTheme();
  const [aiOnline, setAiOnline] = useState(false);
  const [time, setTime] = useState(new Date());
  const [dashEnabled, setDashEnabled] = useState(() => {
    try {
      return localStorage.getItem("swg_has_url_scan") === "1";
    } catch {
      return false;
    }
  });

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

  useEffect(() => {
    const onScanDone = () => setDashEnabled(true);
    window.addEventListener("swg_url_scan_done", onScanDone);
    return () => window.removeEventListener("swg_url_scan_done", onScanDone);
  }, []);

  const handleResetDashboard = () => {
    try {
      localStorage.removeItem("swg_has_url_scan");
    } catch {}
    setDashEnabled(false);
    window.dispatchEvent(new Event("swg_url_scan_reset"));
  };

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
          {currentPage === "dashboard" && dashEnabled && (
            <button
              onClick={handleResetDashboard}
              className="btn btn-ghost btn-sm"
              title="Hide dashboard analytics until a URL scan completes"
            >
              Reset Dashboard
            </button>
          )}
          <button
            onClick={toggleTheme}
            className="theme-toggle"
            title={`Switch to ${isDarkMode ? 'light' : 'dark'} mode`}
          >
            {isDarkMode ? '☀️' : '🌙'}
          </button>
          <div className="indicator" title="WebSocket Connection">
            <span className={`dot ${connected ? "dot-green" : "dot-red"}`} />
            <span>{connected ? "Connected" : "Offline"}</span>
          </div>
          <div className="indicator" title="AI Engine">
            <span className={`dot ${aiOnline ? "dot-green" : "dot-red"}`} />
            <span>AI {aiOnline ? "Online" : "Offline"}</span>
          </div>
          <AiChatbot inline />
        </div>
      </div>
    </header>
  );
}
