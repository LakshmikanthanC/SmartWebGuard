import React, { useState } from "react";
import "./Settings.css";

export default function Settings() {
  const [theme, setTheme] = useState("light");
  const [notifications, setNotifications] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const handleThemeChange = (e) => {
    setTheme(e.target.value);
    // Apply theme logic here if needed
  };

  return (
    <div className="settings-container">
      <div className="settings-header">
        <h2 className="settings-title">⚙️ Settings</h2>
        <p className="settings-subtitle">
          Customize your AI-NIDS experience
        </p>
      </div>

      <div className="settings-content">
        {/* <div className="card">
          <div className="card-hdr">
            <span className="card-title">Appearance</span>
          </div>
          <div className="setting-item">
            <label htmlFor="theme">Theme</label>
            <select id="theme" value={theme} onChange={handleThemeChange}>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
              <option value="auto">Auto</option>
            </select>
          </div>
        </div> */}

        <div className="card">
          <div className="card-hdr">
            <span className="card-title">Notifications</span>
          </div>
          <div className="setting-item">
            <label htmlFor="notifications">Enable Notifications</label>
            <input
              type="checkbox"
              id="notifications"
              checked={notifications}
              onChange={(e) => setNotifications(e.target.checked)}
            />
          </div>
        </div>

        <div className="card">
          <div className="card-hdr">
            <span className="card-title">Dashboard</span>
          </div>
          <div className="setting-item">
            <label htmlFor="autoRefresh">Auto Refresh Data</label>
            <input
              type="checkbox"
              id="autoRefresh"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
