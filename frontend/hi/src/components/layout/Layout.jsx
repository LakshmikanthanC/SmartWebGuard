import React, { useState } from "react";
import Sidebar from "../layout/Sidebar";
import TopBar from "../layout/TopBar";
import AiChatbot from "../AiChatbot/AiChatbot";
import "./Layout.css";

export default function Layout({ children }) {
  const [activeNav, setActiveNav] = useState("dashboard");

  return (
    <div className="layout">
      <Sidebar active={activeNav} onChange={setActiveNav} />
      <div className="layout-main">
        <TopBar currentPage={activeNav} />
        <div className="layout-content">
          {children}
        </div>
      </div>
      {/* AiChatbot appears on every page that uses this Layout */}
      <AiChatbot />
    </div>
  );
}
