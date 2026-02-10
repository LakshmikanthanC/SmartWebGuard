import React, { useState, useEffect, useCallback } from "react";
import "./App.css";
import { SocketProvider, useSocket } from "./context/SocketContext";
import { ThemeProvider, useTheme } from "./context/ThemeContext";
import { getDashboard, getTimeline, getTopSources, postPredict, getModelInfo } from "./services/api";
import Sidebar from "./components/layout/Sidebar";
import TopBar from "./components/layout/TopBar";
import StatsCards from "./components/dashboard/StatsCards";
import TrafficChart from "./components/dashboard/TrafficChart";
import AttackDonut from "./components/dashboard/AttackDonut";
import ThreatGauge from "./components/dashboard/ThreatGauge";
import LiveFeed from "./components/dashboard/LiveFeed";
import RecentAlerts from "./components/dashboard/RecentAlerts";
import TopAttackers from "./components/dashboard/TopAttackers";
import AlertsTable from "./components/alerts/AlertsTable";
import PredictionPanel from "./components/PredictionPanel";
import TimelineChart from "./components/analytics/TimelineChart";
import SeverityHeatmap from "./components/analytics/SeverityHeatmap";
import ProtocolBreakdown from "./components/analytics/ProtocolBreakdown";
import ModelMetrics from "./components/analytics/ModelMetrics";
import UrlScanner from "./components/UrlScanner";
import Settings from "./components/Settings";

function MainApp() {
  const [page, setPage] = useState("dashboard");
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topSrc, setTopSrc] = useState([]);

  const loadData = useCallback(async () => {
    try {
      const [d, t, s] = await Promise.all([
        getDashboard(),
        getTimeline("24h"),
        getTopSources(8),
      ]);
      setStats(d.data);
      setTimeline(t.data);
      setTopSrc(s.data);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    loadData();
    const iv = setInterval(loadData, 15000);
    return () => clearInterval(iv);
  }, [loadData]);

  return (
    <div className="app-layout">
      <Sidebar active={page} onChange={setPage} />
      <div className="app-main">
        <TopBar page={page} />
        <div className="app-content">
          {/* DASHBOARD */}
          {page === "dashboard" && (
            <>
              <StatsCards stats={stats} />
              <div className="grid-2-1 mb">
                <TrafficChart timeline={timeline} />
                <ThreatGauge level={stats?.overview?.threatLevel} stats={stats} />
              </div>
              <div className="grid-2 mb">
                <AttackDonut distribution={stats?.attackDistribution} />
                <TopAttackers data={topSrc} />
              </div>
              <div className="grid-2 mb">
                <LiveFeed />
                <RecentAlerts alerts={stats?.recentAlerts} />
              </div>
            </>
          )}

          {/* URL SCANNER */}
          {page === "urlscanner" && <UrlScanner />}

          {/* ALERTS */}
          {page === "alerts" && <AlertsTable />}

          {/* ANALYTICS */}
          {page === "analytics" && (
            <>
              <div style={{ marginBottom: 24 }}>
                <h2 style={{
                  fontSize: "1.45rem",
                  fontWeight: 700,
                  background: "linear-gradient(135deg, var(--blue), var(--cyan))",
                  WebkitBackgroundClip: "text",
                  backgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                }}>
                  Analytics & Insights
                </h2>
                <p style={{ color: "var(--text-dim)", fontSize: "0.85rem", marginTop: 4 }}>
                  Deep analysis of network intrusion patterns and model performance
                </p>
              </div>
              <div className="mb">
                <TimelineChart />
              </div>
              <div className="grid-2 mb">
                <SeverityHeatmap />
                <ProtocolBreakdown />
              </div>
              <div className="mb">
                <ModelMetrics />
              </div>
            </>
          )}

          {/* PREDICTION */}
          {page === "prediction" && <PredictionPanel />}

          {/* SETTINGS */}
          {page === "settings" && <Settings />}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <SocketProvider>
        <MainApp />
      </SocketProvider>
    </ThemeProvider>
  );
}
