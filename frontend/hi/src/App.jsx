import React, { useCallback, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import "./App.css";

import { SocketProvider } from "./context/SocketContext";
import { ThemeProvider } from "./context/ThemeContext";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { getDashboard, getTimeline, getTopSources } from "./services/api";

import Login from "./pages/Login";
import AlertsTable from "./components/alerts/AlertsTable";
import ModelMetrics from "./components/analytics/ModelMetrics";
import ProtocolBreakdown from "./components/analytics/ProtocolBreakdown";
import SeverityHeatmap from "./components/analytics/SeverityHeatmap";
import TimelineChart from "./components/analytics/TimelineChart";
import AttackDonut from "./components/dashboard/AttackDonut";
import CountryMap from "./components/dashboard/CountryMap";
import LiveFeed from "./components/dashboard/LiveFeed";
import RecentAlerts from "./components/dashboard/RecentAlerts";
import StatsCards from "./components/dashboard/StatsCards";
import ThreatGauge from "./components/dashboard/ThreatGauge";
import TopAttackers from "./components/dashboard/TopAttackers";
import TrafficChart from "./components/dashboard/TrafficChart";
import PredictionPanel from "./components/PredictionPanel";
import Settings from "./components/Settings";
import UrlScanner from "./components/UrlScanner";
import Sidebar from "./components/layout/Sidebar";
import TopBar from "./components/layout/TopBar";

// Protected Route Component
function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function MainApp() {
  const [page, setPage] = useState("urlscanner");
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topSrc, setTopSrc] = useState([]);
  const [dashboardEnabled, setDashboardEnabled] = useState(() => {
    try {
      return localStorage.getItem("swg_has_url_scan") === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    const onScanDone = () => setDashboardEnabled(true);
    const onReset = () => setDashboardEnabled(false);
    window.addEventListener("swg_url_scan_done", onScanDone);
    window.addEventListener("swg_url_scan_reset", onReset);
    return () => {
      window.removeEventListener("swg_url_scan_done", onScanDone);
      window.removeEventListener("swg_url_scan_reset", onReset);
    };
  }, []);

  const loadData = useCallback(async () => {
    if (!dashboardEnabled) return;
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
  }, [dashboardEnabled]);

  useEffect(() => {
    if (!dashboardEnabled) return;
    loadData();
    const iv = setInterval(loadData, 15000);
    return () => clearInterval(iv);
  }, [loadData]);

  return (
    <>
      <div className="app-layout">
        <Sidebar active={page} onChange={setPage} />

        <div className="app-main">
          <TopBar currentPage={page} />

          <div className="app-content">
          {/* DASHBOARD */}
          {page === "dashboard" && (
            <>
              {!dashboardEnabled ? (
                <div className="card">
                  <div className="empty">
                    <div className="empty-icon">🔒</div>
                    <p>
                      Dashboard analytics are hidden until a URL scan completes.
                      Go to URL Scanner and run a scan to enable live analytics.
                    </p>
                  </div>
                </div>
              ) : (
                <>
                  <StatsCards stats={stats} />

                  <div className="grid-2-1 mb">
                    <TrafficChart timeline={timeline} />
                    <ThreatGauge level={stats?.overview?.threatLevel} stats={stats} />
                  </div>

                  <div className="grid-2 mb">
                    <AttackDonut distribution={stats?.attackDistribution} />
                    <CountryMap />
                  </div>

                  <div className="grid-2 mb">
                    <TopAttackers data={topSrc} />
                    <LiveFeed />
                  </div>

                  <RecentAlerts alerts={stats?.recentAlerts} />
                </>
              )}
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
                <h2
                  style={{
                    fontSize: "1.45rem",
                    fontWeight: 700,
                    background: "linear-gradient(135deg, var(--blue), var(--cyan))",
                    WebkitBackgroundClip: "text",
                    backgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                  }}
                >
                  Analytics & Insights
                </h2>
                <p
                  style={{
                    color: "var(--text-dim)",
                    fontSize: "0.85rem",
                    marginTop: 4,
                  }}
                >
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

    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <SocketProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <MainApp />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </SocketProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
