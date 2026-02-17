import { useEffect, useState } from "react";
import { api } from "../api";
import TrafficChart from "../components/charts/TrafficChart";
import LiveMap from "../components/maps/LiveMap";
import Recommendations from "../components/Recommendations";
import WebsiteChecklist from "../components/WebsiteChecklist";
import { useSocket } from "../hooks/useSocket";

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const liveAlert = useSocket(); // newest alert from WebSocket

  // Load history once on mount
  useEffect(() => {
    api.get("/alerts").then(r => setAlerts(r.data)).catch(console.error);
  }, []);

  // Update list when new alert arrives
  useEffect(() => {
    if (liveAlert) setAlerts(prev => [liveAlert, ...prev].slice(0, 200));
  }, [liveAlert]);

  // Prepare chart data (last 30 alerts, reverse order)
  const chartData = alerts
    .slice(0, 30)
    .map(a => ({
      time: new Date(a.timestamp).toLocaleTimeString(),
      severity: a.severity
    }))
    .reverse();

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Live Dashboard</h1>

      <TrafficChart data={chartData} />
      <LiveMap points={alerts.slice(0, 50)} />

      {alerts[0] && (
        <div className="border rounded p-4 bg-gray-50">
          <h2 className="font-semibold mb-2">Latest Alert</h2>
          <p><strong>Signature:</strong> {alerts[0].signature}</p>
          <p><strong>Src → Dst:</strong> {alerts[0].src_ip} → {alerts[0].dest_ip}</p>
          <p><strong>Severity:</strong> {alerts[0].severity}</p>
          <p><strong>File type:</strong> {alerts[0].file_type || "N/A"}</p>
          <p><strong>Explanation:</strong> {alerts[0].explanation || "None provided."}</p>

          {/* Show remediation steps */}
          <Recommendations steps={alerts[0].recommendations} />

          {/* Show UI safety checklist */}
          <WebsiteChecklist />
        </div>
      )}
    </div>
  );
}