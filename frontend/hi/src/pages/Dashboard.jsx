import { useEffect, useState } from "react";
import api from "../services/api";
import TrafficChart from "../components/dashboard/TrafficChart";
import Recommendations from "../components/Recommendations";
import WebsiteChecklist from "../components/WebsiteChecklist";

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);

  // Load history once on mount
  useEffect(() => {
    api.get("/alerts").then(r => setAlerts(r.data)).catch(console.error);
  }, []);

  // Prepare chart data (last 30 alerts, reverse order)
  const chartData = alerts
    .slice(0, 30)
    .map(a => ({
      time: new Date(a.timestamp).toLocaleTimeString(),
      dos: a.severity === "dos" ? 1 : 0,
      probe: a.severity === "probe" ? 1 : 0,
      r2l: a.severity === "r2l" ? 1 : 0,
      u2r: a.severity === "u2r" ? 1 : 0
    }))
    .reverse();

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Live Dashboard</h1>

      <TrafficChart timeline={chartData} />

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
