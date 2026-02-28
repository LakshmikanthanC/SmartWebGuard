import React, { useEffect, useState, useMemo } from "react";
import { Bar } from "react-chartjs-2";
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from "chart.js";
import { fmtNum } from "../../utils/formatters";
import { getCountryDistribution } from "../../services/api";
import { useSocket } from "../../context/SocketContext";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

// Country code to name mapping
const countryNames = {
  US: "United States", CN: "China", RU: "Russia", DE: "Germany", FR: "France",
  GB: "United Kingdom", JP: "Japan", IN: "India", BR: "Brazil", CA: "Canada",
  AU: "Australia", KR: "South Korea", NL: "Netherlands", IT: "Italy", ES: "Spain",
  IR: "Iran", UA: "Ukraine", PL: "Poland", TR: "Turkey", VN: "Vietnam",
  ID: "Indonesia", TH: "Thailand", MY: "Malaysia", PH: "Philippines", SG: "Singapore",
  MX: "Mexico", AR: "Argentina", CO: "Colombia", CL: "Chile", PE: "Peru",
  EG: "Egypt", NG: "Nigeria", ZA: "South Africa", KE: "Kenya", MA: "Morocco",
  RO: "Romania", SE: "Sweden", NO: "Norway", FI: "Finland", DK: "Denmark",
  CH: "Switzerland", AT: "Austria", BE: "Belgium", IE: "Ireland", PT: "Portugal",
  GR: "Greece", CZ: "Czech Republic", HU: "Hungary", IL: "Israel", SA: "Saudi Arabia",
  AE: "United Arab Emirates", PK: "Pakistan", BD: "Bangladesh", Unknown: "Unknown",
};

const getCountryName = (code) => countryNames[code] || code;

const countryColors = {
  US: "#3b82f6", CN: "#ef4444", RU: "#f97316", DE: "#22c55e", FR: "#8b5cf6",
  GB: "#ec4899", JP: "#06b6d4", IN: "#eab308", BR: "#84cc16", CA: "#f43f5e",
  default: "#6366f1",
};

const getCountryColor = (code) => countryColors[code] || countryColors.default;

export default function CountryMap() {
  const { countryStats } = useSocket();
  const [countryData, setCountryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState("24h");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await getCountryDistribution(period);
        setCountryData(res.data);
      } catch (err) {
        console.error("Failed to fetch country data:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [period]);

  // Merge real-time country stats with historical data - must be called before any early returns
  const mergedData = useMemo(() => {
    if (!countryData?.countries) return [];
    
    const merged = [...countryData.countries];
    
    // Add real-time data from socket
    Object.entries(countryStats).forEach(([country, count]) => {
      const existing = merged.find(c => c.country === country);
      if (existing) {
        existing.count += count;
      } else {
        merged.push({ country, count, types: [] });
      }
    });
    
    // Sort by count descending
    merged.sort((a, b) => b.count - a.count);
    
    return merged;
  }, [countryData, countryStats]);

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        </div>
        <div className="loading-state">Loading...</div>
      </div>
    );
  }

  if (mergedData.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        </div>
        <div className="empty-state">
          <div className="empty-icon">🌍</div>
          <p>No country data available</p>
        </div>
      </div>
    );
  }

  const countries = mergedData.slice(0, 10);
  const total = countryData?.total || 0;
  const realtimeTotal = Object.values(countryStats).reduce((a, b) => a + b, 0);
  const displayTotal = total + realtimeTotal;

  const labels = countries.map((c) => getCountryName(c.country));
  const values = countries.map((c) => c.count);
  const colors = countries.map((c) => getCountryColor(c.country));

  const data = {
    labels,
    datasets: [{
      label: "Attacks",
      data: values,
      backgroundColor: colors.map((c) => c + "80"),
      borderColor: colors,
      borderWidth: 1,
      borderRadius: 4,
    }],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: "y",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#1a2055",
        titleColor: "#e4e7f1",
        bodyColor: "#8f96b8",
        borderColor: "#2a3370",
        borderWidth: 1,
        cornerRadius: 8,
        callbacks: {
          title: (items) => getCountryName(items[0].label),
          label: (ctx) => ` ${fmtNum(ctx.parsed.x)} attacks`,
        },
      },
    },
    scales: {
      x: {
        grid: { color: "#2a3370" },
        ticks: { color: "#8f96b8" },
      },
      y: {
        grid: { display: false },
        ticks: { color: "#8f96b8", font: { size: 11 } },
      },
    },
  };

  return (
    <div className="card">
      <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        <select
          value={period}
          onChange={(e) => setPeriod(e.target.value)}
          style={{ background: "#1a2055", color: "#8f96b8", border: "1px solid #2a3370", padding: "4px 8px", borderRadius: "4px", fontSize: "0.75rem" }}
        >
          <option value="1h">Last Hour</option>
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
        </select>
      </div>
      <div style={{ maxHeight: 300, overflowY: "auto", position: "relative" }}>
        <Bar data={data} options={options} />
      </div>
      <div style={{ padding: "12px 0 0", borderTop: "1px solid #2a3370", marginTop: "8px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "#8f96b8" }}>
          <span>Total: <strong style={{ color: "#e4e7f1" }}>{fmtNum(displayTotal)}</strong> attacks</span>
          <span>Top: <strong style={{ color: "#e4e7f1" }}>{countries[0]?.country ? getCountryName(countries[0].country) : "N/A"}</strong></span>
        </div>
      </div>
    </div>
  );
}
