import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from "react";
import { io } from "socket.io-client";

const defaultSocketContext = {
  socket: null,
  connected: false,
  alerts: [],
  feed: [],
  liveStats: { total: 0, normal: 0, malicious: 0, perType: {} },
  countryStats: {},
  connectionError: null,
  clearAlerts: () => {},
  clearFeed: () => {},
  resetStats: () => {},
  clearCountryStats: () => {},
};

const Ctx = createContext(defaultSocketContext);
export const useSocket = () => useContext(Ctx) || defaultSocketContext;

export function SocketProvider({ children }) {
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [feed, setFeed] = useState([]);
  const [liveStats, setLiveStats] = useState({ total: 0, normal: 0, malicious: 0, perType: {} });
  const [countryStats, setCountryStats] = useState({});
  const [connectionError, setConnectionError] = useState(null);
  const ref = useRef(null);

  useEffect(() => {
    // Direct connection to backend for WebSocket
    const socketUrl = import.meta.env.VITE_SOCKET_URL || "http://localhost:4000";
    const sock = io(socketUrl, {
      transports: ["websocket", "polling"], reconnection: true,
      reconnectionDelay: 1000, reconnectionAttempts: Infinity,
    });
    ref.current = sock;

    sock.on("connect", () => { setConnected(true); setConnectionError(null); sock.emit("start_monitoring"); });
    sock.on("disconnect", () => setConnected(false));

    sock.on("connect_error", (error) => {
      console.error("Socket connection error:", error);
      setConnectionError(error.message || "Network Error");
    });

    sock.on("reconnect_error", (error) => {
      console.error("Socket reconnection error:", error);
      setConnectionError(error.message || "Reconnection Failed");
    });

    sock.on("reconnect", () => {
      setConnectionError(null);
    });

    sock.on("new_alert", (a) => setAlerts((p) => [a, ...p].slice(0, 500)));

    sock.on("traffic_update", (d) => {
      setFeed((p) => [d, ...p].slice(0, 200));
      setLiveStats((prev) => ({
        total: prev.total + 1,
        normal: prev.normal + (d.is_malicious ? 0 : 1),
        malicious: prev.malicious + (d.is_malicious ? 1 : 0),
        perType: {
          ...prev.perType,
          [d.prediction]: (prev.perType[d.prediction] || 0) + 1,
        },
      }));
      // Track country data in real-time
      if (d.sourceCountry) {
        setCountryStats((prev) => ({
          ...prev,
          [d.sourceCountry]: (prev[d.sourceCountry] || 0) + 1,
        }));
      }
    });

    return () => sock.disconnect();
  }, []);

  const clearAlerts = useCallback(() => setAlerts([]), []);
  const clearFeed = useCallback(() => setFeed([]), []);
  const resetStats = useCallback(() => setLiveStats({ total: 0, normal: 0, malicious: 0, perType: {} }), []);
  const clearCountryStats = useCallback(() => setCountryStats({}), []);

  return (
    <Ctx.Provider value={{ socket: ref.current, connected, alerts, feed, liveStats, countryStats, connectionError, clearAlerts, clearFeed, resetStats, clearCountryStats }}>
      {children}
    </Ctx.Provider>
  );
}
