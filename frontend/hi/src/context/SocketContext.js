import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from "react";
import { io } from "socket.io-client";

const Ctx = createContext(null);
export const useSocket = () => useContext(Ctx);

export function SocketProvider({ children }) {
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [feed, setFeed] = useState([]);
  const [liveStats, setLiveStats] = useState({ total: 0, normal: 0, malicious: 0, perType: {} });
  const ref = useRef(null);

  useEffect(() => {
    const sock = io(process.env.REACT_APP_SOCKET_URL || "http://localhost:4000", {
      transports: ["websocket", "polling"], reconnection: true,
      reconnectionDelay: 1000, reconnectionAttempts: Infinity,
    });
    ref.current = sock;

    sock.on("connect", () => { setConnected(true); sock.emit("start_monitoring"); });
    sock.on("disconnect", () => setConnected(false));

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
    });

    return () => sock.disconnect();
  }, []);

  const clearAlerts = useCallback(() => setAlerts([]), []);
  const clearFeed = useCallback(() => setFeed([]), []);
  const resetStats = useCallback(() => setLiveStats({ total: 0, normal: 0, malicious: 0, perType: {} }), []);

  return (
    <Ctx.Provider value={{ socket: ref.current, connected, alerts, feed, liveStats, clearAlerts, clearFeed, resetStats }}>
      {children}
    </Ctx.Provider>
  );
}