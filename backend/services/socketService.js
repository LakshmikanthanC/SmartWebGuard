let io = null;

module.exports = {
  init(ioInstance) {
    io = ioInstance;
    io.on("connection", (socket) => {
      console.log(`[WS] Connected: ${socket.id}`);
      socket.emit("connected", { id: socket.id, time: new Date().toISOString() });
      socket.on("start_monitoring", () => socket.join("monitor"));
      socket.on("stop_monitoring", () => socket.leave("monitor"));
      socket.on("disconnect", () => console.log(`[WS] Disconnected: ${socket.id}`));
    });
  },
  emitAlert(alert) { if (io) io.to("monitor").emit("new_alert", alert); },
  emitTraffic(data) { if (io) io.to("monitor").emit("traffic_update", data); },
  emitStats(data) { if (io) io.to("monitor").emit("stats_update", data); },
};