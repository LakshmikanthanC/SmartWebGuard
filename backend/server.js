require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const morgan = require("morgan");
const connectDB = require("./config/db");
const errorHandler = require("./middleware/errorHandler");
const socketService = require("./services/socketService");
const { genTraffic, randIP, randPort } = require("./utils/helpers");
const bridge = require("./services/pythonBridge");
const Alert = require("./models/Alert");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL || "http://localhost:3000", methods: ["GET", "POST"] },
});
socketService.init(io);

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(morgan("dev"));

// Add with other app.use route lines:
app.use("/api/url", require("./routes/urlscan"));

app.use("/api/predict", require("./routes/predict"));
app.use("/api/alerts", require("./routes/alerts"));
app.use("/api/analytics", require("./routes/analytics"));

app.get("/api/health", async (req, res) => {
  const ai = await bridge.healthCheck();
  res.json({ status: "healthy", ai_engine: ai, uptime: process.uptime() });
});

// Simulation
let simTimer = null;
const startSim = () => {
  if (simTimer) return;
  simTimer = setInterval(async () => {
    try {
      const feat = genTraffic();
      feat.source_ip = randIP(); feat.dest_ip = randIP();
      feat.source_port = randPort(); feat.dest_port = randPort();
      let pred;
      try { pred = await bridge.predict(feat); } catch {
        const types = ["normal", "dos", "probe", "r2l", "u2r"];
        const w = [0.6, 0.18, 0.12, 0.06, 0.04];
        let r = Math.random(), c = 0, s = "normal";
        for (let i = 0; i < types.length; i++) { c += w[i]; if (r <= c) { s = types[i]; break; } }
        const sev = { normal: "none", dos: "high", probe: "medium", r2l: "high", u2r: "critical" };
        pred = { prediction: s, confidence: 0.7 + Math.random() * 0.29, severity: sev[s], is_malicious: s !== "normal", probabilities: {} };
      }
      socketService.emitTraffic({
        timestamp: new Date().toISOString(), sourceIP: feat.source_ip, destinationIP: feat.dest_ip,
        sourcePort: feat.source_port, destinationPort: feat.dest_port,
        protocol: feat.protocol_type, prediction: pred.prediction,
        confidence: pred.confidence, is_malicious: pred.is_malicious, severity: pred.severity,
      });
      if (pred.is_malicious) {
        const alert = await Alert.create({
          sourceIP: feat.source_ip, destinationIP: feat.dest_ip,
          sourcePort: feat.source_port, destinationPort: feat.dest_port,
          protocol: feat.protocol_type, attackType: pred.prediction,
          severity: pred.severity, confidence: pred.confidence,
          probabilities: pred.probabilities, rawFeatures: feat,
        });
        socketService.emitAlert({
          _id: alert._id, timestamp: alert.timestamp, sourceIP: alert.sourceIP,
          destinationIP: alert.destinationIP, sourcePort: alert.sourcePort,
          destinationPort: alert.destinationPort, attackType: alert.attackType,
          severity: alert.severity, confidence: alert.confidence,
        });
      }
    } catch {}
  }, 1500);
};

app.post("/api/simulation/start", (_, res) => { startSim(); res.json({ status: "started" }); });
app.post("/api/simulation/stop", (_, res) => { clearInterval(simTimer); simTimer = null; res.json({ status: "stopped" }); });
app.get("/api/simulation/status", (_, res) => res.json({ running: !!simTimer }));
app.use(errorHandler);

const PORT = process.env.PORT || 4000;
(async () => {
  await connectDB();
  server.listen(PORT, () => {
    console.log(`\n  🛡️  AI-NIDS Backend on port ${PORT}\n`);
    startSim(); // Always start simulation for demo
  });
})();
