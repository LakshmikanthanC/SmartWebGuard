require("dotenv").config({ path: "../backend/.env" });
const mongoose = require("mongoose");

const AlertSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  sourceIP: String,
  destinationIP: String,
  sourcePort: Number,
  destinationPort: Number,
  protocol: String,
  attackType: String,
  severity: String,
  confidence: Number,
  probabilities: mongoose.Schema.Types.Mixed,
  acknowledged: { type: Boolean, default: false },
}, { timestamps: true });

const Alert = mongoose.model("Alert", AlertSchema);

const randIP = () =>
  Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join(".");
const randPort = () => Math.floor(Math.random() * 65535) + 1;

const types = ["dos", "probe", "r2l", "u2r"];
const sevMap = { dos: "high", probe: "medium", r2l: "high", u2r: "critical" };
const protos = ["tcp", "udp", "icmp"];

async function seed() {
  await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/ai_nids");
  console.log("Connected to MongoDB");

  await Alert.deleteMany({});
  console.log("Cleared existing alerts");

  const alerts = [];
  const now = Date.now();

  for (let i = 0; i < 500; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const hoursAgo = Math.random() * 168;

    alerts.push({
      timestamp: new Date(now - hoursAgo * 3600000),
      sourceIP: randIP(),
      destinationIP: randIP(),
      sourcePort: randPort(),
      destinationPort: randPort(),
      protocol: protos[Math.floor(Math.random() * protos.length)],
      attackType: type,
      severity: sevMap[type],
      confidence: +(0.65 + Math.random() * 0.34).toFixed(3),
      probabilities: {
        normal: +(Math.random() * 0.2).toFixed(3),
        dos: +(type === "dos" ? 0.5 + Math.random() * 0.5 : Math.random() * 0.2).toFixed(3),
        probe: +(type === "probe" ? 0.5 + Math.random() * 0.5 : Math.random() * 0.15).toFixed(3),
        r2l: +(type === "r2l" ? 0.5 + Math.random() * 0.5 : Math.random() * 0.1).toFixed(3),
        u2r: +(type === "u2r" ? 0.5 + Math.random() * 0.5 : Math.random() * 0.05).toFixed(3),
      },
      acknowledged: Math.random() < 0.3,
    });
  }

  await Alert.insertMany(alerts);
  console.log(`Seeded ${alerts.length} alerts`);

  await mongoose.disconnect();
  console.log("Done!");
}

seed().catch(console.error);