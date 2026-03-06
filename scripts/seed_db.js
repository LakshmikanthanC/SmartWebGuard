require("dotenv").config({ path: "../backend/.env" });
const mongoose = require("mongoose");
const geoip = require("geoip-lite");

const AlertSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  sourceIP: String,
  destinationIP: String,
  sourceCountry: String,
  destinationCountry: String,
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

// Weighted country distribution for realistic attack simulation
const COUNTRIES = [
  { code: "US", weight: 25 },
  { code: "CN", weight: 15 },
  { code: "RU", weight: 12 },
  { code: "DE", weight: 8 },
  { code: "BR", weight: 7 },
  { code: "IN", weight: 6 },
  { code: "KR", weight: 5 },
  { code: "JP", weight: 4 },
  { code: "GB", weight: 4 },
  { code: "FR", weight: 3 },
  { code: "UA", weight: 3 },
  { code: "NL", weight: 2 },
  { code: "RO", weight: 2 },
  { code: "VN", weight: 2 },
  { code: "IR", weight: 2 },
];

const COUNTRY_WEIGHTS = COUNTRIES.reduce((acc, c) => acc + c.weight, 0);

const randIP = () =>
  Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join(".");
const randPort = () => Math.floor(Math.random() * 65535) + 1;

const getCountryFromIP = (ip) => {
  try {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10 || parts[0] === 127) return null;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return null;
    if (parts[0] === 192 && parts[1] === 168) return null;
    
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      return geo.country;
    }
  } catch (e) {
    // Ignore errors
  }
  return null;
};

const getRandomCountry = () => {
  let r = Math.random() * COUNTRY_WEIGHTS;
  for (const c of COUNTRIES) {
    r -= c.weight;
    if (r <= 0) return c.code;
  }
  return "US";
};

const types = ["dos", "probe", "r2l", "u2r"];
const sevMap = { dos: "high", probe: "medium", r2l: "high", u2r: "critical" };
const protos = ["tcp", "udp", "icmp"];

async function seed() {
  if (!process.env.MONGODB_URI) {
    console.error("Error: MONGODB_URI environment variable is not set");
    process.exit(1);
  }
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connected to MongoDB");

  await Alert.deleteMany({});
  console.log("Cleared existing alerts");

  const alerts = [];
  const now = Date.now();

  for (let i = 0; i < 500; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const hoursAgo = Math.random() * 168;
    
    const sourceIP = randIP();
    const destinationIP = randIP();
    
    // Try geoip lookup first, fallback to random country
    let sourceCountry = getCountryFromIP(sourceIP);
    let destCountry = getCountryFromIP(destinationIP);
    
    if (!sourceCountry) sourceCountry = getRandomCountry();
    if (!destCountry) destCountry = getRandomCountry();

    alerts.push({
      timestamp: new Date(now - hoursAgo * 3600000),
      sourceIP,
      destinationIP,
      sourceCountry,
      destinationCountry: destCountry,
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
  console.log(`Seeded ${alerts.length} alerts with country data`);

  await mongoose.disconnect();
  console.log("Done!");
}

seed().catch(console.error);
