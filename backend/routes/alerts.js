const router = require("express").Router();
const Alert = require("../models/Alert");
const { randIP, randPort } = require("../utils/helpers");

const AUTO_SEED_ALERTS = process.env.AUTO_SEED_ALERTS !== "false";
const MIN_ALERTS = Number(process.env.AUTO_SEED_ALERTS_MIN || 100);

const ATTACK_TYPES = ["dos", "probe", "r2l", "u2r"];
const SEVERITIES = ["low", "medium", "high", "critical"];
const PROTOCOLS = ["tcp", "udp", "icmp"];
const COUNTRIES = ["US", "IN", "DE", "GB", "FR", "SG", "JP", "BR", "AU", "CA"];

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randBetween = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(randBetween(min, max + 1));

const attackToSeverity = (type) => {
  switch (type) {
    case "dos": return "high";
    case "probe": return "medium";
    case "r2l": return "high";
    case "u2r": return "critical";
    default: return "medium";
  }
};

const makeAlert = () => {
  const attackType = pick(ATTACK_TYPES);
  const severity = attackToSeverity(attackType);
  const now = Date.now();
  const ts = new Date(now - randInt(0, 24 * 60 * 60 * 1000));
  return {
    timestamp: ts,
    sourceIP: randIP(),
    destinationIP: randIP(),
    sourceCountry: pick(COUNTRIES),
    destinationCountry: pick(COUNTRIES),
    sourcePort: randPort(),
    destinationPort: randPort(),
    protocol: pick(PROTOCOLS),
    attackType,
    severity,
    confidence: Number(randBetween(0.7, 0.99).toFixed(2)),
    probabilities: { [attackType]: Number(randBetween(0.7, 0.99).toFixed(2)) },
    acknowledged: Math.random() < 0.2,
    explanation: "Auto-generated demo alert",
    recommendations: ["Inspect source host", "Block offending IP", "Review firewall rules"],
  };
};

const ensureMinAlerts = async () => {
  if (!AUTO_SEED_ALERTS) return;
  const total = await Alert.countDocuments();
  if (total >= MIN_ALERTS) return;
  const toCreate = MIN_ALERTS - total;
  const docs = Array.from({ length: toCreate }, () => makeAlert());
  await Alert.insertMany(docs);
};

router.get("/", async (req, res, next) => {
  try {
    await ensureMinAlerts();
    const { page = 1, limit = 20, severity, attackType, acknowledged, sortBy = "timestamp", sortOrder = "desc" } = req.query;
    const filter = {};
    if (severity) filter.severity = severity;
    if (attackType) filter.attackType = attackType;
    if (acknowledged !== undefined) filter.acknowledged = acknowledged === "true";

    const [alerts, total] = await Promise.all([
      Alert.find(filter).sort({ [sortBy]: sortOrder === "asc" ? 1 : -1 })
        .skip((+page - 1) * +limit).limit(+limit).lean(),
      Alert.countDocuments(filter),
    ]);
    res.json({ alerts, pagination: { page: +page, limit: +limit, total, pages: Math.ceil(total / +limit) } });
  } catch (err) { next(err); }
});

router.get("/recent", async (req, res, next) => {
  try {
    await ensureMinAlerts();
    const alerts = await Alert.find().sort({ timestamp: -1 }).limit(+(req.query.limit || 20)).lean();
    res.json(alerts);
  } catch (err) { next(err); }
});

router.get("/:id", async (req, res, next) => {
  try {
    const alert = await Alert.findById(req.params.id).lean();
    if (!alert) return res.status(404).json({ error: "Not found" });
    res.json(alert);
  } catch (err) { next(err); }
});

router.patch("/:id/acknowledge", async (req, res, next) => {
  try {
    const alert = await Alert.findByIdAndUpdate(req.params.id,
      { acknowledged: true, notes: req.body.notes || "" }, { new: true });
    if (!alert) return res.status(404).json({ error: "Not found" });
    res.json(alert);
  } catch (err) { next(err); }
});

router.delete("/:id", async (req, res, next) => {
  try {
    await Alert.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) { next(err); }
});

module.exports = router;
