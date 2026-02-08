const router = require("express").Router();
const bridge = require("../services/pythonBridge");
const Alert = require("../models/Alert");
const { emitAlert } = require("../services/socketService");
const { randIP, randPort } = require("../utils/helpers");

router.post("/", async (req, res, next) => {
  try {
    const features = req.body;
    if (!features || !Object.keys(features).length)
      return res.status(400).json({ error: "No features provided" });

    const prediction = await bridge.predict(features);

    if (prediction.is_malicious) {
      const alert = await Alert.create({
        sourceIP: features.source_ip || randIP(),
        destinationIP: features.dest_ip || randIP(),
        sourcePort: features.source_port || randPort(),
        destinationPort: features.dest_port || randPort(),
        protocol: features.protocol_type || "tcp",
        attackType: prediction.prediction,
        severity: prediction.severity,
        confidence: prediction.confidence,
        probabilities: prediction.probabilities,
        rawFeatures: features,
      });
      emitAlert({
        _id: alert._id, timestamp: alert.timestamp,
        sourceIP: alert.sourceIP, destinationIP: alert.destinationIP,
        attackType: alert.attackType, severity: alert.severity,
        confidence: alert.confidence,
      });
    }
    res.json(prediction);
  } catch (err) { next(err); }
});

router.get("/health", async (req, res) => {
  res.json(await bridge.healthCheck());
});

router.get("/model-info", async (req, res, next) => {
  try { res.json(await bridge.getModelInfo()); }
  catch (err) { next(err); }
});

router.post("/train", async (req, res, next) => {
  try { res.json(await bridge.triggerTraining()); }
  catch (err) { next(err); }
});

module.exports = router;