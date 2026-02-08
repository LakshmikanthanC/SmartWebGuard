const router = require("express").Router();
const Alert = require("../models/Alert");

router.get("/", async (req, res, next) => {
  try {
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