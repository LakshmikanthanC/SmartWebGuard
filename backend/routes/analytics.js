const router = require("express").Router();
const Alert = require("../models/Alert");

router.get("/dashboard", async (req, res, next) => {
  try {
    const now = new Date();
    const h24 = new Date(now - 864e5);
    const d7 = new Date(now - 6048e5);

    const [totalAlerts, alerts24h, bySeverity, byType, recent, hourly, unack] = await Promise.all([
      Alert.countDocuments(),
      Alert.countDocuments({ timestamp: { $gte: h24 } }),
      Alert.aggregate([{ $match: { timestamp: { $gte: d7 } } }, { $group: { _id: "$severity", count: { $sum: 1 } } }]),
      Alert.aggregate([{ $match: { timestamp: { $gte: d7 } } }, { $group: { _id: "$attackType", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Alert.find().sort({ timestamp: -1 }).limit(10).select("timestamp attackType severity sourceIP confidence destinationIP protocol").lean(),
      Alert.aggregate([
        { $match: { timestamp: { $gte: h24 } } },
        { $group: { _id: { $dateToString: { format: "%H:00", date: "$timestamp" } }, count: { $sum: 1 }, avgConf: { $avg: "$confidence" } } },
        { $sort: { _id: 1 } },
      ]),
      Alert.countDocuments({ acknowledged: false }),
    ]);

    const sevDist = {};
    bySeverity.forEach((i) => (sevDist[i._id] = i.count));
    const atkDist = {};
    byType.forEach((i) => (atkDist[i._id] = i.count));

    res.json({
      overview: {
        totalAlerts, alerts24h, unacknowledged: unack,
        threatLevel: alerts24h > 100 ? "critical" : alerts24h > 50 ? "high" : alerts24h > 10 ? "medium" : "low",
      },
      severityDistribution: sevDist,
      attackDistribution: atkDist,
      recentAlerts: recent,
      hourlyTrend: hourly,
    });
  } catch (err) { next(err); }
});

router.get("/attack-timeline", async (req, res, next) => {
  try {
    const { period = "24h" } = req.query;
    const ms = { "1h": 36e5, "24h": 864e5, "7d": 6048e5, "30d": 2592e6 };
    const fmt = { "1h": "%H:%M", "24h": "%H:00", "7d": "%m-%d", "30d": "%m-%d" };
    const since = new Date(Date.now() - (ms[period] || 864e5));

    const data = await Alert.aggregate([
      { $match: { timestamp: { $gte: since } } },
      { $group: { _id: { t: { $dateToString: { format: fmt[period] || "%H:00", date: "$timestamp" } }, type: "$attackType" }, count: { $sum: 1 } } },
      { $sort: { "_id.t": 1 } },
    ]);

    const map = {};
    data.forEach(({ _id, count }) => {
      if (!map[_id.t]) map[_id.t] = { time: _id.t };
      map[_id.t][_id.type] = count;
    });
    res.json(Object.values(map));
  } catch (err) { next(err); }
});

router.get("/top-sources", async (req, res, next) => {
  try {
    const top = await Alert.aggregate([
      { $group: { _id: "$sourceIP", count: { $sum: 1 }, types: { $addToSet: "$attackType" }, last: { $max: "$timestamp" } } },
      { $sort: { count: -1 } }, { $limit: +(req.query.limit || 10) },
    ]);
    res.json(top);
  } catch (err) { next(err); }
});

module.exports = router;