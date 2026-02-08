const router = require("express").Router();
const axios = require("axios");
const UrlScan = require("../models/UrlScan");

const AI_URL = process.env.AI_ENGINE_URL || "http://localhost:5000";

// POST /api/url/scan — Deep scan
router.post("/scan", async (req, res, next) => {
  try {
    const { url, deep_scan = true } = req.body;
    if (!url || !url.trim()) {
      return res.status(400).json({ error: "URL is required" });
    }

    const cleanUrl = url.trim();

    // Cache check (1 hour)
    const cached = await UrlScan.findOne({
      url: cleanUrl,
      scanType: deep_scan ? "deep" : "quick",
      createdAt: { $gte: new Date(Date.now() - 3600000) },
    })
      .sort({ createdAt: -1 })
      .lean();

    if (cached) {
      return res.json({ ...cached, cached: true });
    }

    const endpoint = deep_scan ? "/api/url/scan" : "/api/url/quick";
    const startTime = Date.now();

    const { data: result } = await axios.post(
      `${AI_URL}${endpoint}`,
      { url: cleanUrl, deep_scan },
      { timeout: 30000 }
    );

    const scanDuration = Date.now() - startTime;

    const scan = await UrlScan.create({
      url: cleanUrl,
      urlHash: result.url_hash,
      scanType: result.scan_type || (deep_scan ? "deep" : "quick"),
      safe: result.safe,
      riskScore: result.risk_score,
      riskLevel: result.risk_level,
      threats: result.threats,
      warnings: result.warnings,
      info: result.info,
      recommendations: result.recommendations,
      analysis: result.analysis,
      malwareIndicators: result.malware_indicators,
      phishingIndicators: result.phishing_indicators,
      scanDuration: result.scan_duration_ms || scanDuration,
    });

    res.json({
      _id: scan._id,
      url: scan.url,
      scanType: scan.scanType,
      safe: scan.safe,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      threats: scan.threats,
      warnings: scan.warnings,
      info: scan.info,
      recommendations: scan.recommendations,
      analysis: scan.analysis,
      malwareIndicators: scan.malwareIndicators,
      phishingIndicators: scan.phishingIndicators,
      scanDuration: scan.scanDuration,
      timestamp: scan.createdAt,
      cached: false,
    });
  } catch (err) {
    if (err.code === "ECONNREFUSED") {
      return res
        .status(503)
        .json({ error: "AI Engine offline. Start ai-engine first." });
    }
    next(err);
  }
});

// POST /api/url/batch — Batch scan
router.post("/batch", async (req, res, next) => {
  try {
    const { urls, deep_scan = false } = req.body;
    if (!urls || !urls.length) {
      return res.status(400).json({ error: "URLs required" });
    }

    const { data } = await axios.post(
      `${AI_URL}/api/url/batch`,
      { urls: urls.slice(0, 20), deep_scan },
      { timeout: 60000 }
    );

    // Save all results
    for (const r of data.results) {
      await UrlScan.create({
        url: r.url,
        urlHash: r.url_hash,
        scanType: r.scan_type,
        safe: r.safe,
        riskScore: r.risk_score,
        riskLevel: r.risk_level,
        threats: r.threats,
        warnings: r.warnings,
        info: r.info,
        recommendations: r.recommendations,
        analysis: r.analysis,
        malwareIndicators: r.malware_indicators,
        phishingIndicators: r.phishing_indicators,
        scanDuration: r.scan_duration_ms,
      });
    }

    res.json(data);
  } catch (err) {
    next(err);
  }
});

// GET /api/url/history
router.get("/history", async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 20,
      riskLevel,
      safe,
      scanType,
    } = req.query;

    const filter = {};
    if (riskLevel) filter.riskLevel = riskLevel;
    if (safe !== undefined) filter.safe = safe === "true";
    if (scanType) filter.scanType = scanType;

    const [scans, total] = await Promise.all([
      UrlScan.find(filter)
        .sort({ createdAt: -1 })
        .skip((+page - 1) * +limit)
        .limit(+limit)
        .select(
          "url safe riskScore riskLevel scanType threats warnings " +
          "malwareIndicators phishingIndicators scanDuration createdAt"
        )
        .lean(),
      UrlScan.countDocuments(filter),
    ]);

    res.json({
      scans,
      pagination: {
        page: +page, limit: +limit, total,
        pages: Math.ceil(total / +limit),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/url/stats
router.get("/stats", async (req, res, next) => {
  try {
    const [total, safe, unsafe, byRisk, byType, recent] = await Promise.all([
      UrlScan.countDocuments(),
      UrlScan.countDocuments({ safe: true }),
      UrlScan.countDocuments({ safe: false }),
      UrlScan.aggregate([
        { $group: { _id: "$riskLevel", count: { $sum: 1 } } },
      ]),
      UrlScan.aggregate([
        { $group: { _id: "$scanType", count: { $sum: 1 } } },
      ]),
      UrlScan.find()
        .sort({ createdAt: -1 })
        .limit(5)
        .select("url safe riskScore riskLevel scanType createdAt")
        .lean(),
    ]);

    const riskDist = {};
    byRisk.forEach((r) => (riskDist[r._id] = r.count));

    const typeDist = {};
    byType.forEach((t) => (typeDist[t._id] = t.count));

    res.json({
      total, safe, unsafe,
      riskDistribution: riskDist,
      scanTypes: typeDist,
      recentScans: recent,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/url/:id
router.get("/:id", async (req, res, next) => {
  try {
    const scan = await UrlScan.findById(req.params.id).lean();
    if (!scan) return res.status(404).json({ error: "Not found" });
    res.json(scan);
  } catch (err) {
    next(err);
  }
});

// DELETE /api/url/:id
router.delete("/:id", async (req, res, next) => {
  try {
    await UrlScan.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;