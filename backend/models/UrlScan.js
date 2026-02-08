const mongoose = require("mongoose");

const urlScanSchema = new mongoose.Schema(
  {
    url: { type: String, required: true, index: true },
    urlHash: { type: String, index: true },
    scanType: {
      type: String,
      enum: ["deep", "quick"],
      default: "deep",
    },
    safe: { type: Boolean, required: true },
    riskScore: { type: Number, min: 0, max: 100 },
    riskLevel: {
      type: String,
      enum: ["safe", "low", "medium", "high", "critical"],
    },
    threats: [{ type: String }],
    warnings: [{ type: String }],
    info: [{ type: String }],
    recommendations: [{ type: String }],
    malwareIndicators: [{ type: String }],
    phishingIndicators: [{ type: String }],
    analysis: { type: mongoose.Schema.Types.Mixed },
    scanDuration: { type: Number },
  },
  { timestamps: true }
);

urlScanSchema.index({ createdAt: -1 });
urlScanSchema.index({ riskLevel: 1 });
urlScanSchema.index({ safe: 1 });

module.exports = mongoose.model("UrlScan", urlScanSchema);