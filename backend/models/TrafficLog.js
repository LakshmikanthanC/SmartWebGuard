const mongoose = require("mongoose");

const trafficLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  totalPackets: { type: Number, default: 0 },
  normalCount: { type: Number, default: 0 },
  maliciousCount: { type: Number, default: 0 },
  attackDistribution: {
    dos: { type: Number, default: 0 },
    probe: { type: Number, default: 0 },
    r2l: { type: Number, default: 0 },
    u2r: { type: Number, default: 0 },
  },
}, { timestamps: true });

module.exports = mongoose.model("TrafficLog", trafficLogSchema);