const axios = require("axios");
const AI_URL = process.env.AI_ENGINE_URL || "http://localhost:5000";
const client = axios.create({ baseURL: AI_URL, timeout: 30000 });

module.exports = {
  async predict(features) {
    const { data } = await client.post("/api/predict", features);
    return data;
  },
  async getModelInfo() {
    const { data } = await client.get("/api/model/info");
    return data;
  },
  async healthCheck() {
    try {
      const { data } = await client.get("/api/health");
      return data;
    } catch {
      return { status: "unreachable" };
    }
  },
  async triggerTraining() {
    const { data } = await client.post("/api/train", {}, { timeout: 600000 });
    return data;
  },
};