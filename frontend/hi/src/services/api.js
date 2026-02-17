import axios from "axios";

const API = import.meta.env.VITE_API_URL || "http://localhost:4000/api";
const api = axios.create({ baseURL: API, timeout: 30000 });

export const getDashboard = () => api.get("/analytics/dashboard");
export const getAlerts = (p) => api.get("/alerts", { params: p });
export const getRecentAlerts = (n = 20) => api.get(`/alerts/recent?limit=${n}`);
export const ackAlert = (id, notes) => api.patch(`/alerts/${id}/acknowledge`, { notes });
export const deleteAlert = (id) => api.delete(`/alerts/${id}`);
export const getTimeline = (p = "24h") => api.get(`/analytics/attack-timeline?period=${p}`);
export const getTopSources = (n = 10) => api.get(`/analytics/top-sources?limit=${n}`);
export const postPredict = (f) => api.post("/predict", f);
export const getModelInfo = () => api.get("/predict/model-info");
export const getAIHealth = () => api.get("/predict/health");
export const getHealth = () => api.get("/health");
export const startSim = () => api.post("/simulation/start");
export const stopSim = () => api.post("/simulation/stop");
export const getSimStatus = () => api.get("/simulation/status");

// URL Scanner - Deep & Quick
export const scanUrl = (url, deep = true) =>
  api.post("/url/scan", { url, deep_scan: deep });
export const quickScanUrl = (url) =>
  api.post("/url/scan", { url, deep_scan: false });
export const batchScanUrls = (urls, deep = false) =>
  api.post("/url/batch", { urls, deep_scan: deep });
export const getUrlHistory = (params) =>
  api.get("/url/history", { params });
export const getUrlStats = () => api.get("/url/stats");
export const getUrlScan = (id) => api.get(`/url/${id}`);
export const deleteUrlScan = (id) => api.delete(`/url/${id}`);

export default api;
