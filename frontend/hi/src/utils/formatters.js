export const fmtTime = (t) => new Date(t).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const fmtDate = (t) => new Date(t).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
export const fmtPct = (v) => `${(v * 100).toFixed(1)}%`;
export const fmtNum = (n) => (n || 0).toLocaleString();

export const sevColor = (s) => ({
  none: "#00e67a", low: "#8bc34a", medium: "#ff9800", high: "#ff4757", critical: "#a855f7",
}[s] || "#5c6490");

export const sevBg = (s) => ({
  none: "rgba(0,230,122,0.12)", low: "rgba(139,195,74,0.12)", medium: "rgba(255,152,0,0.12)",
  high: "rgba(255,71,87,0.12)", critical: "rgba(168,85,247,0.12)",
}[s] || "rgba(92,100,144,0.12)");

export const atkIcon = (t) => ({ dos: "🔥", probe: "🔍", r2l: "🔓", u2r: "⚠️", normal: "✅" }[t] || "❓");
export const atkColor = (t) => ({ dos: "#ff4757", probe: "#ff9800", r2l: "#4d8dff", u2r: "#a855f7", normal: "#00e67a" }[t] || "#5c6490");