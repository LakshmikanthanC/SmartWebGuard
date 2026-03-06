/* eslint-disable no-console */
const DEFAULT_URL = process.env.CHAT_API_URL || "http://localhost:4000/api/ai/chat";

async function main() {
  const message = process.argv.slice(2).join(" ").trim() || "what is sql injection";
  const payload = { message, history: [] };

  const res = await fetch(DEFAULT_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`Request failed: ${res.status} ${txt}`);
  }

  const data = await res.json();
  console.log(`source: ${data?.source || "unknown"}`);
  console.log("reply:");
  console.log(data?.reply || data?.message || data?.text || "(empty)");
}

main().catch((err) => {
  console.error(err.message || err);
  process.exitCode = 1;
});
