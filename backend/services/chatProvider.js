const DEFAULT_BASE_URL = process.env.OPENAI_BASE_URL || "https://api.openai.com/v1";
const DEFAULT_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const CHAT_TIMEOUT_MS = Math.max(
  1000,
  Number(process.env.OPENAI_CHAT_TIMEOUT_MS || 60000)
);

const SYSTEM_PROMPT = [
  "You are an AI assistant for a cybersecurity dashboard.",
  "Give direct, technically accurate answers.",
  "When debugging, ask for missing details only if necessary.",
  "Keep responses concise and actionable.",
].join(" ");

const mapRole = (role) => {
  if (role === "assistant" || role === "bot") return "assistant";
  return "user";
};

const normalizeMessages = (history = [], message = "") => {
  const items = Array.isArray(history) ? history : [];
  const prior = items
    .map((m) => {
      const content = String(m?.content || m?.text || "").trim();
      if (!content) return null;
      return { role: mapRole(m?.role || m?.sender), content };
    })
    .filter(Boolean)
    .slice(-8);

  return [
    { role: "system", content: SYSTEM_PROMPT },
    ...prior,
    { role: "user", content: String(message || "").trim() },
  ];
};

const hasProviderConfig = () => Boolean(process.env.OPENAI_API_KEY);

const buildUrl = () => `${DEFAULT_BASE_URL.replace(/\/$/, "")}/chat/completions`;

const createRequestBody = (message, history, stream = false) => ({
  model: DEFAULT_MODEL,
  temperature: 0.4,
  messages: normalizeMessages(history, message),
  stream,
});

const parseSseContent = (raw) => {
  const line = raw
    .split("\n")
    .find((l) => l.startsWith("data:"));
  if (!line) return null;
  const payload = line.slice(5).trim();
  if (!payload || payload === "[DONE]") return { done: true };

  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }
  const delta = parsed?.choices?.[0]?.delta?.content || "";
  const done = Boolean(parsed?.choices?.[0]?.finish_reason);
  return { delta, done };
};

async function getReply(message, history = []) {
  if (!hasProviderConfig()) {
    throw new Error("provider_not_configured");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CHAT_TIMEOUT_MS);
  const response = await fetch(buildUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify(createRequestBody(message, history, false)),
    signal: controller.signal,
  }).finally(() => clearTimeout(timer));

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`provider_request_failed_${response.status}:${text.slice(0, 200)}`);
  }

  const data = await response.json();
  return String(data?.choices?.[0]?.message?.content || "").trim();
}

async function streamReply(message, history = [], onDelta, signal) {
  if (!hasProviderConfig()) {
    throw new Error("provider_not_configured");
  }

  // Don't link external signal - handle it separately to avoid issues
  const controller = new AbortController();
  let timer = setTimeout(() => controller.abort(), CHAT_TIMEOUT_MS);
  
  // If external signal is already aborted, throw immediately
  if (signal?.aborted) {
    clearTimeout(timer);
    throw new Error("Request was cancelled");
  }
  
  // Listen for external abort
  const abortHandler = () => controller.abort();
  signal?.addEventListener("abort", abortHandler);

  try {
    const response = await fetch(buildUrl(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(createRequestBody(message, history, true)),
      signal: controller.signal,
    });
    
    // Clear timeout once we get a response - streaming has started
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }

    if (!response.ok || !response.body) {
      const text = await response.text().catch(() => "");
      throw new Error(`provider_stream_failed_${response.status}:${text.slice(0, 200)}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let full = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const events = buffer.split("\n\n");
      buffer = events.pop() || "";

      for (const evt of events) {
        const parsed = parseSseContent(evt);
        if (!parsed) continue;
        if (parsed.delta) {
          full += parsed.delta;
          if (onDelta) onDelta(parsed.delta);
        }
        if (parsed.done) {
          return full.trim();
        }
      }
    }

    return full.trim();
  } finally {
    if (timer) clearTimeout(timer);
    signal?.removeEventListener("abort", abortHandler);
  }
}

module.exports = {
  hasProviderConfig,
  getReply,
  streamReply,
};
