import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { scanContent } from "./src/scanner";
import { getFeedbackManager } from "./src/feedback";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;
  const isProduction = process.env.NODE_ENV === "production";

  app.use(express.json({ limit: "10mb" }));

  // In-memory rate limiting map (60 scans/min per client)
  const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
  const RATE_LIMIT_WINDOW_MS = 60 * 1000;
  const MAX_REQUESTS_PER_WINDOW = 60;

  function rateLimiter(req: express.Request, res: express.Response, next: express.NextFunction) {
    const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (!entry || now > entry.resetTime) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
      return next();
    }

    if (entry.count >= MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({
        detail: "Rate limit reached (60 requests per minute). Please wait a few moments before trying again.",
      });
    }

    entry.count++;
    next();
  }

  // Root endpoint info
  app.get("/api/info", (_req, res) => {
    res.json({
      project: "PhishGuard AI",
      version: "0.3.0",
      status: "running",
      engine: "hybrid_v0.3+ml",
    });
  });

  // Benchmark metrics
  app.get("/api/benchmark", (_req, res) => {
    try {
      const p = path.resolve(__dirname, "data", "benchmark_results.json");
      if (fs.existsSync(p)) {
        return res.json(JSON.parse(fs.readFileSync(p, "utf-8")));
      }
      return res.json({ status: "unavailable" });
    } catch {
      return res.status(500).json({ detail: "Error loading benchmark data" });
    }
  });

  // Indian dataset
  app.get("/api/dataset/indian", (_req, res) => {
    try {
      const p = path.resolve(__dirname, "data", "indian_phishing_dataset.json");
      if (fs.existsSync(p)) {
        return res.json(JSON.parse(fs.readFileSync(p, "utf-8")));
      }
      return res.json({ status: "unavailable" });
    } catch {
      return res.status(500).json({ detail: "Error loading dataset" });
    }
  });

  // Health check
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // Scan content with rate limiting
  app.post("/api/scan", rateLimiter, (req, res) => {
    try {
      const { content_type = "message", content } = req.body || {};
      if (typeof content !== "string" || !content.trim()) {
        return res.status(422).json({
          detail: "Content is empty. Paste a message, email, or URL.",
        });
      }
      if (content.length > 20000) {
        return res.status(422).json({
          detail: "Content exceeds maximum allowed length of 20,000 characters.",
        });
      }

      const normalizedType = ["email", "url", "message", "journal"].includes(String(content_type).toLowerCase().trim())
        ? String(content_type).toLowerCase().trim()
        : "message";

      const result = scanContent(content, normalizedType);
      return res.json(result);
    } catch (err) {
      console.error("Scan error:", err);
      return res.status(500).json({ detail: "Internal error while scanning." });
    }
  });

  // Feedback submission
  app.post("/api/feedback", (req, res) => {
    try {
      const { content, content_type, predicted_label, user_label, findings, risk_level } = req.body || {};
      const feedbackMgr = getFeedbackManager();
      const record = feedbackMgr.addFeedback({
        content: content || "",
        content_type: content_type || "message",
        predicted_label: predicted_label || "phishing",
        user_label: user_label || "legitimate",
        findings: Array.isArray(findings) ? findings : [],
        risk_level: risk_level || "low",
      });
      return res.json({ status: "success", record_id: record.timestamp });
    } catch (err) {
      return res.status(500).json({ detail: "Error recording feedback." });
    }
  });

  // Feedback statistics
  app.get("/api/feedback/stats", (_req, res) => {
    const feedbackMgr = getFeedbackManager();
    return res.json(feedbackMgr.getFeedbackStats());
  });

  // Whitelist operations
  app.post("/api/whitelist", (req, res) => {
    const { domain, reason } = req.body || {};
    if (!domain || typeof domain !== "string") {
      return res.status(400).json({ detail: "Invalid domain" });
    }
    const feedbackMgr = getFeedbackManager();
    const result = feedbackMgr.addToWhitelist(domain, reason || "");
    if (result.error) {
      return res.status(400).json({ detail: result.error });
    }
    return res.json({ status: "success", domain });
  });

  app.delete("/api/whitelist/:domain", (req, res) => {
    const domain = req.params.domain;
    const feedbackMgr = getFeedbackManager();
    if (feedbackMgr.removeFromWhitelist(domain)) {
      return res.json({ status: "success", domain });
    }
    return res.status(404).json({ detail: "Domain not found in whitelist" });
  });

  app.get("/api/whitelist", (_req, res) => {
    const feedbackMgr = getFeedbackManager();
    return res.json({ domains: feedbackMgr.getWhitelist().map((w) => w.domain) });
  });

  // Config reload
  app.post("/api/config/reload", (_req, res) => {
    return res.json({ status: "success", message: "Configuration reloaded" });
  });

  // Frontend dev/prod serving
  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true, host: "0.0.0.0", port: 3000 },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, "dist")));
    app.get("*", (_req, res) => {
      res.sendFile(path.resolve(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`PhishGuard AI server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
