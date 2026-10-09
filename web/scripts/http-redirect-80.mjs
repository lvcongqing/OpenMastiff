#!/usr/bin/env node
/** HTTP :80 → HTTPS :443 重定向（与 Vite HTTPS 开发服务配合） */
import http from "node:http";

const httpPort = Number(process.env.VITE_DEV_HTTP_PORT || 80);
const httpsPort = Number(process.env.VITE_DEV_HTTPS_PORT || 443);

function httpsLocation(req) {
  const hostHeader = req.headers.host || "localhost";
  const host = hostHeader.split(":")[0];
  const portPart = httpsPort === 443 ? "" : `:${httpsPort}`;
  return `https://${host}${portPart}${req.url || "/"}`;
}

const server = http.createServer((req, res) => {
  res.writeHead(301, { Location: httpsLocation(req) });
  res.end();
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `[http-redirect] 端口 ${httpPort} 已被占用。请先执行: npm run dev:stop`
    );
    process.exit(1);
  }
  throw err;
});

server.listen(httpPort, "0.0.0.0", () => {
  const target = httpsPort === 443 ? "443" : String(httpsPort);
  console.log(`[http-redirect] :${httpPort} → https://<host>:${target}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
