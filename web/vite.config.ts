import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const webRoot = path.dirname(fileURLToPath(import.meta.url));
const certDir = path.join(webRoot, "certs");
const keyFile = path.join(certDir, "server.key");
const certFile = path.join(certDir, "server.crt");

const httpsEnabled = process.env.VITE_DEV_HTTPS !== "false";
const httpsPort = Number(process.env.VITE_DEV_HTTPS_PORT || 443);
const httpPort = Number(process.env.VITE_DEV_HTTP_PORT || 80);

function resolveHttps(): boolean | { key: Buffer; cert: Buffer } {
  if (!httpsEnabled) return false;
  if (fs.existsSync(keyFile) && fs.existsSync(certFile)) {
    return {
      key: fs.readFileSync(keyFile),
      cert: fs.readFileSync(certFile),
    };
  }
  console.warn(
    "[vite] 未找到 HTTPS 证书，请先执行: cd web && bash scripts/gen-dev-certs.sh"
  );
  return false;
}

const sharedServer = {
  host: true as const,
  strictPort: true,
  proxy: {
    "/api": {
      target: "http://127.0.0.1:18000",
      changeOrigin: true,
      rewrite: (p: string) => p.replace(/^\/api/, ""),
    },
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    ...sharedServer,
    port: httpsEnabled ? httpsPort : httpPort,
    https: resolveHttps(),
  },
  preview: {
    ...sharedServer,
    port: httpsEnabled ? httpsPort : httpPort,
    https: resolveHttps(),
  },
});
