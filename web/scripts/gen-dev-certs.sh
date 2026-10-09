#!/usr/bin/env bash
# 生成开发用自签名证书（web/certs/），供 Vite HTTPS :443 使用
set -euo pipefail

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${WEB_DIR}/certs"
KEY="${CERT_DIR}/server.key"
CRT="${CERT_DIR}/server.crt"

mkdir -p "${CERT_DIR}"

if [[ -f "${KEY}" && -f "${CRT}" ]]; then
  echo "证书已存在: ${CERT_DIR}"
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "错误: 需要 openssl，请先安装" >&2
  exit 1
fi

# 逗号分隔，例如: DNS:localhost,DNS:openmastiff.local,IP:127.0.0.1,IP:<服务器IP>
SAN="${VITE_DEV_CERT_SAN:-DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1}"
CN="${VITE_DEV_CERT_CN:-localhost}"

openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout "${KEY}" -out "${CRT}" \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "${KEY}"
chmod 644 "${CRT}"
echo "已生成开发证书:"
echo "  ${CRT}"
echo "  ${KEY}"
echo "访问 https 时浏览器会提示不受信任，属自签名证书正常现象。"
