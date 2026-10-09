import { Alert, Drawer, Tag, Typography } from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { getScanConsole } from "../api/client";
import { useI18n } from "../i18n/LocaleContext";

export function isLiveScanStatus(status: unknown): boolean {
  const s = String(status || "").toLowerCase();
  return s === "queued" || s === "running";
}

export default function ScanConsoleDrawer({
  scanRunId,
  open,
  onClose,
  onEnded,
}: {
  scanRunId: string | null;
  open: boolean;
  onClose: () => void;
  onEnded?: () => void;
}) {
  const { t } = useI18n();
  const [text, setText] = useState("");
  const [status, setStatus] = useState("");
  const [live, setLive] = useState(true);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState("");
  const preRef = useRef<HTMLPreElement>(null);
  const pinBottom = useRef(true);
  const endedNotified = useRef(false);
  const onEndedRef = useRef(onEnded);
  onEndedRef.current = onEnded;

  const load = useCallback(async () => {
    if (!scanRunId) return;
    try {
      const data = await getScanConsole(scanRunId);
      setText(String(data.text || ""));
      setStatus(String(data.status || ""));
      setLive(Boolean(data.live));
      setTruncated(Boolean(data.truncated));
      setError("");
      if (!data.live && !endedNotified.current) {
        endedNotified.current = true;
        onEndedRef.current?.();
      }
    } catch {
      setError(t("request.consoleLoadFail"));
    }
  }, [scanRunId, t]);

  useEffect(() => {
    if (!open || !scanRunId) return;
    endedNotified.current = false;
    pinBottom.current = true;
    setText("");
    setStatus("");
    setLive(true);
    setTruncated(false);
    setError("");
    void load();
  }, [open, scanRunId, load]);

  useEffect(() => {
    if (!open || !scanRunId || !live) return;
    const timer = window.setInterval(() => {
      void load();
    }, 1000);
    return () => window.clearInterval(timer);
  }, [open, scanRunId, live, load]);

  useEffect(() => {
    const el = preRef.current;
    if (el && pinBottom.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [text]);

  const display =
    text ||
    (live
      ? status === "queued"
        ? t("request.consoleWaiting")
        : t("request.consoleEmpty")
      : t("request.consoleEnded", { status: status || "—" }));

  return (
    <Drawer
      title={
        <span className="scan-console-title">
          {t("request.consoleTitle")}
          {scanRunId ? (
            <Typography.Text type="secondary" style={{ marginLeft: 8, fontWeight: 400 }}>
              {scanRunId.slice(0, 8)}…
            </Typography.Text>
          ) : null}
          {live ? (
            <Tag color="processing" style={{ marginLeft: 8 }}>
              {t("request.consoleLive")}
            </Tag>
          ) : (
            <Tag style={{ marginLeft: 8 }}>{t("request.consoleStopped")}</Tag>
          )}
        </span>
      }
      placement="right"
      width={720}
      open={open}
      onClose={onClose}
      destroyOnClose
    >
      {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} /> : null}
      {truncated ? <Alert type="info" showIcon message={t("request.consoleTruncated")} style={{ marginBottom: 12 }} /> : null}
      {!live && !error ? (
        <Alert
          type="success"
          showIcon
          message={t("request.consoleEnded", { status: status || "—" })}
          style={{ marginBottom: 12 }}
        />
      ) : null}
      <pre
        ref={preRef}
        className="scan-console-pre"
        onScroll={(e) => {
          const el = e.currentTarget;
          pinBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
        }}
      >
        {display}
      </pre>
    </Drawer>
  );
}
