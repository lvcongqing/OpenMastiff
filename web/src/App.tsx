import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { getBootstrapStatus } from "./api/client";
import { useI18n } from "./i18n/LocaleContext";
import AppLayout from "./layout/AppLayout";
import { getAuthToken, getAuthUser } from "./auth";
import { canManageRequests } from "./utils/requestActions";
import Dashboard from "./pages/Dashboard";
import LoginPage from "./pages/LoginPage";
import SetupPage from "./pages/SetupPage";
import RequestsList from "./pages/RequestsList";
import RequestNew from "./pages/RequestNew";
import RequestDetail from "./pages/RequestDetail";
import ScanRunDetail from "./pages/ScanRunDetail";
import ReviewInbox from "./pages/ReviewInbox";
import PolicyPage from "./pages/PolicyPage";
import CredentialsPage from "./pages/CredentialsPage";
import RolesPage from "./pages/RolesPage";
type AppRole = string;

function RequireAuth({ children }: { children: JSX.Element }) {
  const token = getAuthToken();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function RequireRole({ children, roles }: { children: JSX.Element; roles: AppRole[] }) {
  const user = getAuthUser();
  const userRoles = (user?.roles && user.roles.length ? user.roles : [user?.role || "viewer"]) as AppRole[];
  if (!roles.some((r) => userRoles.includes(r))) {
    return <Navigate to="/" replace />;
  }
  return children;
}

function RequireCreateRequest({ children }: { children: JSX.Element }) {
  if (!canManageRequests()) {
    return <Navigate to="/requests" replace />;
  }
  return children;
}

export default function App() {
  const { t } = useI18n();
  const [boot, setBoot] = useState<{ checked: boolean; initialized: boolean; error?: string }>({
    checked: false,
    initialized: false,
  });

  useEffect(() => {
    (async () => {
      try {
        const s = await getBootstrapStatus();
        if (typeof s?.initialized !== "boolean") {
          setBoot({ checked: true, initialized: false, error: "app.bootStatusFail" });
          return;
        }
        setBoot({ checked: true, initialized: s.initialized });
      } catch {
        setBoot({ checked: true, initialized: false, error: "app.bootConnectFail" });
      }
    })();
  }, []);

  if (!boot.checked) {
    return <div style={{ padding: 24 }}>{t("common.loading")}</div>;
  }

  if (boot.error) {
    return <div style={{ padding: 24 }}>{t(boot.error)}</div>;
  }

  if (!boot.initialized) {
    return (
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/setup" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/requests" element={<RequestsList />} />
        <Route
          path="/requests/new"
          element={
            <RequireCreateRequest>
              <RequestNew />
            </RequireCreateRequest>
          }
        />
        <Route path="/requests/batch" element={<Navigate to="/requests/new?tab=batch" replace />} />
        <Route path="/requests/:requestId" element={<RequestDetail />} />
        <Route path="/requests/:requestId/scans/:scanRunId" element={<ScanRunDetail />} />
        <Route path="/review/inbox" element={<ReviewInbox />} />
        <Route
          path="/policy"
          element={
            <RequireRole roles={["admin"]}>
              <PolicyPage />
            </RequireRole>
          }
        />
        <Route
          path="/credentials"
          element={
            <RequireRole roles={["admin"]}>
              <CredentialsPage />
            </RequireRole>
          }
        />
        <Route
          path="/roles"
          element={
            <RequireRole roles={["admin"]}>
              <RolesPage />
            </RequireRole>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
