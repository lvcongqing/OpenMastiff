import { Layout, Menu, theme } from "antd";
import {
  DashboardOutlined,
  UnorderedListOutlined,
  InboxOutlined,
  SafetyCertificateOutlined,
  KeyOutlined,
  TeamOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import { clearAuthToken, getAuthUser } from "../auth";
import BrandMark from "../components/BrandMark";
import LanguageSwitcher from "../components/LanguageSwitcher";
import ThemeSwitcher from "../components/ThemeSwitcher";
import { roleLabel } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";
import { canManageRequests } from "../utils/requestActions";
import { useAppTheme } from "../theme/ThemeContext";

const { Header, Sider, Content } = Layout;

export default function AppLayout() {
  const navigate = useNavigate();
  const loc = useLocation();
  const { token } = theme.useToken();
  const { surfaces } = useAppTheme();
  const { t } = useI18n();
  const user = getAuthUser();
  const role = user?.role || "viewer";
  const roles = user?.roles || (role ? [role] : ["viewer"]);

  const selected = (() => {
    const p = loc.pathname;
    if (p.startsWith("/requests/new") || p.startsWith("/requests/batch")) return ["/requests/new"];
    if (p.startsWith("/requests/") && p !== "/requests") return ["/requests"];
    if (p === "/requests") return ["/requests"];
    if (p.startsWith("/review")) return ["/review/inbox"];
    if (p.startsWith("/policy")) return ["/policy"];
    if (p.startsWith("/credentials")) return ["/credentials"];
    if (p.startsWith("/roles")) return ["/roles"];
    return ["/"];
  })();

  return (
    <Layout className="app-shell" style={{ minHeight: "100vh", background: surfaces.pageBg }}>
      <Sider
        breakpoint="lg"
        collapsedWidth={0}
        width={220}
        theme={surfaces.menuDark ? "dark" : "light"}
        className="app-sider"
        style={{
          borderRight: surfaces.menuDark ? "none" : `1px solid ${token.colorBorderSecondary}`,
          background: `linear-gradient(180deg, ${surfaces.siderFrom} 0%, ${surfaces.siderTo} 100%)`,
        }}
      >
        <div style={{ padding: "16px 16px 12px" }}>
          <BrandMark size={42} />
        </div>
        <Menu
          mode="inline"
          theme={surfaces.menuDark ? "dark" : "light"}
          selectedKeys={selected}
          items={[
            { key: "/", icon: <DashboardOutlined />, label: t("nav.dashboard"), onClick: () => navigate("/") },
            { key: "/requests", icon: <UnorderedListOutlined />, label: t("nav.requests"), onClick: () => navigate("/requests") },
            ...(canManageRequests()
              ? [{ key: "/requests/new", icon: <PlusOutlined />, label: t("nav.requestNew"), onClick: () => navigate("/requests/new") }]
              : []),
            { key: "/review/inbox", icon: <InboxOutlined />, label: t("nav.inbox"), onClick: () => navigate("/review/inbox") },
            ...(roles.includes("admin")
              ? [
                  { key: "/policy", icon: <SafetyCertificateOutlined />, label: t("nav.policy"), onClick: () => navigate("/policy") },
                  { key: "/credentials", icon: <KeyOutlined />, label: t("nav.credentials"), onClick: () => navigate("/credentials") },
                ]
              : []),
            ...(roles.includes("admin")
              ? [{ key: "/roles", icon: <TeamOutlined />, label: t("nav.roles"), onClick: () => navigate("/roles") }]
              : []),
          ]}
        />
      </Sider>
      <Layout>
        <Header
          className="app-header"
          style={{
            backgroundColor: surfaces.headerBg,
            color: surfaces.onHeader,
            padding: "0 24px",
            borderBottom: "none",
            lineHeight: "64px",
            fontSize: 15,
            fontWeight: 600,
            boxShadow: "0 6px 24px rgba(15,23,42,0.08)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
            <span style={{ letterSpacing: 0.2 }}>{t("brand.subtitle")}</span>
            <span style={{ fontSize: 13, fontWeight: 500, display: "inline-flex", alignItems: "center", gap: 16 }}>
              <LanguageSwitcher />
              <ThemeSwitcher />
              {(user?.display_name || user?.username || t("common.notLoggedIn")) +
                ` (${roles.map((r) => roleLabel(r)).join(" / ")})`}
              <a
                onClick={() => {
                  clearAuthToken();
                  navigate("/login", { replace: true });
                }}
              >
                {t("common.logout")}
              </a>
            </span>
          </div>
        </Header>
        <Content style={{ margin: 24, minHeight: 280 }}>
          <div className="page-content">
            <Outlet />
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}
