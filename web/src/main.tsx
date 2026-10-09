import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { initLocale } from "./i18n";
import { LocaleProvider } from "./i18n/LocaleContext";
import { AppThemeProvider } from "./theme/ThemeContext";
import "./index.css";

initLocale();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <AppThemeProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AppThemeProvider>
    </LocaleProvider>
  </React.StrictMode>
);
