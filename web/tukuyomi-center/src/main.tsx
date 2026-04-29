import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "@/App";
import "@/App.css";
import { I18nProvider } from "@/lib/i18n";

const root = document.getElementById("root");

if (!root) {
  throw new Error("missing root element");
}

createRoot(root).render(
  <StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </StrictMode>,
);
