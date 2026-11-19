import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import "./index.css";

const Dashboard = lazy(() => import("./pages/Dashboard"));

const rootEl = document.getElementById("root");
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <Suspense fallback={<div style={{ padding: 32, textAlign: "center" }}>Loading dashboard…</div>}>
        <Dashboard />
      </Suspense>
    </React.StrictMode>
  );
}
