import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

const SEVERITY_COLORS = {
  critical: "#f85149",
  high: "#db6d28",
  medium: "#d29922",
  low: "#3fb950",
};

const TOOL_LABEL = {
  semgrep: "Semgrep (SAST)",
  "owasp-dependency-check": "OWASP Dependency-Check (SCA)",
  trivy: "Trivy (Container)",
};

export default function SeverityBreakdown({ breakdown }) {
  if (!breakdown) {
    return <EmptyState />;
  }

  return (
    <div>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px", color: "var(--text-primary)" }}>
        Findings by tool
        <span style={{ marginLeft: 12, fontSize: 12, color: "var(--risk-critical)" }}>
          Known exploited: {breakdown.known_exploited_count ?? 0}
        </span>
      </h2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
        {breakdown.components.map((c) => {
          const data = [
            { name: "critical", value: c.counts.critical },
            { name: "high", value: c.counts.high },
            { name: "medium", value: c.counts.medium },
            { name: "low", value: c.counts.low },
          ].filter((d) => d.value > 0);
          const total = c.counts.critical + c.counts.high + c.counts.medium + c.counts.low;

          return (
            <div key={c.tool} style={{ textAlign: "center" }}>
              <div style={{ position: "relative", height: 120 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={total > 0 ? data : [{ name: "none", value: 1 }]}
                      dataKey="value"
                      innerRadius={34}
                      outerRadius={52}
                      paddingAngle={total > 0 ? 2 : 0}
                      stroke="none"
                      isAnimationActive={false}
                    >
                      {(total > 0 ? data : [{ name: "none", value: 1 }]).map((d) => (
                        <Cell key={d.name} fill={SEVERITY_COLORS[d.name] || "var(--panel-border)"} />
                      ))}
                    </Pie>
                    {total > 0 && <Tooltip />}
                  </PieChart>
                </ResponsiveContainer>
                <div
                  style={{
                    position: "absolute",
                    inset: 0,
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    pointerEvents: "none",
                  }}
                >
                  <span style={{ fontFamily: "var(--font-data)", fontSize: 18, fontWeight: 700 }}>{total}</span>
                  <span style={{ fontSize: 9, color: "var(--text-tertiary)" }}>findings</span>
                </div>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{TOOL_LABEL[c.tool] ?? c.tool}</div>
              <div style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-tertiary)" }}>
                score {c.normalized_score.toFixed(1)}
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 14, justifyContent: "center", marginTop: 16 }}>
        {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-tertiary)" }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: "inline-block" }} />
            {sev}
          </div>
        ))}
      </div>
      {breakdown.findings?.some((finding) => finding.source_tool === "semgrep") && (
        <div style={{ marginTop: 20 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, margin: "0 0 8px" }}>
            Semgrep findings (SAST)
          </h3>
          <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 7 }}>
            {breakdown.findings
              .filter((finding) => finding.source_tool === "semgrep")
              .map((finding, index) => (
                <li
                  key={`${finding.rule_id}:${finding.file_path}:${finding.line_start}:${index}`}
                  style={{ color: "var(--text-secondary)", fontSize: 12 }}
                >
                  <strong style={{ color: "var(--text-primary)" }}>
                    {finding.rule_id || "Unknown rule"}
                  </strong>
                  {" · "}
                  {finding.file_path || "Unknown file"}
                  {finding.line_start != null ? `:${finding.line_start}` : ""}
                  {" · "}
                  {finding.severity}
                </li>
              ))}
          </ul>
        </div>
      )}
      {breakdown.findings?.some((finding) => finding.source_tool !== "semgrep") && (
        <div style={{ marginTop: 20 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, margin: "0 0 8px" }}>Package findings</h3>
          <ul
            style={{
              listStyle: "none",
              padding: 0,
              margin: 0,
              display: "grid",
              gap: 7,
              maxHeight: 240,
              overflowY: "auto",
            }}
          >
            {breakdown.findings.filter((finding) => finding.source_tool !== "semgrep").map((finding, index) => (
              <li
                key={`${finding.source_tool}:${finding.cve_id ?? finding.package_name}:${index}`}
                style={{ color: "var(--text-secondary)", fontSize: 12 }}
              >
                <strong style={{ color: "var(--text-primary)" }}>
                  {finding.package_name || "Unknown package"}
                </strong>
                {finding.installed_version ? ` ${finding.installed_version}` : ""}
                {finding.cve_id ? ` · ${finding.cve_id}` : ""}
                {finding.epss_probability > 0 ? ` · EPSS ${(finding.epss_probability * 100).toFixed(1)}%` : ""}
                {` · ${finding.source_tool} · ${finding.severity}`}
                {finding.known_exploited && (
                  <span
                    style={{
                      marginLeft: 8,
                      color: "var(--risk-critical)",
                      border: "1px solid currentColor",
                      borderRadius: 4,
                      padding: "1px 5px",
                      fontSize: 10,
                      fontWeight: 700,
                    }}
                  >
                    Known exploited
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px", color: "var(--text-primary)" }}>
        Findings by tool
      </h2>
      <div style={{ color: "var(--text-tertiary)", fontSize: 13, padding: "24px 0", textAlign: "center" }}>
        Select a commit to see its severity breakdown.
      </div>
    </div>
  );
}
