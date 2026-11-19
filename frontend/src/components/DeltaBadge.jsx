const TREND_CONFIG = {
  improving: { symbol: "▼", color: "var(--risk-low)", label: "improving" },
  regressing: { symbol: "▲", color: "var(--risk-critical)", label: "regressing" },
  flat: { symbol: "—", color: "var(--text-tertiary)", label: "unchanged" },
  "first-commit": { symbol: "◆", color: "var(--text-tertiary)", label: "first commit scored" },
};

export default function DeltaBadge({ delta }) {
  if (!delta) {
    return <div style={{ fontSize: 12, color: "var(--text-tertiary)" }}>Select a commit to see its trend.</div>;
  }

  const cfg = TREND_CONFIG[delta.trend];

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          background: "var(--panel)",
          border: `1px solid ${cfg.color}`,
          borderRadius: 6,
          padding: "6px 10px",
          fontFamily: "var(--font-data)",
          fontSize: 13,
          color: cfg.color,
        }}
      >
        <span>{cfg.symbol}</span>
        <span>{delta.delta === null ? "—" : `${delta.delta > 0 ? "+" : ""}${delta.delta.toFixed(1)}`}</span>
      </div>
      <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
        {cfg.label}
        {delta.previous_score !== null && (
          <>
            {" "}vs previous ({delta.previous_score.toFixed(1)})
          </>
        )}
      </span>
    </div>
  );
}
