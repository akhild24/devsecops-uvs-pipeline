export default function FixFirstCard({ fixes, selectedFixes = [], onToggle = () => {} }) {
  const toggle = (fix) => onToggle(`${fix.source_tool}:${fix.package}`);

  return (
    <section
      style={{
        background: "var(--panel)",
        border: "1px solid var(--panel-border)",
        borderRadius: 10,
        padding: 20,
        marginBottom: 20,
      }}
    >
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>Fix first</h2>
      {!fixes || fixes.length === 0 ? (
        <div style={{ color: "var(--text-tertiary)", fontSize: 13 }}>
          No package fixes are available for this commit.
        </div>
      ) : (
        <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 8 }}>
          {fixes.map((fix) => {
            const key = `${fix.source_tool}:${fix.package}`;
            const checked = selectedFixes.includes(key);
            return (
              <li key={key} style={{ color: "var(--text-secondary)", fontSize: 13 }}>
                <label style={{ display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(fix)}
                    style={{ marginTop: 3 }}
                  />
                  <span>
                    {fix.fix_known
                      ? `Upgrade ${fix.package} to ${fix.fixed_version}`
                      : `Fix version unknown for ${fix.package}`}
                    {`: score ${fix.current_score.toFixed(1)} -> ${fix.simulated_score.toFixed(1)} (-${fix.score_reduction.toFixed(1)})`}
                    <span style={{ color: "var(--text-tertiary)" }}>
                      {" "}· {fix.findings_removed} finding{fix.findings_removed === 1 ? "" : "s"} · {fix.source_tool}
                    </span>
                  </span>
                </label>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
