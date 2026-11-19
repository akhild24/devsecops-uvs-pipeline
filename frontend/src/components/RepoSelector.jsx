export default function RepoSelector({ repos, selected, onChange }) {
  return (
    <select
      value={selected}
      onChange={(e) => onChange(e.target.value)}
      style={{
        background: "var(--panel)",
        color: "var(--text-primary)",
        border: "1px solid var(--panel-border)",
        borderRadius: 6,
        padding: "7px 10px",
        fontSize: 13,
        fontFamily: "var(--font-data)",
        cursor: "pointer",
      }}
    >
      {repos.map((r) => (
        <option key={r} value={r}>
          {r}
        </option>
      ))}
    </select>
  );
}
