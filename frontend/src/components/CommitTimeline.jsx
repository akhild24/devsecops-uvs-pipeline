import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceArea,
} from "recharts";
import { RISK_COLOR } from "../api/risk";

function CustomDot(props) {
  const { cx, cy, payload, selectedSha, onSelect } = props;
  const color = RISK_COLOR[payload.risk_level];
  const isSelected = payload.commit_sha === selectedSha;
  return (
    <circle
      cx={cx}
      cy={cy}
      r={isSelected ? 6 : 4}
      fill={color}
      stroke={isSelected ? "#e6edf3" : "none"}
      strokeWidth={2}
      style={{ cursor: "pointer" }}
      onClick={() => onSelect(payload.commit_sha)}
    />
  );
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div
      style={{
        background: "var(--panel)",
        border: "1px solid var(--panel-border)",
        borderRadius: 6,
        padding: "8px 12px",
        fontFamily: "var(--font-data)",
        fontSize: 12,
      }}
    >
      <div style={{ color: "var(--text-secondary)" }}>{p.commit_sha.slice(0, 7)}</div>
      <div style={{ color: RISK_COLOR[p.risk_level], fontWeight: 700, fontSize: 16 }}>{p.final_score.toFixed(1)}</div>
      <div style={{ color: "var(--text-tertiary)" }}>{p.risk_level} · {p.environment}</div>
    </div>
  );
}

export default function CommitTimeline({ history, selectedSha, onSelect }) {
  const data = history.map((h, i) => ({ ...h, index: i, shortSha: h.commit_sha.slice(0, 7) }));

  return (
    <div>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 12 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0, color: "var(--text-primary)" }}>
          Risk score by commit
        </h2>
        <span style={{ fontFamily: "var(--font-data)", fontSize: 11, color: "var(--text-tertiary)" }}>
          {history.length} commits
        </span>
      </div>
      <ResponsiveContainer width="100%" height={280}>
        <LineChart data={data} margin={{ top: 16, right: 24, bottom: 12, left: 4 }}>
          <ReferenceArea y1={0} y2={20} fill="var(--risk-low)" fillOpacity={0.06} />
          <ReferenceArea y1={21} y2={50} fill="var(--risk-medium)" fillOpacity={0.06} />
          <ReferenceArea y1={51} y2={75} fill="var(--risk-high)" fillOpacity={0.06} />
          <ReferenceArea y1={76} y2={100} fill="var(--risk-critical)" fillOpacity={0.06} />
          <CartesianGrid stroke="var(--panel-border)" strokeDasharray="0" vertical={false} />
          <XAxis
            dataKey="shortSha"
            interval={0}
            padding={{ left: 10, right: 10 }}
            tick={{ fill: "var(--text-tertiary)", fontFamily: "var(--font-data)", fontSize: 11 }}
            axisLine={{ stroke: "var(--panel-border)" }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fill: "var(--text-tertiary)", fontFamily: "var(--font-data)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={44}
          />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="final_score"
            stroke="#58a6ff"
            strokeWidth={1.5}
            dot={<CustomDot selectedSha={selectedSha} onSelect={onSelect} />}
            activeDot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
