import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { RISK_COLOR, riskLevelForScore } from "../api/risk";
import RepoSelector from "../components/RepoSelector";
import CommitTimeline from "../components/CommitTimeline";
import SeverityBreakdown from "../components/SeverityBreakdown";
import DeltaBadge from "../components/DeltaBadge";
import FixFirstCard from "../components/FixFirstCard";

const panelStyle = {
  background: "var(--panel)",
  border: "1px solid var(--panel-border)",
  borderRadius: 10,
  padding: 20,
};

export default function Dashboard() {
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState("");
  const [history, setHistory] = useState([]);
  const [selectedSha, setSelectedSha] = useState(null);
  const [scoreDetail, setScoreDetail] = useState(null);
  const [breakdown, setBreakdown] = useState(null);
  const [delta, setDelta] = useState(null);
  const [fixes, setFixes] = useState(null);
  const [selectedFixes, setSelectedFixes] = useState([]);
  const [fixesError, setFixesError] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .repos()
      .then((r) => {
        setRepos(r);
        if (r.length > 0) {
          setSelectedRepo(
            r.includes("demo/acme-webapp") ? "demo/acme-webapp" : r[0]
          );
        }
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e.message ?? e));
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!selectedRepo) return;
    api
      .history(selectedRepo)
      .then((h) => {
        setHistory(h);
        setSelectedSha(h.length > 0 ? h[h.length - 1].commit_sha : null);
      })
      .catch((e) => setError(String(e.message ?? e)));
  }, [selectedRepo]);

  useEffect(() => {
    if (!selectedSha) {
      setScoreDetail(null);
      setBreakdown(null);
      setDelta(null);
      setFixes(null);
      setSelectedFixes([]);
      setFixesError(null);
      return;
    }
    setFixesError(null);
    setSelectedFixes([]);
    Promise.all([api.score(selectedSha), api.breakdown(selectedSha), api.delta(selectedSha)])
      .then(([s, b, d]) => {
        setScoreDetail(s);
        setBreakdown(b);
        setDelta(d);
      })
      .catch((e) => setError(String(e.message ?? e)));
    api
      .whatIf(selectedSha)
      .then(setFixes)
      .catch((e) => {
        setFixes([]);
        setFixesError(String(e.message ?? e));
      });
  }, [selectedSha]);

  const projectedReduction = useMemo(() => {
    if (!scoreDetail || !fixes) return 0;
    return fixes
      .filter((fix) => selectedFixes.includes(`${fix.source_tool}:${fix.package}`))
      .reduce((sum, fix) => sum + Number(fix.score_reduction || 0), 0);
  }, [fixes, scoreDetail, selectedFixes]);

  const projectedScore = scoreDetail ? Math.max(0, scoreDetail.final_score - projectedReduction) : null;
  const projectedBand = projectedScore == null ? null : riskLevelForScore(projectedScore);

  if (loading) {
    return <CenteredMessage>Loading…</CenteredMessage>;
  }

  if (error && repos.length === 0) {
    return (
      <CenteredMessage>
        <div style={{ color: "var(--risk-critical)", marginBottom: 8 }}>Can't reach the scoring API.</div>
        <div style={{ color: "var(--text-tertiary)", fontSize: 13, fontFamily: "var(--font-data)" }}>{error}</div>
        <div style={{ color: "var(--text-tertiary)", fontSize: 13, marginTop: 12 }}>
          Start the backend (<code>uvicorn main:app --reload</code>) and submit at least one commit via{' '}
          <code>/v1/scan/submit</code>, then reload.
        </div>
      </CenteredMessage>
    );
  }

  if (repos.length === 0) {
    return (
      <CenteredMessage>
        <div style={{ marginBottom: 8 }}>No scanned commits yet.</div>
        <div style={{ color: "var(--text-tertiary)", fontSize: 13 }}>
          Run the pipeline or POST to <code>/v1/scan/submit</code> to see risk scores here.
        </div>
      </CenteredMessage>
    );
  }

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "32px 24px 64px" }}>
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>DevSecOps Risk Dashboard</h1>
          <p style={{ margin: "4px 0 0", color: "var(--text-tertiary)", fontSize: 13 }}>
            Unified Vulnerability Score per commit — Semgrep + OWASP Dependency-Check + Trivy
          </p>
        </div>
        <RepoSelector repos={repos} selected={selectedRepo} onChange={setSelectedRepo} />
      </header>

      {scoreDetail && (
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: 20, marginBottom: 20, ...panelStyle }}>
          <div style={{ textAlign: "center", minWidth: 140 }}>
            <div
              style={{
                fontFamily: "var(--font-data)",
                fontSize: 44,
                fontWeight: 700,
                color: RISK_COLOR[scoreDetail.risk_level],
                lineHeight: 1,
              }}
            >
              {scoreDetail.final_score.toFixed(1)}
            </div>
            <div
              style={{
                marginTop: 6,
                display: "inline-block",
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: 0.3,
                color: RISK_COLOR[scoreDetail.risk_level],
                border: `1px solid ${RISK_COLOR[scoreDetail.risk_level]}`,
                borderRadius: 4,
                padding: "2px 8px",
              }}
            >
              {scoreDetail.risk_level}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", justifyContent: "center", gap: 10 }}>
            <div style={{ fontFamily: "var(--font-data)", fontSize: 12, color: "var(--text-secondary)" }}>
              commit <strong style={{ color: "var(--text-primary)" }}>{scoreDetail.commit_sha.slice(0, 10)}</strong>
              {"  ·  "}
              env <strong style={{ color: "var(--text-primary)" }}>{scoreDetail.environment}</strong>
              {"  ·  "}
              ×{scoreDetail.environment_multiplier} env · ×{scoreDetail.delta_factor} delta
            </div>
            <div style={{ fontSize: 13, color: "var(--text-primary)" }}>{scoreDetail.recommended_action}</div>
            <DeltaBadge delta={delta} />
          </div>
        </div>
      )}

      <div style={{ ...panelStyle, marginBottom: 20 }}>
        <CommitTimeline history={history} selectedSha={selectedSha} onSelect={setSelectedSha} />
      </div>

      {selectedSha && (
        <>
          {fixesError && (
            <div style={{ color: "var(--text-tertiary)", fontSize: 12, marginBottom: 8 }}>
              Fix simulation unavailable: {fixesError}
            </div>
          )}
          {projectedScore != null && (
            <div style={{ ...panelStyle, marginBottom: 20 }}>
              <div style={{ fontSize: 12, color: "var(--text-tertiary)", marginBottom: 8 }}>
                What-if projection for selected fixes
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ fontFamily: "var(--font-data)", fontSize: 26, fontWeight: 700, color: RISK_COLOR[projectedBand] }}>
                  {projectedScore.toFixed(1)}
                </span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  {projectedBand} risk band after {selectedFixes.length} selected fix{selectedFixes.length === 1 ? "" : "es"}
                </span>
              </div>
            </div>
          )}
          <FixFirstCard
            fixes={fixes}
            selectedFixes={selectedFixes}
            onToggle={(key) => {
              setSelectedFixes((current) =>
                current.includes(key) ? current.filter((item) => item !== key) : [...current, key]
              );
            }}
          />
        </>
      )}

      <div style={panelStyle}>
        <SeverityBreakdown breakdown={breakdown} />
      </div>

      <footer
        style={{
          textAlign: "center",
          color: "var(--text-tertiary)",
          fontSize: 11,
          marginTop: 18,
          paddingBottom: 4,
        }}
      >
        Demo/sample data only — for presentation use, not live production scan results.
      </footer>
    </div>
  );
}

function CenteredMessage({ children }) {
  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        textAlign: "center",
        padding: 24,
      }}
    >
      {children}
    </div>
  );
}
