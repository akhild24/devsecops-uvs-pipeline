const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function get(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body.detail ? `: ${body.detail}` : "";
    } catch {
      // Some proxies return an empty or non-JSON error response.
    }
    throw new Error(`${res.status} ${res.statusText} for ${path}${detail}`);
  }
  return res.json();
}

export const api = {
  repos: () => get(`/v1/repos`),
  history: (repo) => get(`/v1/history/${encodeURIComponent(repo)}`),
  score: (commitSha) => get(`/v1/score/${commitSha}`),
  breakdown: (commitSha) => get(`/v1/breakdown/${commitSha}`),
  delta: (commitSha) => get(`/v1/delta/${commitSha}`),
  whatIf: (commitSha, limit = 3) => get(`/v1/whatif/${commitSha}?limit=${limit}`),
};
