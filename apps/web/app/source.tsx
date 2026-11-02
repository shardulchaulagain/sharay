"use client";

import { useState } from "react";
import { post, type Check } from "./api";
import { Badge, Empty, ErrorNotice, Icon, Panel, SectionHead } from "./components";

type SourceFinding = {
  fingerprint: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  description: string;
  remediation: string;
  affected_url: string;
};
type SourcePackage = { ecosystem: string; name: string; version: string; manifest?: string };
type SourceAnalysisResult = {
  basis: string;
  root: string;
  findings: SourceFinding[];
  packages: SourcePackage[];
  manifests: string[];
  skipped: { file: string; reason: string }[];
  checks: Check[];
};

export default function SourceAnalysis() {
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [result, setResult] = useState<SourceAnalysisResult>();

  async function run(event: React.FormEvent) {
    event.preventDefault();
    if (!path.trim() || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(await post<SourceAnalysisResult>("/source-analysis", { path: path.trim() }));
    } catch (err) {
      setResult(undefined);
      setError(err instanceof Error ? err : new Error("Source analysis failed."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <SectionHead eyebrow="SOURCE / NATIVE ANALYSIS" title="Source analysis">
        Runs the built-in secret-pattern and dependency detectors over a local code tree. No scanner
        binary, container or network. The path is confined to the configured source root.
      </SectionHead>
      <Panel title="Analyze a source directory">
        <form className="scope-form" onSubmit={run}>
          <div className="form-wide">
            <label>
              Directory
              <input
                name="path"
                value={path}
                onChange={event => setPath(event.target.value)}
                placeholder="project/ (relative to the source root)"
                required
              />
              <small>A path inside the server's source root (SHARAY_SOURCE_ROOT). Paths that resolve outside it are refused.</small>
            </label>
          </div>
          <ErrorNotice error={error} />
          <div className="form-wide form-actions">
            <button className="primary" type="submit" disabled={busy || !path.trim()}>
              {busy ? "Analyzing…" : "Run source analysis"}
              <Icon name="arrow" />
            </button>
          </div>
        </form>
        <p className="panel-note">
          Pattern-based detection surfaces <strong>suspected</strong> findings for triage; it is not a
          replacement for a full SAST or secret scanner and does not confirm a live credential.
        </p>
      </Panel>
      {result && (
        <>
          <Panel title="Findings" action={<Badge value={`${result.findings.length} suspected`} />}>
            {result.findings.length ? (
              <div className="finding-summary-list">
                {result.findings.map(finding => (
                  <details key={finding.fingerprint} className="finding-summary-card">
                    <summary>
                      <Badge value={finding.severity} />
                      <strong>{finding.title}</strong>
                      <Badge value={finding.status} />
                    </summary>
                    <div className="finding-summary-body">
                      <p>{finding.description}</p>
                      <dl className="facts">
                        <div>
                          <dt>Location</dt>
                          <dd className="mono">{finding.affected_url}</dd>
                        </div>
                        <div>
                          <dt>Category</dt>
                          <dd>{finding.category.replaceAll("_", " ")}</dd>
                        </div>
                        <div>
                          <dt>Remediation</dt>
                          <dd>{finding.remediation}</dd>
                        </div>
                      </dl>
                    </div>
                  </details>
                ))}
              </div>
            ) : (
              <Empty title="No secret-shaped values found">
                The tree was scanned and no built-in secret pattern matched. Review coverage below before
                reading this as evidence of safety.
              </Empty>
            )}
          </Panel>
          <Panel title="Declared dependencies" action={<Badge value={`${result.packages.length} package${result.packages.length === 1 ? "" : "s"}`} />}>
            {result.packages.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Ecosystem</th>
                      <th>Package</th>
                      <th>Version</th>
                      <th>Manifest</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.packages.map((pkg, index) => (
                      <tr key={`${pkg.ecosystem}:${pkg.name}:${index}`}>
                        <td>{pkg.ecosystem}</td>
                        <td className="mono">{pkg.name}</td>
                        <td className="mono">{pkg.version}</td>
                        <td className="mono">{pkg.manifest ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="panel-note">No declared package manifests found in this tree.</p>
            )}
          </Panel>
          <Panel title="Coverage">
            <div className="check-list">
              {result.checks.map((check, index) => (
                <div className="check-row" key={index}>
                  <div>
                    <strong>{check.category?.replaceAll("_", " ") ?? "Check"}</strong>
                    <p>{String(check.detail ?? "No detail recorded.")}</p>
                  </div>
                  <Badge value={check.status} />
                </div>
              ))}
            </div>
            <p className="panel-note mono">Root: {result.root}</p>
          </Panel>
        </>
      )}
    </>
  );
}
