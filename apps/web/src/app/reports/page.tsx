'use client';

import React, { useEffect, useState } from 'react';
import { AppLayout } from '../../components/layout/AppLayout';
import { ScoreGauge } from '../../components/ScoreGauge';
import { SeverityBadge } from '../../components/SeverityBadge';
import { api } from '../../lib/api';

export default function ReportsPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [generatedReport, setGeneratedReport] = useState<any | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getScans().then((res) => {
      const completed = (res.scans || []).filter((s: any) => s.status === 'COMPLETED');
      setScans(completed);
      if (completed.length > 0) {
        setSelectedScanId(completed[0].id);
      }
    });
  }, []);

  const handleGenerate = async () => {
    if (!selectedScanId) return;
    setGenerating(true);
    setError(null);

    try {
      const res = await api.generateReport(selectedScanId);
      setGeneratedReport(res.report);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <AppLayout>
      <div className="space-y-8 max-w-5xl mx-auto">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">Executive Security Reports</h1>
            <p className="text-sm text-gray-400 mt-1">
              Audit-grade posture reports with methodology breakdowns and compliance disclaimers.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            {generatedReport && (
              <button
                onClick={handlePrint}
                className="px-4 py-2 bg-card hover:bg-border/60 border border-border text-xs font-semibold text-gray-200 rounded-lg transition-colors"
              >
                🖨️ Export / Print PDF
              </button>
            )}
          </div>
        </div>

        {/* Generator Controls */}
        <div className="bg-surface border border-border p-6 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex-1 max-w-md">
            <label className="block text-xs font-semibold text-gray-300 mb-1">
              Select Completed Assessment
            </label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-xs focus:outline-none focus:border-cyan-500"
            >
              {scans.length === 0 ? (
                <option value="">No completed scans found</option>
              ) : (
                scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.asset?.targetUrl} (Score: {s.overallScore}/100 — {new Date(s.createdAt).toLocaleDateString()})
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            onClick={handleGenerate}
            disabled={!selectedScanId || generating}
            className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-gray-950 text-xs font-bold rounded-lg transition-colors shadow-lg shadow-cyan-500/20"
          >
            {generating ? 'Compiling Report...' : 'Generate Executive Report'}
          </button>
        </div>

        {error && (
          <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg text-red-300 text-xs">
            {error}
          </div>
        )}

        {/* Rendered Report Document View */}
        {generatedReport ? (
          <div className="bg-surface border border-border rounded-2xl p-8 space-y-8 print:bg-white print:text-black">
            {/* Report Header */}
            <div className="border-b border-border pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest block mb-1">
                  SECURESCAN AI POSTURE ASSESSMENT
                </span>
                <h2 className="text-2xl font-black text-white">{generatedReport.title}</h2>
                <p className="text-xs text-gray-400 mt-1">
                  Generated: {new Date(generatedReport.generatedAt).toLocaleString()}
                </p>
              </div>

              <div className="text-center">
                <ScoreGauge score={generatedReport.metadata.score} size="md" />
              </div>
            </div>

            {/* Mandatory Section 29 Disclaimer Banner */}
            <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-xl space-y-1">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider block">
                ⚠️ Legal & Assessment Scope Disclaimer
              </span>
              <p className="text-xs text-amber-200/90 leading-relaxed">
                {generatedReport.disclaimer}
              </p>
              <p className="text-[11px] text-amber-300/70 pt-1">
                Assessment covers non-destructive configuration inspection: DNS, TLS/SSL, HTTP Headers, and Cookies. No denial-of-service, brute force, or exploitation activities were performed.
              </p>
            </div>

            {/* Executive Summary Cards */}
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-3">
                Executive Risk Summary
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 bg-card rounded-xl border border-border">
                  <span className="text-xs font-bold text-red-400">Critical Findings</span>
                  <span className="text-2xl font-black text-white block mt-1">
                    {generatedReport.executiveSummary.criticalCount}
                  </span>
                </div>
                <div className="p-4 bg-card rounded-xl border border-border">
                  <span className="text-xs font-bold text-orange-400">High Findings</span>
                  <span className="text-2xl font-black text-white block mt-1">
                    {generatedReport.executiveSummary.highCount}
                  </span>
                </div>
                <div className="p-4 bg-card rounded-xl border border-border">
                  <span className="text-xs font-bold text-yellow-400">Medium Findings</span>
                  <span className="text-2xl font-black text-white block mt-1">
                    {generatedReport.executiveSummary.mediumCount}
                  </span>
                </div>
                <div className="p-4 bg-card rounded-xl border border-border">
                  <span className="text-xs font-bold text-sky-400">Low Findings</span>
                  <span className="text-2xl font-black text-white block mt-1">
                    {generatedReport.executiveSummary.lowCount}
                  </span>
                </div>
              </div>
            </div>

            {/* Detailed Findings Table */}
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-3">
                Verified Technical Findings & Evidence
              </h3>

              <div className="border border-border rounded-xl divide-y divide-border/60 overflow-hidden">
                {generatedReport.findings.map((f: any) => (
                  <div key={f.id} className="p-4 space-y-2">
                    <div className="flex items-center space-x-3">
                      <SeverityBadge severity={f.severity} />
                      <span className="font-mono text-xs text-gray-400">{f.ruleId}</span>
                      <span className="font-bold text-sm text-white">{f.title}</span>
                    </div>
                    <p className="text-xs text-gray-300">{f.description}</p>
                    <div className="text-xs font-mono text-emerald-400 bg-background/50 p-2.5 rounded border border-border/50">
                      Recommendation: {f.remediation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-surface border border-border rounded-2xl p-12 text-center text-sm text-gray-400">
            Select a completed scan above and click "Generate Executive Report" to produce an audit-ready security assessment document.
          </div>
        )}
      </div>
    </AppLayout>
  );
}
