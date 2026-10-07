'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { AppLayout } from '../../../components/layout/AppLayout';
import { SeverityBadge } from '../../../components/SeverityBadge';
import { api } from '../../../lib/api';

export default function FindingDetailPage() {
  const params = useParams();
  const id = params?.id as string;

  const [finding, setFinding] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [explaining, setExplaining] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchFinding = () => {
    setLoading(true);
    api
      .getFinding(id)
      .then((res) => setFinding(res.finding))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (id) fetchFinding();
  }, [id]);

  const handleGenerateAI = async () => {
    setExplaining(true);
    try {
      const res = await api.explainFinding(id);
      setFinding((prev: any) => ({ ...prev, aiAnalysis: res.analysis }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setExplaining(false);
    }
  };

  const handleUpdateStatus = async (newStatus: string) => {
    setStatusUpdating(true);
    try {
      await api.updateFindingStatus(id, newStatus, 'User status change from UI');
      fetchFinding();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <AppLayout>
        <div className="p-8 text-center text-sm text-gray-400">Loading finding details...</div>
      </AppLayout>
    );
  }

  if (!finding) {
    return (
      <AppLayout>
        <div className="p-8 text-center text-sm text-red-400">
          {error || 'Finding not found.'}
        </div>
      </AppLayout>
    );
  }

  const ai = finding.aiAnalysis;

  return (
    <AppLayout>
      <div className="space-y-8 max-w-5xl mx-auto">
        {/* Navigation Breadcrumb */}
        <div className="flex items-center space-x-2 text-xs text-gray-400">
          <Link href="/findings" className="hover:text-white transition-colors">Findings</Link>
          <span>/</span>
          <span className="font-mono text-cyan-400">{finding.ruleId}</span>
        </div>

        {/* Top Header Card */}
        <div className="bg-surface border border-border p-6 rounded-2xl space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-card border border-border text-gray-300">
                  {finding.ruleId}
                </span>
                <span className="text-xs text-gray-400 font-mono">
                  Confidence: <strong className="text-emerald-400">{finding.confidence}</strong>
                </span>
              </div>
              <h1 className="text-2xl font-black text-white">{finding.title}</h1>
              <p className="text-xs font-mono text-gray-400">
                Target: <span className="text-cyan-300">{finding.asset?.targetUrl}</span>
              </p>
            </div>

            {/* Lifecycle Status Manager */}
            <div className="flex flex-col items-end space-y-2">
              <span className="text-xs text-gray-400 uppercase tracking-wider font-mono">Finding Status</span>
              <select
                value={finding.status}
                disabled={statusUpdating}
                onChange={(e) => handleUpdateStatus(e.target.value)}
                className="px-3.5 py-2 rounded-lg bg-card border border-border text-xs font-bold text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="OPEN">OPEN</option>
                <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                <option value="IN_PROGRESS">IN_PROGRESS</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                <option value="ACCEPTED_RISK">ACCEPTED_RISK</option>
              </select>
            </div>
          </div>
        </div>

        {/* 2-Column Layout: Overview & Technical Evidence */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-surface border border-border p-6 rounded-2xl space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono text-cyan-400">
              1. Vulnerability Overview
            </h2>
            <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>

            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-mono pt-2">
              Technical Impact
            </h3>
            <p className="text-xs text-gray-300 leading-relaxed">{finding.impact}</p>

            {finding.rule?.cwe && (
              <div className="pt-2 text-xs font-mono text-gray-400">
                Authoritative Mapping: <strong className="text-gray-200">{finding.rule.cwe}</strong>
              </div>
            )}
          </div>

          <div className="bg-surface border border-border p-6 rounded-2xl space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono text-cyan-400">
              2. Collected Technical Evidence
            </h2>
            <div className="p-3 bg-background rounded-xl border border-border/80 font-mono text-xs text-gray-300">
              <span className="text-emerald-400 block mb-1">✓ Rule Engine Verifiable Proof:</span>
              {finding.evidence?.summary || 'Deterministic scanner collected header/TLS failure evidence.'}
            </div>

            {finding.evidence?.details && (
              <pre className="p-4 bg-background rounded-xl border border-border/80 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-48">
                {JSON.stringify(finding.evidence.details, null, 2)}
              </pre>
            )}
          </div>
        </div>

        {/* AI Security Analyst Remediation Panel */}
        <div className="bg-gradient-to-b from-surface to-background border border-cyan-800/60 p-8 rounded-2xl shadow-xl space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-xl font-bold">
                🤖
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">AI Remediation & Fix Guidance</h2>
                <p className="text-xs text-gray-400">Zero-hallucination analysis built from collected scanner evidence</p>
              </div>
            </div>

            {!ai && (
              <button
                onClick={handleGenerateAI}
                disabled={explaining}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 text-xs font-bold rounded-lg transition-colors shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                {explaining ? 'Analyzing...' : 'Generate AI Fix'}
              </button>
            )}
          </div>

          {ai ? (
            <div className="space-y-6 pt-4 border-t border-border/60">
              {/* Plain-Language Explanation */}
              <div>
                <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono mb-1">
                  Executive Explanation
                </h3>
                <p className="text-sm text-gray-200 leading-relaxed">{ai.plainExplanation}</p>
              </div>

              {/* Business Impact */}
              <div>
                <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono mb-1">
                  Business & Compliance Impact
                </h3>
                <p className="text-sm text-gray-300 leading-relaxed">{ai.businessImpact}</p>
              </div>

              {/* Developer Fix Code Snippet */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider font-mono">
                    Developer Remediation Patch
                  </h3>
                  <button
                    onClick={() => handleCopyCode(ai.developerFix)}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                  >
                    {copied ? '✓ Copied' : 'Copy Patch'}
                  </button>
                </div>
                <pre className="p-4 bg-background rounded-xl border border-border text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                  {ai.developerFix}
                </pre>
              </div>

              {/* Validation Steps */}
              {ai.validationSteps && Array.isArray(ai.validationSteps) && (
                <div>
                  <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-mono mb-2">
                    Validation & Verification Checklist
                  </h3>
                  <ul className="space-y-1.5 text-xs text-gray-300 list-disc list-inside">
                    {ai.validationSteps.map((step: string, idx: number) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="p-6 bg-card/40 rounded-xl border border-border/50 text-center text-xs text-gray-400">
              Click "Generate AI Fix" to inspect business impact, code patches, and step-by-step verification instructions.
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
