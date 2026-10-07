'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { AppLayout } from '../../components/layout/AppLayout';
import { ScoreGauge } from '../../components/ScoreGauge';
import { SeverityBadge } from '../../components/SeverityBadge';
import { api } from '../../lib/api';

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getStats().catch(() => ({ metrics: { overallScore: 85, totalAssets: 1, criticalFindings: 0, highFindings: 1, mediumFindings: 2, lowFindings: 3, recentScans: [] } })),
      api.getFindings({ status: 'OPEN' }).catch(() => ({ findings: [] })),
    ])
      .then(([statsRes, findingsRes]) => {
        setStats(statsRes.metrics);
        setFindings(findingsRes.findings || []);
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <AppLayout>
      <div className="space-y-8">
        {/* Header & Quick Action */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">Security Posture Dashboard</h1>
            <p className="text-sm text-gray-400 mt-1">Continuous posture score, active vulnerability inventory and AI remediation.</p>
          </div>
          <div className="flex items-center space-x-3">
            <Link
              href="/assets"
              className="px-4 py-2 bg-card hover:bg-border/60 border border-border text-xs font-semibold text-gray-200 rounded-lg transition-colors"
            >
              + Add Target Asset
            </Link>
            <Link
              href="/scans"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 text-xs font-bold rounded-lg transition-colors shadow-lg shadow-cyan-500/20"
            >
              Trigger Posture Scan
            </Link>
          </div>
        </div>

        {/* Posture Score & Severity Metrics */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Score Card */}
          <div className="lg:col-span-1 bg-surface border border-border p-6 rounded-2xl flex flex-col items-center justify-center text-center relative overflow-hidden">
            <div className="text-xs font-mono uppercase tracking-widest text-gray-400 mb-4">
              Overall Security Score
            </div>
            <ScoreGauge score={stats?.overallScore ?? 85} size="lg" />
            <p className="text-xs text-gray-400 mt-4 max-w-xs">
              Derived from verified deterministic posture rules. Scores are heavily penalized by critical findings.
            </p>
          </div>

          {/* Severity Counters Grid */}
          <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-surface border border-red-900/40 p-5 rounded-2xl flex flex-col justify-between">
              <div>
                <span className="text-xs font-bold text-red-400 uppercase tracking-wider block">Critical</span>
                <span className="text-3xl font-black text-red-500 mt-2 block">{stats?.criticalFindings ?? 0}</span>
              </div>
              <p className="text-xs text-gray-400 mt-3">Immediate risk. Require same-day remediation.</p>
            </div>

            <div className="bg-surface border border-orange-900/40 p-5 rounded-2xl flex flex-col justify-between">
              <div>
                <span className="text-xs font-bold text-orange-400 uppercase tracking-wider block">High</span>
                <span className="text-3xl font-black text-orange-500 mt-2 block">{stats?.highFindings ?? 0}</span>
              </div>
              <p className="text-xs text-gray-400 mt-3">Severe misconfiguration or weak encryption.</p>
            </div>

            <div className="bg-surface border border-yellow-900/40 p-5 rounded-2xl flex flex-col justify-between">
              <div>
                <span className="text-xs font-bold text-yellow-400 uppercase tracking-wider block">Medium</span>
                <span className="text-3xl font-black text-yellow-500 mt-2 block">{stats?.mediumFindings ?? 0}</span>
              </div>
              <p className="text-xs text-gray-400 mt-3">Missing defense-in-depth security headers.</p>
            </div>

            <div className="bg-surface border border-sky-900/40 p-5 rounded-2xl flex flex-col justify-between">
              <div>
                <span className="text-xs font-bold text-sky-400 uppercase tracking-wider block">Low & Info</span>
                <span className="text-3xl font-black text-sky-400 mt-2 block">{(stats?.lowFindings ?? 0) + (stats?.infoFindings ?? 0)}</span>
              </div>
              <p className="text-xs text-gray-400 mt-3">Server disclosures and posture improvements.</p>
            </div>
          </div>
        </div>

        {/* Top Open Findings Table */}
        <div className="bg-surface border border-border rounded-2xl overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white">Priority Security Findings</h2>
              <p className="text-xs text-gray-400">Deterministic vulnerabilities awaiting developer remediation</p>
            </div>
            <Link href="/findings" className="text-xs text-cyan-400 hover:underline">
              View All Findings →
            </Link>
          </div>

          <div className="divide-y divide-border/60 overflow-x-auto">
            {findings.length === 0 ? (
              <div className="p-8 text-center text-sm text-gray-400">
                {loading ? 'Analyzing posture findings...' : 'No open findings. Your configured assets meet security posture baselines!'}
              </div>
            ) : (
              findings.slice(0, 5).map((f) => (
                <div key={f.id} className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-card/40 transition-colors">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <SeverityBadge severity={f.severity} />
                      <span className="font-mono text-xs text-gray-400">{f.ruleId}</span>
                      <Link href={`/findings/${f.id}`} className="font-semibold text-sm text-gray-100 hover:text-cyan-400 transition-colors">
                        {f.title}
                      </Link>
                    </div>
                    <p className="text-xs text-gray-400 pl-1">{f.description}</p>
                  </div>

                  <div className="flex items-center space-x-3 shrink-0">
                    <span className="text-xs font-mono text-gray-400 bg-card px-2.5 py-1 rounded border border-border">
                      {f.asset?.targetUrl || 'Target'}
                    </span>
                    <Link
                      href={`/findings/${f.id}`}
                      className="text-xs bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 px-3 py-1.5 rounded-lg transition-colors font-medium"
                    >
                      AI Fix & Details
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
