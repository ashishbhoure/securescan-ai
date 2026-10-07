'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { AppLayout } from '../../components/layout/AppLayout';
import { SeverityBadge } from '../../components/SeverityBadge';
import { api } from '../../lib/api';

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const fetchFindings = () => {
    setLoading(true);
    api
      .getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        search: search || undefined,
      })
      .then((res) => setFindings(res.findings || []))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFindings();
  };

  return (
    <AppLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Vulnerabilities & Security Findings</h1>
          <p className="text-sm text-gray-400 mt-1">Deterministic security defects with actionable AI developer remediation.</p>
        </div>

        {/* Filter & Search Bar */}
        <div className="bg-surface border border-border p-4 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
          <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings by rule ID, title, or keyword..."
              className="w-full px-3.5 py-2 rounded-lg bg-card border border-border text-white text-xs focus:outline-none focus:border-cyan-500"
            />
          </form>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-card border border-border text-xs rounded-lg text-gray-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 bg-card border border-border text-xs rounded-lg text-gray-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="ACCEPTED_RISK">Accepted Risk</option>
            </select>

            {(severityFilter || statusFilter || search) && (
              <button
                onClick={() => {
                  setSeverityFilter('');
                  setStatusFilter('');
                  setSearch('');
                }}
                className="text-xs text-gray-400 hover:text-white px-2 py-1"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Findings List */}
        <div className="bg-surface border border-border rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-border/80 flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-300">
              Showing {findings.length} findings
            </span>
          </div>

          <div className="divide-y divide-border/60">
            {findings.length === 0 ? (
              <div className="p-8 text-center text-sm text-gray-400">
                {loading ? 'Querying findings...' : 'No findings matching your criteria.'}
              </div>
            ) : (
              findings.map((f) => (
                <div key={f.id} className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-card/40 transition-colors">
                  <div className="space-y-1.5 max-w-3xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-card border border-border text-gray-300">
                        {f.ruleId}
                      </span>
                      <span className="text-xs text-gray-500 font-mono">
                        Status: <strong className="text-gray-300">{f.status}</strong>
                      </span>
                    </div>

                    <Link
                      href={`/findings/${f.id}`}
                      className="block text-base font-bold text-white hover:text-cyan-400 transition-colors"
                    >
                      {f.title}
                    </Link>

                    <p className="text-xs text-gray-400 line-clamp-2">
                      {f.description}
                    </p>

                    {f.evidence?.summary && (
                      <div className="text-xs font-mono text-gray-400 bg-background/60 p-2 rounded border border-border/50">
                        Evidence: {f.evidence.summary}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center space-x-3 shrink-0">
                    <span className="text-xs font-mono text-gray-400 bg-card px-2.5 py-1 rounded border border-border truncate max-w-[200px]">
                      {f.asset?.targetUrl}
                    </span>
                    <Link
                      href={`/findings/${f.id}`}
                      className="px-4 py-2 bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 rounded-lg text-xs font-semibold transition-colors"
                    >
                      AI Remediation →
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
