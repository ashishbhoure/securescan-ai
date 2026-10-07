'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { AppLayout } from '../../components/layout/AppLayout';
import { ScoreGauge } from '../../components/ScoreGauge';
import { api } from '../../lib/api';

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showTriggerModal, setShowTriggerModal] = useState(false);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = () => {
    setLoading(true);
    api
      .getScans()
      .then((res) => setScans(res.scans || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans();
    api.getAssets().then((res) => {
      const authorized = (res.assets || []).filter((a: any) => a.verificationStatus === 'VERIFIED');
      setAssets(authorized);
      if (authorized.length > 0) {
        setSelectedAssetId(authorized[0].id);
      }
    });
  }, []);

  const handleTriggerScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId) return;
    setTriggering(true);
    setError(null);

    try {
      await api.triggerScan(selectedAssetId);
      setShowTriggerModal(false);
      fetchScans();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTriggering(false);
    }
  };

  return (
    <AppLayout>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">Security Scans & Audit History</h1>
            <p className="text-sm text-gray-400 mt-1">Inspection pipeline runs, duration telemetry, and finding generation.</p>
          </div>
          <button
            onClick={() => setShowTriggerModal(true)}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 text-xs font-bold rounded-lg transition-colors shadow-lg shadow-cyan-500/20"
          >
            + Run New Scan
          </button>
        </div>

        {error && (
          <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg text-red-300 text-xs">
            {error}
          </div>
        )}

        {/* Scans Table */}
        <div className="bg-surface border border-border rounded-2xl overflow-hidden">
          <div className="p-6 border-b border-border/80 flex items-center justify-between">
            <h2 className="text-base font-bold text-white">Scan Runs</h2>
            <button
              onClick={fetchScans}
              className="text-xs text-gray-400 hover:text-white transition-colors flex items-center space-x-1"
            >
              <span>↻ Refresh</span>
            </button>
          </div>

          <div className="divide-y divide-border/60">
            {scans.length === 0 ? (
              <div className="p-8 text-center text-sm text-gray-400">
                {loading ? 'Retrieving scans...' : 'No scans executed yet. Click "+ Run New Scan" to begin assessment.'}
              </div>
            ) : (
              scans.map((scan) => (
                <div key={scan.id} className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 hover:bg-card/40 transition-colors">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span
                        className={`text-xs font-semibold px-2.5 py-0.5 rounded-full border ${
                          scan.status === 'COMPLETED'
                            ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                            : scan.status === 'RUNNING'
                            ? 'bg-cyan-950 text-cyan-400 border-cyan-800 animate-pulse'
                            : scan.status === 'FAILED'
                            ? 'bg-red-950 text-red-400 border-red-800'
                            : 'bg-card text-gray-400 border-border'
                        }`}
                      >
                        ● {scan.status}
                      </span>
                      <span className="font-bold text-white text-base">
                        {scan.asset?.targetUrl}
                      </span>
                    </div>

                    <div className="flex items-center space-x-4 text-xs text-gray-400 pt-1">
                      <span>Scan ID: <strong className="font-mono text-gray-300">{scan.id.substring(0, 8)}</strong></span>
                      <span>Findings: <strong className="text-cyan-400">{scan._count?.findings ?? 0}</strong></span>
                      <span>Duration: <strong className="text-gray-300">{scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)}s` : '—'}</strong></span>
                      <span>Date: <strong className="text-gray-300">{new Date(scan.createdAt).toLocaleString()}</strong></span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-6">
                    {scan.overallScore !== null && (
                      <div className="text-center">
                        <ScoreGauge score={scan.overallScore} size="sm" />
                      </div>
                    )}
                    <Link
                      href={`/findings?scanId=${scan.id}`}
                      className="px-3.5 py-1.5 bg-card hover:bg-border/60 border border-border text-gray-200 rounded-lg text-xs font-semibold transition-colors"
                    >
                      View Findings →
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Modal: Run New Scan */}
        {showTriggerModal && (
          <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-surface border border-border max-w-md w-full p-6 rounded-2xl shadow-2xl">
              <h3 className="text-lg font-bold text-white mb-2">Execute Security Scan</h3>
              <p className="text-xs text-gray-400 mb-4">
                Select an authorized target. The scan runs asynchronously across DNS, TLS, HTTP security headers, and cookie engines.
              </p>

              {assets.length === 0 ? (
                <div className="p-4 bg-amber-950/40 border border-amber-800 rounded-xl text-xs text-amber-300 mb-4">
                  No verified targets available. You must confirm authorization for your asset before triggering a scan.
                </div>
              ) : (
                <form onSubmit={handleTriggerScan} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-300 mb-1">Target Asset</label>
                    <select
                      value={selectedAssetId}
                      onChange={(e) => setSelectedAssetId(e.target.value)}
                      className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
                    >
                      {assets.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.targetUrl} ({a.type})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center justify-end space-x-3 pt-4 border-t border-border/60">
                    <button
                      type="button"
                      onClick={() => setShowTriggerModal(false)}
                      className="px-4 py-2 bg-card hover:bg-border/60 border border-border text-xs font-medium text-gray-300 rounded-lg"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={triggering}
                      className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-gray-950 text-xs font-bold rounded-lg shadow-lg shadow-cyan-500/20"
                    >
                      {triggering ? 'Queuing Scan...' : 'Start Assessment'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
