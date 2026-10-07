'use client';

import React, { useEffect, useState } from 'react';
import { AppLayout } from '../../components/layout/AppLayout';
import { ScoreGauge } from '../../components/ScoreGauge';
import { api } from '../../lib/api';

export default function AssetsPage() {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState<any | null>(null);
  const [targetUrl, setTargetUrl] = useState('');
  const [type, setType] = useState('WEBSITE');
  const [confirmedOwnership, setConfirmedOwnership] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAssets = () => {
    setLoading(true);
    api
      .getAssets()
      .then((res) => setAssets(res.assets || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleAddAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
      await api.createAsset(targetUrl, type);
      setTargetUrl('');
      setShowAddModal(false);
      fetchAssets();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleAuthorizeAsset = async () => {
    if (!showAuthModal || !confirmedOwnership) return;
    setError(null);

    try {
      await api.authorizeAsset(showAuthModal.id);
      setShowAuthModal(null);
      setConfirmedOwnership(false);
      fetchAssets();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <AppLayout>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight">Monitored Assets & Targets</h1>
            <p className="text-sm text-gray-400 mt-1">Manage verified web properties and target scan authorizations.</p>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 text-xs font-bold rounded-lg transition-colors shadow-lg shadow-cyan-500/20"
          >
            + Add Target Asset
          </button>
        </div>

        {error && (
          <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg text-red-300 text-xs">
            {error}
          </div>
        )}

        {/* Asset Cards / Table */}
        <div className="bg-surface border border-border rounded-2xl overflow-hidden">
          <div className="p-6 border-b border-border/80">
            <h2 className="text-base font-bold text-white">Asset Inventory</h2>
          </div>

          <div className="divide-y divide-border/60">
            {assets.length === 0 ? (
              <div className="p-8 text-center text-sm text-gray-400">
                {loading ? 'Loading assets...' : 'No assets found. Click "+ Add Target Asset" to register your website.'}
              </div>
            ) : (
              assets.map((asset) => (
                <div key={asset.id} className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 hover:bg-card/40 transition-colors">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-3">
                      <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-card border border-border text-gray-300">
                        {asset.type}
                      </span>
                      <a
                        href={asset.targetUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-base font-bold text-white hover:text-cyan-400 transition-colors"
                      >
                        {asset.targetUrl}
                      </a>
                    </div>
                    <div className="flex items-center space-x-4 text-xs text-gray-400">
                      <span>Project: <strong className="text-gray-300">{asset.project?.name || 'Main'}</strong></span>
                      <span>
                        Authorization Status:{' '}
                        {asset.verificationStatus === 'VERIFIED' ? (
                          <span className="text-emerald-400 font-semibold">● AUTHORIZED</span>
                        ) : (
                          <span className="text-amber-400 font-semibold">● PENDING CONFIRMATION</span>
                        )}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-6">
                    {asset.lastScore !== null && (
                      <div className="text-center">
                        <ScoreGauge score={asset.lastScore} size="sm" />
                      </div>
                    )}

                    {asset.verificationStatus !== 'VERIFIED' ? (
                      <button
                        onClick={() => {
                          setShowAuthModal(asset);
                          setConfirmedOwnership(false);
                        }}
                        className="px-3.5 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-700/60 rounded-lg text-xs font-semibold transition-colors"
                      >
                        Confirm Authorization
                      </button>
                    ) : (
                      <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-3 py-1.5 rounded-lg">
                        Ready to Scan
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Modal: Add Asset */}
        {showAddModal && (
          <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-surface border border-border max-w-md w-full p-6 rounded-2xl shadow-2xl">
              <h3 className="text-lg font-bold text-white mb-2">Register Target Asset</h3>
              <p className="text-xs text-gray-400 mb-4">
                Specify the public website or API endpoint you wish to assess. Private IP addresses and local networks are blocked by SSRF defense.
              </p>

              <form onSubmit={handleAddAsset} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Target URL</label>
                  <input
                    type="url"
                    required
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://app.yourdomain.com"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Asset Category</label>
                  <select
                    value={type}
                    onChange={(e) => setType(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
                  >
                    <option value="WEBSITE">Website / Web App</option>
                    <option value="API">REST / OpenAPI Service</option>
                    <option value="DOMAIN">Root Domain Posture</option>
                  </select>
                </div>

                <div className="flex items-center justify-end space-x-3 pt-4 border-t border-border/60">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="px-4 py-2 bg-card hover:bg-border/60 border border-border text-xs font-medium text-gray-300 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-gray-950 text-xs font-bold rounded-lg shadow-lg shadow-cyan-500/20"
                  >
                    Save Target
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Modal: Target Authorization Confirmation */}
        {showAuthModal && (
          <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-surface border border-border max-w-lg w-full p-6 rounded-2xl shadow-2xl space-y-4">
              <div className="flex items-center space-x-3 text-amber-400">
                <span className="text-2xl">⚠️</span>
                <h3 className="text-lg font-bold text-white">Target Authorization & Consent</h3>
              </div>

              <p className="text-xs text-gray-300 leading-relaxed">
                Under the Computer Fraud and Abuse Act (CFAA) and international cybersecurity statutes, security assessment must be explicitly authorized.
              </p>

              <div className="p-3 bg-card rounded-lg border border-border text-xs font-mono text-cyan-300 break-all">
                Target: {showAuthModal.targetUrl}
              </div>

              <div className="p-4 bg-background/50 border border-border/60 rounded-xl space-y-3">
                <label className="flex items-start space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={confirmedOwnership}
                    onChange={(e) => setConfirmedOwnership(e.target.checked)}
                    className="mt-1 w-4 h-4 rounded text-cyan-500 focus:ring-0 bg-card border-border"
                  />
                  <span className="text-xs text-gray-200">
                    I explicitly confirm that our organization owns or holds signed written authorization to conduct non-destructive security posture assessments against this target.
                  </span>
                </label>
              </div>

              <p className="text-[11px] text-gray-500">
                This authorization will be permanently logged with your User ID, IP address, and timestamp for audit compliance.
              </p>

              <div className="flex items-center justify-end space-x-3 pt-3 border-t border-border/60">
                <button
                  type="button"
                  onClick={() => setShowAuthModal(null)}
                  className="px-4 py-2 bg-card hover:bg-border/60 border border-border text-xs font-medium text-gray-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={!confirmedOwnership}
                  onClick={handleAuthorizeAsset}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-gray-950 text-xs font-bold rounded-lg shadow-lg shadow-amber-500/20"
                >
                  Confirm & Authorize
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
