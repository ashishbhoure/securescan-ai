'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '../../lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('demo@securescan.ai');
  const [password, setPassword] = useState('SecureScan123!');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await api.login(email, password);
      router.push('/dashboard');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleFillDemo = () => {
    setEmail('demo@securescan.ai');
    setPassword('SecureScan123!');
  };

  return (
    <div className="min-h-screen bg-background flex flex-col justify-center items-center px-4">
      <div className="w-full max-w-md bg-surface border border-border p-8 rounded-2xl shadow-2xl">
        <div className="text-center mb-8">
          <div className="inline-flex w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/40 items-center justify-center text-cyan-400 font-black text-2xl mb-3">
            S
          </div>
          <h2 className="text-2xl font-bold text-white">Sign In to SecureScan AI</h2>
          <p className="text-sm text-gray-400 mt-1">Access your security posture workspace</p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Email Address</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
              placeholder="you@company.com"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
              placeholder="••••••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold rounded-lg transition-colors text-sm shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-border/60">
          <button
            type="button"
            onClick={handleFillDemo}
            className="w-full py-2 bg-card hover:bg-border/60 border border-border text-cyan-400 font-mono text-xs rounded-lg transition-colors"
          >
            Load Seed Demo Credentials (demo@securescan.ai)
          </button>
        </div>

        <p className="text-center text-xs text-gray-400 mt-6">
          Don't have an account?{' '}
          <Link href="/register" className="text-cyan-400 hover:underline">
            Register workspace
          </Link>
        </p>
      </div>
    </div>
  );
}
