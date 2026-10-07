'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '../../lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await api.register(email, password, name, organizationName);
      router.push('/dashboard');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col justify-center items-center px-4">
      <div className="w-full max-w-md bg-surface border border-border p-8 rounded-2xl shadow-2xl">
        <div className="text-center mb-8">
          <div className="inline-flex w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/40 items-center justify-center text-cyan-400 font-black text-2xl mb-3">
            S
          </div>
          <h2 className="text-2xl font-bold text-white">Create Security Workspace</h2>
          <p className="text-sm text-gray-400 mt-1">Start automated posture assessments</p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Your Full Name</label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
              placeholder="Jane Doe"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Organization / Company Name</label>
            <input
              type="text"
              required
              value={organizationName}
              onChange={(e) => setOrganizationName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
              placeholder="Acme Cyber Labs"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Work Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-card border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
              placeholder="jane@company.com"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-300 mb-1">Password (min 8 characters)</label>
            <input
              type="password"
              required
              minLength={8}
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
            {loading ? 'Setting up Workspace...' : 'Create Account'}
          </button>
        </form>

        <p className="text-center text-xs text-gray-400 mt-6">
          Already registered?{' '}
          <Link href="/login" className="text-cyan-400 hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
