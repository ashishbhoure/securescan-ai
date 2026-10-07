'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { api } from '../../lib/api';

interface AppLayoutProps {
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const pathname = usePathname();
  const [user, setUser] = useState<{ email: string; name: string } | null>(null);
  const [org, setOrg] = useState<{ name: string; planTier: string } | null>(null);

  useEffect(() => {
    api
      .getMe()
      .then((res) => {
        setUser(res.user);
        if (res.organizations && res.organizations[0]) {
          setOrg(res.organizations[0]);
        }
      })
      .catch(() => {
        // Redirection handled in pages if not authenticated
      });
  }, []);

  const navItems = [
    { label: 'Posture Dashboard', href: '/dashboard', icon: '📊' },
    { label: 'Assets & Targets', href: '/assets', icon: '🌐' },
    { label: 'Scans & Jobs', href: '/scans', icon: '🔍' },
    { label: 'Vulnerabilities & Findings', href: '/findings', icon: '🛡️' },
    { label: 'Executive Reports', href: '/reports', icon: '📑' },
    { label: 'AI Security Analyst', href: '/ai-assistant', icon: '🤖' },
  ];

  return (
    <div className="flex min-h-screen bg-background text-gray-100">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-surface flex flex-col justify-between shrink-0">
        <div>
          {/* Logo & Brand */}
          <div className="p-5 border-b border-border flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-black text-xl">
              S
            </div>
            <div>
              <div className="font-bold text-base tracking-wide text-white flex items-center">
                SecureScan <span className="ml-1 text-cyan-400 text-xs px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800">AI</span>
              </div>
              <div className="text-xs text-gray-400 font-mono">POSTURE & REMEDIATION</div>
            </div>
          </div>

          {/* Org Workspace Pill */}
          <div className="px-4 py-3 border-b border-border/50 bg-background/40">
            <div className="text-xs text-gray-400 uppercase tracking-wider">Workspace</div>
            <div className="text-sm font-semibold text-gray-200 truncate">{org?.name || 'Acme Cyber Labs'}</div>
            <span className="inline-block mt-1 text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              {org?.planTier || 'PRO'} PLAN
            </span>
          </div>

          {/* Nav links */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    active
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 shadow-sm'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-card/50'
                  }`}
                >
                  <span className="text-base">{item.icon}</span>
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* User profile & logout */}
        <div className="p-4 border-t border-border bg-surface/50">
          <div className="flex items-center justify-between">
            <div className="truncate">
              <div className="text-xs font-semibold text-gray-300 truncate">{user?.name || 'Security Lead'}</div>
              <div className="text-xs text-gray-500 truncate">{user?.email || 'user@securescan.ai'}</div>
            </div>
            <button
              onClick={() => api.logout()}
              className="text-xs text-red-400 hover:text-red-300 hover:underline p-1"
              title="Sign Out"
            >
              Logout
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Top bar banner */}
        <header className="h-14 border-b border-border bg-surface/60 px-8 flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-2 text-xs font-mono text-gray-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>SCAN ENGINE v1.0.0 — ZERO HALLUCINATION ASSURANCE</span>
          </div>
          <div className="text-xs text-gray-400">
            Authorized Posture Audit Mode
          </div>
        </header>

        <div className="p-8 max-w-7xl w-full mx-auto">{children}</div>
      </main>
    </div>
  );
};
