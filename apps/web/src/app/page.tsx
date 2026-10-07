import Link from 'next/link';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-gray-100 flex flex-col justify-between">
      {/* Navigation */}
      <header className="border-b border-border bg-surface/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500 flex items-center justify-center text-cyan-400 font-black">
              S
            </div>
            <span className="font-bold text-lg text-white">
              SecureScan <span className="text-cyan-400 font-mono text-sm px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800">AI</span>
            </span>
          </div>
          <div className="flex items-center space-x-4">
            <Link
              href="/login"
              className="text-sm text-gray-300 hover:text-white transition-colors"
            >
              Sign In
            </Link>
            <Link
              href="/dashboard"
              className="text-sm bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-semibold px-4 py-2 rounded-lg transition-colors shadow-lg shadow-cyan-500/20"
            >
              Launch Dashboard
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-7xl mx-auto px-6 py-20 flex-1 flex flex-col items-center text-center justify-center">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800 text-cyan-300 text-xs font-mono mb-6">
          <span>● DETERMINISTIC DETECTION + AI REMEDIATION</span>
        </div>

        <h1 className="text-4xl md:text-6xl font-black tracking-tight text-white max-w-4xl leading-tight">
          Scan your website & APIs. <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400">
            Fix risks with AI-guided developer patches.
          </span>
        </h1>

        <p className="mt-6 text-lg text-gray-400 max-w-2xl leading-relaxed">
          Production-grade cybersecurity posture scanner for startups, agencies, and SaaS teams.
          Zero hallucinated technical findings. 100% deterministic rule verification paired with
          actionable AI remediation.
        </p>

        <div className="mt-10 flex flex-wrap gap-4 justify-center">
          <Link
            href="/dashboard"
            className="bg-cyan-500 hover:bg-cyan-400 text-gray-950 font-bold px-6 py-3.5 rounded-xl transition-all shadow-xl shadow-cyan-500/25 text-base flex items-center space-x-2"
          >
            <span>Open Security Posture Dashboard</span>
            <span>→</span>
          </Link>
          <Link
            href="/login"
            className="bg-surface hover:bg-card border border-border text-gray-200 font-semibold px-6 py-3.5 rounded-xl transition-colors text-base"
          >
            Access Demo Tenant
          </Link>
        </div>

        {/* Feature Grid */}
        <div className="mt-24 grid grid-cols-1 md:grid-cols-3 gap-8 text-left w-full">
          <div className="p-6 rounded-2xl bg-surface border border-border/80 hover:border-cyan-500/40 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-xl mb-4">
              🛡️
            </div>
            <h3 className="text-lg font-bold text-white mb-2">Deterministic Security Rules</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Technical findings are strictly discovered by verified rules (TLS/SSL, DNS, Security Headers, Cookies, Exposure). AI is never allowed to fabricate vulnerabilities.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-surface border border-border/80 hover:border-cyan-500/40 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-indigo-950 border border-indigo-800 flex items-center justify-center text-indigo-400 text-xl mb-4">
              🤖
            </div>
            <h3 className="text-lg font-bold text-white mb-2">AI-Powered Developer Fixes</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Translates complex CVEs and header omissions into plain business impact explanations and copy-pasteable configuration patches for your engineering stack.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-surface border border-border/80 hover:border-cyan-500/40 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400 text-xl mb-4">
              🔒
            </div>
            <h3 className="text-lg font-bold text-white mb-2">SSRF Defense & Authorization</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Safe scanning architecture with DNS IP-pinning, cloud metadata shielding, and explicit target ownership verification records to prevent misuse.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border bg-surface py-8 text-center text-xs text-gray-500">
        <p>© 2026 SecureScan AI. Built for authorized security testing and posture posture assurance.</p>
      </footer>
    </div>
  );
}
