import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'SecureScan AI — Website, API & Posture Security Scanner',
  description:
    'AI-powered security posture scanner and deterministic vulnerability intelligence for modern SaaS companies, web agencies, and SMBs.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-gray-100 antialiased">{children}</body>
    </html>
  );
}
