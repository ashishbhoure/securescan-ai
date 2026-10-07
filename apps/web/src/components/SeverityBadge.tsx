import React from 'react';

interface SeverityBadgeProps {
  severity: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const norm = severity.toUpperCase();

  switch (norm) {
    case 'CRITICAL':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-400 border border-red-800">
          ● CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-orange-950 text-orange-400 border border-orange-800">
          ● HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-950 text-yellow-400 border border-yellow-800">
          ● MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-950 text-sky-400 border border-sky-800">
          ● LOW
        </span>
      );
    case 'INFO':
    default:
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
          ● INFO
        </span>
      );
  }
};
