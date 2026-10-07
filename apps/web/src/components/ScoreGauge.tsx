import React from 'react';

interface ScoreGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, size = 'md' }) => {
  let color = 'text-cyber-safe';
  let borderColor = 'border-cyber-safe';
  let grade = 'A';
  let label = 'Excellent';

  if (score < 40) {
    color = 'text-cyber-critical';
    borderColor = 'border-cyber-critical';
    grade = 'F';
    label = 'Critical Risk';
  } else if (score < 60) {
    color = 'text-cyber-high';
    borderColor = 'border-cyber-high';
    grade = 'D';
    label = 'High Risk';
  } else if (score < 75) {
    color = 'text-cyber-medium';
    borderColor = 'border-cyber-medium';
    grade = 'C';
    label = 'Moderate';
  } else if (score < 90) {
    color = 'text-cyan-400';
    borderColor = 'border-cyan-500';
    grade = 'B';
    label = 'Good';
  }

  const dimension = size === 'lg' ? 'w-32 h-32' : size === 'sm' ? 'w-14 h-14' : 'w-24 h-24';
  const textClass = size === 'lg' ? 'text-4xl' : size === 'sm' ? 'text-lg' : 'text-2xl';

  return (
    <div className="flex flex-col items-center">
      <div
        className={`${dimension} rounded-full border-4 ${borderColor} bg-surface/50 flex flex-col items-center justify-center shadow-lg relative`}
      >
        <span className={`font-black ${textClass} ${color}`}>{score}</span>
        {size !== 'sm' && <span className="text-xs text-gray-400 uppercase tracking-widest font-semibold">/100</span>}
      </div>
      {size !== 'sm' && (
        <div className="mt-2 text-center">
          <span className={`font-semibold text-sm ${color}`}>Grade {grade}</span>
          <span className="text-gray-400 text-xs block">{label}</span>
        </div>
      )}
    </div>
  );
};
