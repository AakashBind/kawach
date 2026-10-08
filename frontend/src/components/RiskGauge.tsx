import React from 'react';
import { RiskLevel } from '../types';
import { useTranslation } from '../i18n';

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const { t } = useTranslation();

  const getColor = () => {
    if (level === 'CRITICAL' || score >= 85) return '#f43f5e'; // rose-500
    if (level === 'HIGH' || score >= 60) return '#f97316';     // orange-500
    if (level === 'MEDIUM' || score >= 25) return '#f59e0b';   // amber-500
    return '#10b981'; // emerald-500
  };

  const color = getColor();
  const radius = 60;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(Math.max(score, 0), 100) / 100) * circumference;

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg className="w-36 h-36 transform -rotate-90">
        <circle
          cx="72"
          cy="72"
          r={radius}
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        <circle
          cx="72"
          cy="72"
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className="text-3xl font-extrabold tracking-tight text-white font-mono leading-none">
          {score}
        </span>
        <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold font-mono mt-1">
          {t('result.riskScoreOutOf')}
        </span>
      </div>
    </div>
  );
};
