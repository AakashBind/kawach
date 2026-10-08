import React from 'react';
import { RiskLevel } from '../types';
import { useTranslation } from '../i18n';
import { ShieldCheck, AlertTriangle, AlertOctagon, HelpCircle, ShieldAlert } from 'lucide-react';

interface RiskBadgeProps {
  level: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md' }) => {
  const { t } = useTranslation();

  const configs: Record<RiskLevel, { bg: string; text: string; border: string; icon: React.ReactNode; label: string }> = {
    LOW: {
      bg: 'bg-emerald-950/70',
      text: 'text-emerald-400',
      border: 'border-emerald-500/50',
      icon: <ShieldCheck className={size === 'lg' ? 'w-5 h-5' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />,
      label: t('risk.low')
    },
    MEDIUM: {
      bg: 'bg-amber-950/70',
      text: 'text-amber-400',
      border: 'border-amber-500/50',
      icon: <AlertTriangle className={size === 'lg' ? 'w-5 h-5' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />,
      label: t('risk.medium')
    },
    HIGH: {
      bg: 'bg-orange-950/70',
      text: 'text-orange-400',
      border: 'border-orange-500/50',
      icon: <ShieldAlert className={size === 'lg' ? 'w-5 h-5' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />,
      label: t('risk.high')
    },
    CRITICAL: {
      bg: 'bg-rose-950/70',
      text: 'text-rose-400',
      border: 'border-rose-500/50',
      icon: <AlertOctagon className={size === 'lg' ? 'w-5 h-5' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />,
      label: t('risk.critical')
    },
    INSUFFICIENT_EVIDENCE: {
      bg: 'bg-slate-900',
      text: 'text-slate-400',
      border: 'border-slate-700',
      icon: <HelpCircle className={size === 'lg' ? 'w-5 h-5' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />,
      label: t('risk.insufficient')
    }
  };

  const config = configs[level] || configs.INSUFFICIENT_EVIDENCE;

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[11px] font-bold gap-1 font-mono',
    md: 'px-3 py-1 text-xs font-bold gap-1.5 font-mono',
    lg: 'px-4 py-1.5 text-sm font-extrabold gap-2 font-mono'
  };

  return (
    <span
      className={`inline-flex items-center rounded-md border ${config.bg} ${config.text} ${config.border} ${sizeClasses[size]} tracking-wide shadow-sm select-none`}
    >
      {config.icon}
      <span>{config.label}</span>
    </span>
  );
};
