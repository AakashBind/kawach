import React from 'react';
import { UncertaintyLevel } from '../types';
import { useTranslation } from '../i18n';
import { Info, AlertTriangle, CheckCircle } from 'lucide-react';

interface UncertaintyProps {
  level: UncertaintyLevel;
}

export const UncertaintyIndicator: React.FC<UncertaintyProps> = ({ level }) => {
  const { t } = useTranslation();

  const configs: Record<UncertaintyLevel, { color: string; label: string; desc: string; icon: React.ReactNode }> = {
    LOW: {
      color: 'text-emerald-400 border-emerald-500/40 bg-emerald-950/40',
      label: t('uncertainty.lowLabel'),
      desc: t('uncertainty.lowDesc'),
      icon: <CheckCircle className="w-4 h-4 flex-shrink-0 text-emerald-400 mt-0.5" />
    },
    MEDIUM: {
      color: 'text-amber-400 border-amber-500/40 bg-amber-950/40',
      label: t('uncertainty.medLabel'),
      desc: t('uncertainty.medDesc'),
      icon: <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400 mt-0.5" />
    },
    HIGH: {
      color: 'text-rose-400 border-rose-500/40 bg-rose-950/40',
      label: t('uncertainty.highLabel'),
      desc: t('uncertainty.highDesc'),
      icon: <Info className="w-4 h-4 flex-shrink-0 text-rose-400 mt-0.5" />
    }
  };

  const cfg = configs[level] || configs.LOW;

  return (
    <div className={`p-3.5 rounded-xl border flex items-start gap-3 ${cfg.color}`}>
      {cfg.icon}
      <div>
        <div className="text-xs font-bold tracking-wider font-mono uppercase">{cfg.label}</div>
        <div className="text-xs text-slate-300 mt-0.5 leading-relaxed">{cfg.desc}</div>
      </div>
    </div>
  );
};
