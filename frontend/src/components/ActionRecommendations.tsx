import React from 'react';
import { useTranslation } from '../i18n';
import { ShieldCheck, ArrowRight } from 'lucide-react';

interface ActionProps {
  actions: string[];
}

export const ActionRecommendations: React.FC<ActionProps> = ({ actions }) => {
  const { t } = useTranslation();

  if (!actions || actions.length === 0) {
    return null;
  }

  return (
    <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 space-y-4">
      <div className="flex items-center gap-2 border-b border-[#1e293b] pb-3">
        <ShieldCheck className="w-5 h-5 text-cyan-400" />
        <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono">
          {t('result.recommendedActions')}
        </h3>
      </div>
      <ul className="space-y-3">
        {actions.map((act, i) => (
          <li key={i} className="flex items-start gap-3 text-xs sm:text-sm text-slate-200">
            <div className="p-1 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 flex-shrink-0 mt-0.5">
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
            <span className="leading-relaxed">{act}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};
