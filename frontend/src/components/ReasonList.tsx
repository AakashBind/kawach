import React from 'react';
import { useTranslation } from '../i18n';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

interface ReasonListProps {
  reasons: string[];
  isLowRisk?: boolean;
}

export const ReasonList: React.FC<ReasonListProps> = ({ reasons, isLowRisk = false }) => {
  const { t } = useTranslation();

  if (!reasons || reasons.length === 0) {
    return (
      <div className="p-4 rounded-xl bg-[#0b0f19] border border-[#1e293b] text-xs text-slate-400 font-mono text-center">
        {t('result.noRiskFactors')}
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      {reasons.map((reason, idx) => (
        <div
          key={idx}
          className="flex items-start gap-3 p-3.5 rounded-xl bg-[#0b0f19] border border-[#1e293b] hover:border-[#334155] transition"
        >
          {isLowRisk ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
          ) : (
            <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          )}
          <span className="text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">
            {reason}
          </span>
        </div>
      ))}
    </div>
  );
};
