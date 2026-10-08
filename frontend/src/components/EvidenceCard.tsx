import React, { useState } from 'react';
import { EvidenceItem } from '../types';
import { useTranslation } from '../i18n';
import { ChevronDown, ChevronUp, Cpu, Shield, Globe, QrCode, MessageSquare, Code } from 'lucide-react';

interface EvidenceCardProps {
  item: EvidenceItem;
}

export const EvidenceCard: React.FC<EvidenceCardProps> = ({ item }) => {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);

  const getSourceIcon = (source: string) => {
    if (source.includes('ml')) return <Cpu className="w-4 h-4 text-cyan-400" />;
    if (source.includes('website')) return <Globe className="w-4 h-4 text-emerald-400" />;
    if (source.includes('qr')) return <QrCode className="w-4 h-4 text-amber-400" />;
    if (source.includes('message') || source.includes('text')) return <MessageSquare className="w-4 h-4 text-purple-400" />;
    return <Shield className="w-4 h-4 text-blue-400" />;
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-rose-950/80 text-rose-400 border border-rose-800">{t('risk.critical')}</span>;
      case 'high':
        return <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-orange-950/80 text-orange-400 border border-orange-800">{t('risk.high')}</span>;
      case 'medium':
        return <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-amber-950/80 text-amber-400 border border-amber-800">{t('risk.medium')}</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-slate-800 text-slate-400 border border-slate-700">{t('risk.low')}</span>;
    }
  };

  const hasDetails = item.details && Object.keys(item.details).length > 0;

  return (
    <div className="bg-[#0f172a] border border-[#1e293b] rounded-xl p-4 transition hover:border-[#334155]">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-[#0b0f19] border border-[#1e293b] flex-shrink-0 mt-0.5">
            {getSourceIcon(item.source)}
          </div>
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/50 border border-cyan-800/60 px-2 py-0.5 rounded">
                {item.signal_id}
              </span>
              {getSeverityBadge(item.severity)}
              <span className="text-[11px] text-slate-400 font-mono">
                {t('result.signalConfidence')} <strong className="text-slate-200">{(item.confidence * 100).toFixed(0)}%</strong>
              </span>
              {item.detector_version && (
                <span className="text-[10px] text-slate-500 font-mono hidden sm:inline">
                  [{item.detector_version}]
                </span>
              )}
            </div>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">
              {item.explanation}
            </p>
          </div>
        </div>

        {hasDetails && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-[#1e293b] transition flex items-center gap-1 text-[11px] font-mono flex-shrink-0"
            aria-label="Toggle technical signal payload"
          >
            <Code className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{expanded ? t('common.hideDetails') : t('common.details')}</span>
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {expanded && hasDetails && (
        <div className="mt-3 pt-3 border-t border-[#1e293b] text-xs font-mono bg-[#070a12] p-3 rounded-lg text-slate-300 overflow-x-auto border border-[#1e293b]">
          <div className="text-[10px] text-slate-500 mb-1 uppercase font-bold tracking-wider">
            {t('result.rawPayload')}
          </div>
          <pre className="text-[11px] leading-snug">{JSON.stringify(item.details, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
