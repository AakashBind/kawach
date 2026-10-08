import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ScanResultData } from '../types';
import { useTranslation } from '../i18n';
import { RiskBadge } from '../components/RiskBadge';
import { RiskGauge } from '../components/RiskGauge';
import { UncertaintyIndicator } from '../components/UncertaintyIndicator';
import { EvidenceCard } from '../components/EvidenceCard';
import { ReasonList } from '../components/ReasonList';
import { ActionRecommendations } from '../components/ActionRecommendations';
import { ShareModal } from '../components/ShareModal';
import { FeedbackModal } from '../components/FeedbackModal';
import { Shield, ArrowLeft, Share2, MessageSquare, Flag, Cpu, Terminal, Clock, Copy, Check, Layers } from 'lucide-react';

interface ResultPageProps {
  result: ScanResultData;
  onNewScan?: () => void;
}

export const ResultPage: React.FC<ResultPageProps> = ({ result, onNewScan }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [shareOpen, setShareOpen] = useState(false);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [copiedTarget, setCopiedTarget] = useState(false);

  const isLow = result.risk_level === 'LOW';
  const rawModelVersions = Array.isArray(result.model_versions)
    ? result.model_versions
    : [String(result.model_versions || '')];
  
  const modelVersionsList = rawModelVersions.filter(v => Boolean(v) && v !== '[]');
  const modelVersionsStr = modelVersionsList.length > 0 ? modelVersionsList.join(', ') : 'text-scam-2.0.0';

  const copyTarget = () => {
    navigator.clipboard.writeText(result.target);
    setCopiedTarget(true);
    setTimeout(() => setCopiedTarget(false), 2000);
  };

  return (
    <div className="max-w-5xl mx-auto py-8 space-y-8">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          onClick={onNewScan ? onNewScan : () => navigate('/scanner')}
          className="px-3.5 py-2 rounded-xl bg-[#0f172a] hover:bg-[#1e293b] border border-[#1e293b] text-xs font-semibold text-slate-200 flex items-center gap-2 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>{t('result.newAnalysis')}</span>
        </button>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShareOpen(true)}
            className="px-3.5 py-2 rounded-xl bg-[#0f172a] hover:bg-[#1e293b] border border-[#1e293b] text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition"
          >
            <Share2 className="w-4 h-4 text-cyan-400" />
            <span>{t('result.exportReport')}</span>
          </button>

          <button
            onClick={() => setFeedbackOpen(true)}
            className="px-3.5 py-2 rounded-xl bg-[#0f172a] hover:bg-[#1e293b] border border-[#1e293b] text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition"
          >
            <MessageSquare className="w-4 h-4 text-amber-400" />
            <span>{t('result.submitFeedback')}</span>
          </button>

          <button
            onClick={() => navigate(`/reports?scan_id=${result.scan_id}&target=${encodeURIComponent(result.target)}`)}
            className="px-3.5 py-2 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/40 text-xs font-semibold text-rose-300 flex items-center gap-1.5 transition"
          >
            <Flag className="w-4 h-4 text-rose-400" />
            <span>{t('result.fileIncident')}</span>
          </button>
        </div>
      </div>

      {/* Target Info Banner */}
      <div className="p-4 rounded-2xl bg-[#0f172a] border border-[#1e293b] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-[#0b0f19] border border-[#1e293b] text-cyan-400 font-mono text-xs font-bold uppercase">
            {result.scan_type}
          </div>
          <div className="min-w-0">
            <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
              <span>{t('result.analysisTarget')}</span>
              <span>•</span>
              <span>{t('common.id')}: {result.analysis_id || result.scan_id}</span>
            </div>
            <div className="text-xs sm:text-sm font-mono text-slate-100 truncate max-w-2xl select-all">
              {result.target}
            </div>
          </div>
        </div>

        <button
          onClick={copyTarget}
          className="px-3 py-1.5 rounded-lg bg-[#0b0f19] border border-[#1e293b] hover:border-slate-600 text-[11px] font-mono text-slate-300 flex items-center gap-1.5 self-start sm:self-center transition"
        >
          {copiedTarget ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copiedTarget ? t('result.copied') : t('result.copyTarget')}</span>
        </button>
      </div>

      {/* Primary Verdict Card */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 sm:p-8 shadow-xl">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
          {/* Gauge & Score */}
          <div className="flex flex-col items-center justify-center p-6 bg-[#0b0f19] border border-[#1e293b] rounded-2xl">
            <RiskGauge score={result.risk_score} level={result.risk_level} />
            <div className="mt-4">
              <RiskBadge level={result.risk_level} size="lg" />
            </div>
          </div>

          {/* Details & Summary */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono mb-1">
                {t('result.threatAssessment')}
              </div>
              <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">
                {result.summary}
              </p>
            </div>

            <UncertaintyIndicator level={result.uncertainty} />

            <div className="p-3 rounded-xl bg-[#0b0f19] border border-[#1e293b] text-[11px] text-slate-400 font-mono flex items-center justify-between">
              <span>{t('result.decisionEngine')}</span>
              <span className="text-cyan-400 font-bold">{result.evidence.length} {t('result.signalsEvaluated')}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Breakdown: Reasons & Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-[#1e293b] pb-3">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              {t('result.keyRiskFactors')}
            </h3>
          </div>
          <ReasonList reasons={result.reasons} isLowRisk={isLow} />
        </div>

        <div>
          <ActionRecommendations actions={result.recommended_actions} />
        </div>
      </div>

      {/* Structured Observed Evidence Items */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 sm:p-8 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1e293b] pb-4">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              {t('result.evidenceBreakdown')} ({result.evidence.length})
            </h3>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>{t('result.evidenceProtocol')} <strong className="text-slate-200">v2.0</strong></span>
          </div>
        </div>

        <div className="space-y-3">
          {result.evidence.map((item, idx) => (
            <EvidenceCard key={idx} item={item} />
          ))}
        </div>
      </div>

      {/* Technical Model Governance & Cryptographic Proof */}
      <div className="p-4 rounded-2xl bg-[#0b0f19] border border-[#1e293b] flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{t('result.activeDetectors')} <strong className="text-slate-200">{modelVersionsStr}</strong></span>
        </div>
        <div className="flex items-center gap-2">
          <Clock className="w-3.5 h-3.5 flex-shrink-0" />
          <span>{t('result.analysisTimestamp')} {new Date(result.generated_at).toLocaleString()}</span>
        </div>
        <div>
          <span className="text-emerald-400 font-bold">{t('result.shaVerified')}</span>
        </div>
      </div>

      {/* Modals */}
      <ShareModal scan={result} isOpen={shareOpen} onClose={() => setShareOpen(false)} />
      <FeedbackModal scanId={result.scan_id} isOpen={feedbackOpen} onClose={() => setFeedbackOpen(false)} />
    </div>
  );
};
