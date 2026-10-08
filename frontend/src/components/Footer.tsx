import React from 'react';
import { useTranslation } from '../i18n';
import { Logo } from './Logo';
import { Lock, Eye, Terminal, CheckCircle2 } from 'lucide-react';

export const Footer: React.FC = () => {
  const { t } = useTranslation();

  return (
    <footer className="bg-[#070a12] border-t border-[#1e293b] mt-24 text-slate-400 text-xs py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-10">
          <div className="space-y-3 md:col-span-2">
            <div className="flex items-center gap-3">
              <Logo size="sm" />
            </div>
            <p className="text-slate-400 text-xs leading-relaxed max-w-md">
              {t('footer.desc')}
            </p>
            <div className="flex items-center gap-2 pt-1 text-[11px] text-emerald-400 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{t('footer.benchmarkTag')}</span>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-3 uppercase tracking-wider text-[11px] font-mono">
              {t('footer.governanceTitle')}
            </h4>
            <ul className="space-y-2 text-slate-400 text-xs">
              <li className="flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                <span>{t('footer.zeroRetention')}</span>
              </li>
              <li className="flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                <span>{t('footer.explainableEvidence')}</span>
              </li>
              <li className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                <span>{t('footer.auditedWeights')}</span>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-3 uppercase tracking-wider text-[11px] font-mono">
              {t('footer.telemetryTitle')}
            </h4>
            <div className="space-y-1.5 text-slate-400 font-mono text-[11px]">
              <div>URL ML: <span className="text-slate-200">v2.0.0 (XGBoost)</span></div>
              <div>Text ML: <span className="text-slate-200">v2.0.0 (TF-IDF + LR)</span></div>
              <div>Decoders: <span className="text-slate-200">QR + SSRF Web DOM</span></div>
              <div>Arbiter: <span className="text-slate-200">Unified Risk Engine v1.0</span></div>
            </div>
          </div>
        </div>

        <div className="pt-6 border-t border-[#1e293b]/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-slate-500 font-mono">
          <div>{t('footer.copyright')}</div>
          <div className="flex items-center gap-4">
            <span>{t('footer.archTag')}</span>
            <span>•</span>
            <span>{t('footer.openDefenseTag')}</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
