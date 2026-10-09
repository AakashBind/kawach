import React from 'react';
import { useTranslation } from '../i18n';
import { Logo } from './Logo';
import { Lock, Eye, Terminal, CheckCircle2 } from 'lucide-react';

export const Footer: React.FC = () => {
  const { t } = useTranslation();

  return (
    <footer className="bg-[#070a12] border-t border-[#1e293b] mt-6 text-slate-400 text-xs py-6">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-6">
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
        </div>

        <div className="pt-4 border-t border-[#1e293b]/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-slate-500 font-mono">
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
