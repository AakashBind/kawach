import React from 'react';
import { useTranslation } from '../i18n';
import { BookOpen, QrCode, Globe, Key, Clock } from 'lucide-react';

export const EducationPage: React.FC = () => {
  const { t } = useTranslation();

  const scamCards = [
    {
      title: t('education.card1Title'),
      icon: <Globe className="w-5 h-5 text-cyan-400" />,
      desc: t('education.card1Desc'),
      indicators: [
        t('education.card1Ind1'),
        t('education.card1Ind2'),
        t('education.card1Ind3'),
        t('education.card1Ind4')
      ]
    },
    {
      title: t('education.card2Title'),
      icon: <Clock className="w-5 h-5 text-rose-400" />,
      desc: t('education.card2Desc'),
      indicators: [
        t('education.card2Ind1'),
        t('education.card2Ind2'),
        t('education.card2Ind3'),
        t('education.card2Ind4')
      ]
    },
    {
      title: t('education.card3Title'),
      icon: <Key className="w-5 h-5 text-amber-400" />,
      desc: t('education.card3Desc'),
      indicators: [
        t('education.card3Ind1'),
        t('education.card3Ind2'),
        t('education.card3Ind3'),
        t('education.card3Ind4')
      ]
    },
    {
      title: t('education.card4Title'),
      icon: <QrCode className="w-5 h-5 text-purple-400" />,
      desc: t('education.card4Desc'),
      indicators: [
        t('education.card4Ind1'),
        t('education.card4Ind2'),
        t('education.card4Ind3'),
        t('education.card4Ind4')
      ]
    }
  ];

  return (
    <div className="max-w-5xl mx-auto py-8 space-y-8">
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-2">
          <BookOpen className="w-3.5 h-3.5" />
          {t('education.badge')}
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          {t('education.title')}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
          {t('education.subtitle')}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {scamCards.map((card, i) => (
          <div key={i} className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 space-y-4 shadow-xl flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-[#0b0f19] border border-[#1e293b]">
                  {card.icon}
                </div>
                <h3 className="text-base font-bold text-white">{card.title}</h3>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-normal">{card.desc}</p>
            </div>

            <div className="space-y-2 pt-3 border-t border-[#1e293b]">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono block">
                {t('education.analyzedIndicators')}
              </span>
              <ul className="space-y-1.5">
                {card.indicators.map((ind, j) => (
                  <li key={j} className="text-xs text-slate-300 flex items-start gap-2">
                    <span className="text-cyan-400 font-mono">•</span>
                    <span className="leading-snug">{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
