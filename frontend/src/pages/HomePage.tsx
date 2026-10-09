import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { useTranslation } from '../i18n';
import { InteractiveThreatVisual } from '../components/InteractiveThreatVisual';
import { ScrollStorySection } from '../components/ScrollStorySection';
import { Shield, Globe, MessageSquare, QrCode, Cpu, ArrowRight, Lock, Eye, Sparkles, Terminal } from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

export const HomePage: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [isScanning, setIsScanning] = useState(false);

  // Auto-typing scanner modalities rotator
  const typewriterPhrases = [
    'Message',
    'URL Link',
    'QR Code',
    'Website DOM'
  ];
  const [phraseIndex, setPhraseIndex] = useState(0);
  const [typedText, setTypedText] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const currentPhrase = typewriterPhrases[phraseIndex];
    let timeout: ReturnType<typeof setTimeout>;

    if (!isDeleting && typedText === currentPhrase) {
      timeout = setTimeout(() => setIsDeleting(true), 1800);
    } else if (isDeleting && typedText === '') {
      setIsDeleting(false);
      setPhraseIndex((prev) => (prev + 1) % typewriterPhrases.length);
      timeout = setTimeout(() => {}, 350);
    } else {
      const speed = isDeleting ? 30 : 65;
      timeout = setTimeout(() => {
        setTypedText(
          isDeleting
            ? currentPhrase.substring(0, typedText.length - 1)
            : currentPhrase.substring(0, typedText.length + 1)
        );
      }, speed);
    }

    return () => clearTimeout(timeout);
  }, [typedText, isDeleting, phraseIndex]);

  // References for GSAP animations
  const pageContainerRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLElement>(null);
  const heroLeftRef = useRef<HTMLDivElement>(null);
  const heroVisualRef = useRef<HTMLDivElement>(null);
  const telemetryRef = useRef<HTMLDivElement>(null);
  const modalitiesSectionRef = useRef<HTMLElement>(null);
  const guaranteesSectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion || !pageContainerRef.current) return;

    const ctx = gsap.context(() => {
      // 1. Initial Hero Staggered Console Entrance
      const heroTl = gsap.timeline({ defaults: { ease: 'power3.out' } });

      heroTl.fromTo('.hero-title-elem', 
        { y: 15, opacity: 0 }, 
        { y: 0, opacity: 1, duration: 0.5, clearProps: 'all' }
      )
      .fromTo('.hero-desc-elem', 
        { y: 12, opacity: 0 }, 
        { y: 0, opacity: 1, duration: 0.4, clearProps: 'all' }, 
        '-=0.2'
      )
      .fromTo('.hero-typewriter-elem', 
        { y: 10, opacity: 0 }, 
        { y: 0, opacity: 1, duration: 0.4, clearProps: 'all' }, 
        '-=0.2'
      )
      .fromTo('.hero-cta-elem', 
        { y: 12, opacity: 0 }, 
        { y: 0, opacity: 1, duration: 0.4, clearProps: 'all' }, 
        '-=0.2'
      )
      .fromTo(heroVisualRef.current, 
        { scale: 0.95, opacity: 0 }, 
        { scale: 1, opacity: 1, duration: 0.6, ease: 'back.out(1.1)', clearProps: 'all' }, 
        '-=0.3'
      )
      .fromTo(telemetryRef.current, 
        { y: 10, opacity: 0 }, 
        { y: 0, opacity: 1, duration: 0.4, clearProps: 'all' }, 
        '-=0.2'
      );

      // 3. Modalities Section Subtle Entrance (safely visible without opacity 0 trap)
      if (modalitiesSectionRef.current) {
        gsap.fromTo('.modality-grid-card', 
          { y: 20 },
          {
            scrollTrigger: {
              trigger: modalitiesSectionRef.current,
              start: 'top 95%',
              toggleActions: 'play none none none'
            },
            y: 0,
            stagger: 0.08,
            duration: 0.5,
            ease: 'power2.out'
          }
        );
      }

      // 4. Guarantees Section Reveal (safely visible without opacity 0 trap)
      if (guaranteesSectionRef.current) {
        gsap.fromTo('.guarantee-card',
          { y: 15 },
          {
            scrollTrigger: {
              trigger: guaranteesSectionRef.current,
              start: 'top 95%',
              toggleActions: 'play none none none'
            },
            y: 0,
            stagger: 0.08,
            duration: 0.5,
            ease: 'power2.out'
          }
        );
      }

      ScrollTrigger.refresh();
    }, pageContainerRef);

    return () => ctx.revert();
  }, []);

  const handleLaunchScanner = () => {
    setIsScanning(true);
  };

  const handleScanComplete = () => {
    navigate('/scanner');
  };

  const modalities = [
    {
      tab: 'url',
      title: t('home.urlModalTitle'),
      badge: 'ML v2.0.0',
      badgeColor: 'text-cyan-400 bg-cyan-950/60 border-cyan-800',
      icon: <Globe className="w-5 h-5 text-cyan-400" />,
      desc: t('home.urlModalDesc'),
      stats: t('home.urlModalStats')
    },
    {
      tab: 'message',
      title: t('home.msgModalTitle'),
      badge: 'ML v2.0.0',
      badgeColor: 'text-purple-400 bg-purple-950/60 border-purple-800',
      icon: <MessageSquare className="w-5 h-5 text-purple-400" />,
      desc: t('home.msgModalDesc'),
      stats: t('home.msgModalStats')
    },
    {
      tab: 'qr',
      title: t('home.qrModalTitle'),
      badge: 'Deterministic',
      badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-800',
      icon: <QrCode className="w-5 h-5 text-amber-400" />,
      desc: t('home.qrModalDesc'),
      stats: t('home.qrModalStats')
    },
    {
      tab: 'website',
      title: t('home.webModalTitle'),
      badge: 'SSRF-Shielded',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-800',
      icon: <Shield className="w-5 h-5 text-emerald-400" />,
      desc: t('home.webModalDesc'),
      stats: t('home.webModalStats')
    }
  ];

  return (
    <div ref={pageContainerRef} className="space-y-10 sm:space-y-12 pt-1 pb-6">
      {/* 1. ENTERPRISE TWO-COLUMN HERO SECTION */}
      <section
        ref={heroRef}
        className="relative overflow-hidden rounded-3xl bg-gradient-to-b from-[#0e1626] to-[#080d18] border border-slate-800/90 p-6 sm:p-7 lg:p-8 shadow-2xl"
      >
        {/* Subtle Background Glow Elements */}
        <div className="absolute -top-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center relative z-10">
          {/* Left Column: Product Message & Actions */}
          <div ref={heroLeftRef} className="lg:col-span-7 space-y-5">
            <h1 className="hero-title-elem text-3xl sm:text-4xl xl:text-5xl font-extrabold tracking-tight text-white leading-[1.15]">
              Think Before You Click with <span className="text-cyan-400">Scam Shield.</span>
            </h1>

            <p className="hero-desc-elem text-xs sm:text-sm md:text-base text-slate-300 leading-relaxed max-w-xl font-normal">
              Got a suspicious message, link, QR code, or website? Check it with Scam Shield and learn what warning signs to look for.
            </p>

            {/* Auto-typing Scanner Engine Stream */}
            <div className="hero-typewriter-elem inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#070c17]/90 border border-slate-700/70 text-xs sm:text-sm font-mono shadow-inner shadow-cyan-950/40">
              <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">WE OFFER:</span>
              <div className="flex items-center font-bold text-cyan-300 min-w-[130px]">
                <span>{typedText}</span>
                <span className="w-1.5 h-3.5 bg-cyan-400 ml-1 animate-pulse" />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                onClick={handleLaunchScanner}
                disabled={isScanning}
                className="hero-cta-elem px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-white font-bold text-xs sm:text-sm flex items-center gap-2 shadow-lg shadow-cyan-500/25 transition-all transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-75 cursor-pointer"
              >
                <Shield className="w-4 h-4" />
                <span>{isScanning ? t('scanner.stageValidating') : 'Launch Multi-Scanner'}</span>
                <ArrowRight className={`w-4 h-4 transition-transform ${isScanning ? 'translate-x-1 animate-pulse' : 'group-hover:translate-x-1'}`} />
              </button>
            </div>
          </div>

          {/* Right Column: Interactive 3D Cybersecurity Threat Visual */}
          <div ref={heroVisualRef} className="lg:col-span-5 flex justify-center items-center w-full">
            <InteractiveThreatVisual isScanning={isScanning} onScanComplete={handleScanComplete} />
          </div>
        </div>

        {/* Technical Sub-telemetry banner */}
        <div
          ref={telemetryRef}
          className="mt-8 pt-5 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono"
        >
          <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60">
            <div className="text-slate-500 text-[10px] uppercase">{t('home.urlClassifier')}</div>
            <div className="text-slate-200 font-bold mt-0.5">XGBoost v2.0.0</div>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60">
            <div className="text-slate-500 text-[10px] uppercase">{t('home.messageClassifier')}</div>
            <div className="text-slate-200 font-bold mt-0.5">TF-IDF + LR v2.0.0</div>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60">
            <div className="text-slate-500 text-[10px] uppercase">{t('home.decoders')}</div>
            <div className="text-slate-200 font-bold mt-0.5">QR + SSRF Web DOM</div>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60">
            <div className="text-slate-500 text-[10px] uppercase">{t('home.decisionArbiter')}</div>
            <div className="text-slate-200 font-bold mt-0.5">Unified Risk v1.0</div>
          </div>
        </div>
      </section>

      {/* 2. 4 CORE SCANNING MODALITIES GRID (FOLLOWS HERO WITH 48-80PX NATURAL GAP) */}
      <section ref={modalitiesSectionRef} className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1e293b] pb-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {t('home.capabilitiesTitle')}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('home.capabilitiesDesc')}
            </p>
          </div>
          <span className="text-xs text-cyan-400 font-mono">{t('home.zeroFakeAi')}</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {modalities.map((item) => (
            <div
              key={item.tab}
              onClick={() => navigate(`/scanner?tab=${item.tab}`)}
              className="modality-grid-card p-6 rounded-2xl bg-[#0f172a] border border-[#1e293b] hover:border-cyan-500/50 cursor-pointer transition flex flex-col justify-between space-y-4 group"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="p-2.5 rounded-xl bg-[#0b0f19] border border-[#1e293b] group-hover:border-cyan-500/40 transition">
                    {item.icon}
                  </div>
                  <span className={`px-2.5 py-0.5 text-[10px] font-bold font-mono rounded border ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                </div>

                <h3 className="text-base sm:text-lg font-bold text-white group-hover:text-cyan-400 transition">
                  {item.title}
                </h3>

                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-normal">
                  {item.desc}
                </p>
              </div>

              <div className="pt-3 border-t border-[#1e293b] text-xs font-mono text-slate-400 flex items-center justify-between">
                <span className="text-slate-300 group-hover:text-cyan-300 transition-colors">{item.stats}</span>
                <ArrowRight className="w-4 h-4 text-cyan-400 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 3. GSAP SCROLLTRIGGER ARCHITECTURAL PIPELINE STORY */}
      <ScrollStorySection />

      {/* 4. SECURITY ARCHITECTURE & DATA MINIMIZATION PRINCIPLES */}
      <section ref={guaranteesSectionRef} className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-8 space-y-6 shadow-xl">
        <div className="border-b border-[#1e293b] pb-4">
          <h2 className="text-lg font-bold text-white tracking-tight">
            {t('home.guaranteesTitle')}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {t('home.guaranteesDesc')}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="guarantee-card space-y-2 p-4 rounded-xl bg-[#0b0f19] border border-[#1e293b]">
            <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase tracking-wider font-mono">
              <Lock className="w-4 h-4" />
              <span>{t('home.zeroRetentionTitle')}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {t('home.zeroRetentionDesc')}
            </p>
          </div>

          <div className="guarantee-card space-y-2 p-4 rounded-xl bg-[#0b0f19] border border-[#1e293b]">
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase tracking-wider font-mono">
              <Eye className="w-4 h-4" />
              <span>{t('home.explainableTitle')}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {t('home.explainableDesc')}
            </p>
          </div>

          <div className="guarantee-card space-y-2 p-4 rounded-xl bg-[#0b0f19] border border-[#1e293b]">
            <div className="flex items-center gap-2 text-amber-400 font-bold text-xs uppercase tracking-wider font-mono">
              <Cpu className="w-4 h-4" />
              <span>{t('home.auditableTitle')}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {t('home.auditableDesc')}
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
