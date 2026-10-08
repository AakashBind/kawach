import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { useTranslation } from '../i18n';
import {
  Globe,
  MessageSquare,
  QrCode,
  Shield,
  Lock,
  Cpu,
  Activity,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  ArrowRight,
  Layers,
  FileCheck,
  Terminal
} from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

export const ScrollStorySection: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useTranslation();

  const sectionRef = useRef<HTMLDivElement>(null);
  const pinContainerRef = useRef<HTMLDivElement>(null);

  // Active step index (0: Input, 1: Route, 2: Intelligence, 3: Evidence, 4: Risk, 5: Protected)
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion || !sectionRef.current || !pinContainerRef.current) return;

    // Is mobile check
    const isMobile = window.innerWidth < 768;

    const ctx = gsap.context(() => {
      // Create master scroll timeline
      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: sectionRef.current,
          pin: !isMobile,
          start: 'top top+=80',
          end: isMobile ? '+=800' : '+=1800',
          scrub: 1,
          anticipatePin: 1,
          onUpdate: (self) => {
            const p = self.progress;
            if (p < 0.18) setActiveStep(0);
            else if (p < 0.38) setActiveStep(1);
            else if (p < 0.58) setActiveStep(2);
            else if (p < 0.78) setActiveStep(3);
            else if (p < 0.92) setActiveStep(4);
            else setActiveStep(5);
          }
        }
      });

      if (!isMobile) {
        // --- STEP 1: MODALITIES ENTRANCE ---
        tl.fromTo(
          '.story-modality-card',
          { y: 40, opacity: 0, scale: 0.95 },
          { y: 0, opacity: 1, scale: 1, stagger: 0.08, duration: 1 }
        );

        // --- STEP 2: ROUTING & CONVERGENCE LINES ---
        tl.fromTo(
          '.story-routing-line',
          { strokeDashoffset: 400, opacity: 0 },
          { strokeDashoffset: 0, opacity: 1, stagger: 0.06, duration: 1.2 }
        );

        // --- STEP 3: CENTRAL INTELLIGENCE CONVERGENCE ---
        tl.fromTo(
          '.story-intelligence-core',
          { scale: 0.85, opacity: 0.3, filter: 'blur(4px)' },
          { scale: 1, opacity: 1, filter: 'blur(0px)', duration: 1 },
          '-=0.5'
        );

        tl.fromTo(
          '.story-pipeline-badge',
          { y: 20, opacity: 0 },
          { y: 0, opacity: 1, stagger: 0.1, duration: 0.8 },
          '-=0.6'
        );

        // --- STEP 4: EVIDENCE CARDS REVEAL ---
        tl.fromTo(
          '.story-evidence-card',
          { x: 30, opacity: 0 },
          { x: 0, opacity: 1, stagger: 0.15, duration: 1.2 }
        );

        // --- STEP 5: RISK ARBITRATION GAUGE ---
        tl.fromTo(
          '.story-risk-meter',
          { scale: 0.9, opacity: 0 },
          { scale: 1, opacity: 1, duration: 1 }
        );

        tl.fromTo(
          '.story-risk-indicator',
          { left: '10%' },
          { left: '82%', duration: 1.5, ease: 'power2.inOut' }
        );

        // --- STEP 6: VERIFIED PROTECTION STATE ---
        tl.fromTo(
          '.story-protection-overlay',
          { opacity: 0, scale: 0.95, y: 20 },
          { opacity: 1, scale: 1, y: 0, duration: 1.2 }
        );
      }
    }, sectionRef);

    return () => ctx.revert();
  }, []);

  const steps = [
    { num: '01', title: 'Multimodal Ingestion', desc: 'Accepts raw URLs, SMS/Email text, QR matrix images, and website domains simultaneously.' },
    { num: '02', title: 'Feature Extraction & Routing', desc: 'Extracts 31 URL features, 10,000 TF-IDF n-grams, deterministic QR data, and SSRF-safe DOM trees.' },
    { num: '03', title: 'ML & Deterministic Inspection', desc: 'Evaluates inputs through XGBoost v2.0, calibrated Logistic Regression, and Cheerio DOM AST.' },
    { num: '04', title: 'Explainable Evidence Signals', desc: 'Generates grounded signals with exact severity weights (CRITICAL, HIGH, MEDIUM, LOW).' },
    { num: '05', title: 'Unified Risk Arbitration', desc: 'Aggregates signals, bounds uncertainty, and computes final calibrated risk score (0-100).' },
    { num: '06', title: 'Actionable Threat Defense', desc: 'Prescribes precise forensic actions and provides exportable audit telemetry.' }
  ];

  return (
    <div ref={sectionRef} className="relative w-full">
      {/* Pinned Container */}
      <div
        ref={pinContainerRef}
        className="w-full min-h-[580px] flex flex-col justify-between rounded-3xl bg-[#090e1a] border border-slate-800/80 p-6 sm:p-8 lg:p-10 shadow-2xl relative overflow-hidden"
      >
        {/* Background Depth Grid & Ambient Cyan Glow */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-cyan-500/10 rounded-full blur-[100px]" />
          <div className="absolute -bottom-32 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-blue-600/10 rounded-full blur-[100px]" />
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b15_1px,transparent_1px),linear-gradient(to_bottom,#1e293b15_1px,transparent_1px)] bg-[size:3rem_3rem]" />
        </div>

        {/* Section Header */}
        <div className="relative z-10 space-y-2 border-b border-slate-800/80 pb-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 text-xs font-semibold font-mono uppercase tracking-wider">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Architectural Execution Pipeline</span>
            </div>

            {/* Step Progress Pills */}
            <div className="flex items-center gap-1.5 font-mono text-[11px]">
              {steps.map((s, idx) => (
                <div
                  key={s.num}
                  className={`px-2.5 py-1 rounded-md transition-all duration-300 ${
                    activeStep === idx
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                      : 'bg-slate-900/60 text-slate-500 border border-slate-800'
                  }`}
                >
                  {s.num}
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-2 pt-1">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              {steps[activeStep].title}
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-xl font-normal">
              {steps[activeStep].desc}
            </p>
          </div>
        </div>

        {/* Interactive Story Visual Stage */}
        <div className="relative z-10 py-8 my-auto grid grid-cols-1 lg:grid-cols-12 gap-8 items-center min-h-[380px]">
          {/* Left Column: 4 Input Modalities */}
          <div className="lg:col-span-4 space-y-3">
            <div className="text-[10px] font-bold font-mono text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>1. Modality Ingestion</span>
            </div>

            {/* Modality 1: URL */}
            <div className={`story-modality-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 0 ? 'bg-[#0f172a] border-cyan-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-500'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold font-mono">URL Endpoint</div>
                    <div className="text-[10px] text-slate-400 font-mono">31 Lexical Features</div>
                  </div>
                </div>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                  ML v2.0.0
                </span>
              </div>
            </div>

            {/* Modality 2: Message */}
            <div className={`story-modality-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 0 ? 'bg-[#0f172a] border-purple-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-500'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg bg-purple-950 border border-purple-800 text-purple-400">
                    <MessageSquare className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold font-mono">Message / Email Text</div>
                    <div className="text-[10px] text-slate-400 font-mono">10,000 TF-IDF n-grams</div>
                  </div>
                </div>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800">
                  ML v2.0.0
                </span>
              </div>
            </div>

            {/* Modality 3: QR */}
            <div className={`story-modality-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 0 ? 'bg-[#0f172a] border-amber-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-500'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg bg-amber-950 border border-amber-800 text-amber-400">
                    <QrCode className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold font-mono">QR Matrix Image</div>
                    <div className="text-[10px] text-slate-400 font-mono">jsQR Decoder</div>
                  </div>
                </div>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800">
                  Deterministic
                </span>
              </div>
            </div>

            {/* Modality 4: Website */}
            <div className={`story-modality-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 0 ? 'bg-[#0f172a] border-emerald-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-500'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-400">
                    <Lock className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-bold font-mono">Website DOM</div>
                    <div className="text-[10px] text-slate-400 font-mono">SSRF Multi-Hop Safe</div>
                  </div>
                </div>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800">
                  SSRF-Shielded
                </span>
              </div>
            </div>
          </div>

          {/* Center Column: Intelligence Convergence Core & Unified Risk Engine */}
          <div className="lg:col-span-4 flex flex-col items-center justify-center relative">
            {/* SVG Dynamic Routing Lines */}
            <svg
              className="absolute inset-0 w-full h-full pointer-events-none hidden lg:block"
              viewBox="0 0 300 300"
              fill="none"
            >
              <path
                d="M 10 50 C 100 50, 150 120, 150 150"
                className="story-routing-line"
                stroke="#22d3ee"
                strokeWidth="1.5"
                strokeDasharray="4 4"
                strokeOpacity={activeStep >= 1 ? '0.8' : '0.2'}
              />
              <path
                d="M 10 110 C 80 110, 130 135, 150 150"
                className="story-routing-line"
                stroke="#c084fc"
                strokeWidth="1.5"
                strokeDasharray="4 4"
                strokeOpacity={activeStep >= 1 ? '0.8' : '0.2'}
              />
              <path
                d="M 10 190 C 80 190, 130 165, 150 150"
                className="story-routing-line"
                stroke="#fbbf24"
                strokeWidth="1.5"
                strokeDasharray="4 4"
                strokeOpacity={activeStep >= 1 ? '0.8' : '0.2'}
              />
              <path
                d="M 10 250 C 100 250, 150 180, 150 150"
                className="story-routing-line"
                stroke="#34d399"
                strokeWidth="1.5"
                strokeDasharray="4 4"
                strokeOpacity={activeStep >= 1 ? '0.8' : '0.2'}
              />
            </svg>

            {/* Central Engine Visual Container */}
            <div className="story-intelligence-core relative p-6 rounded-2xl bg-[#0b1322] border border-slate-700/80 shadow-2xl text-center space-y-4 max-w-[280px] w-full z-20">
              <div className="relative mx-auto w-16 h-16 flex items-center justify-center">
                <div className={`absolute inset-0 rounded-full blur-xl transition-all duration-500 ${
                  activeStep >= 4 ? 'bg-rose-500/30' : activeStep >= 2 ? 'bg-cyan-500/30' : 'bg-slate-800'
                }`} />
                <div className="p-3.5 rounded-2xl bg-slate-900 border border-cyan-500/40 relative z-10">
                  <Shield className="w-8 h-8 text-cyan-400" />
                </div>
              </div>

              <div>
                <h3 className="text-sm font-extrabold text-white font-mono tracking-tight">
                  {activeStep >= 4 ? 'UNIFIED RISK ENGINE' : 'CROSS-MODAL ANALYSIS'}
                </h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                  {activeStep >= 4 ? 'Deterministic Arbitration' : 'Feature Convergence'}
                </p>
              </div>

              {/* Status Pills */}
              <div className="space-y-1.5 pt-1">
                <div className="story-pipeline-badge text-[10px] font-mono p-1.5 rounded bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">XGBoost URL:</span>
                  <span className="text-cyan-400 font-bold">P = 0.941</span>
                </div>
                <div className="story-pipeline-badge text-[10px] font-mono p-1.5 rounded bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">TF-IDF Text NLP:</span>
                  <span className="text-purple-400 font-bold">P = 0.884</span>
                </div>
                <div className="story-pipeline-badge text-[10px] font-mono p-1.5 rounded bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">DOM SSRF Check:</span>
                  <span className="text-emerald-400 font-bold">SECURE</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Grounded Evidence Signals & Calibrated Risk Decision */}
          <div className="lg:col-span-4 space-y-3">
            <div className="text-[10px] font-bold font-mono text-slate-400 uppercase tracking-wider mb-2 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <FileCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>2. Evidence & Risk</span>
              </span>
              <span className="text-[9px] text-slate-500 font-normal">Illustrative Example</span>
            </div>

            {/* Evidence Signal 1 */}
            <div className={`story-evidence-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 3 ? 'bg-rose-950/30 border-rose-800/60 opacity-100' : 'bg-slate-900/20 border-slate-800/50 opacity-40'
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-rose-300 font-mono flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                  <span>CRITICAL • url.ml.phishing</span>
                </span>
                <span className="text-[10px] font-mono text-rose-400 font-bold">+50 PTS</span>
              </div>
              <p className="text-[11px] text-slate-300 mt-1 leading-snug">
                ML classifier detected high-confidence phishing heuristics in lexical URL composition.
              </p>
            </div>

            {/* Evidence Signal 2 */}
            <div className={`story-evidence-card p-3 rounded-xl border transition-all duration-300 ${
              activeStep >= 3 ? 'bg-amber-950/30 border-amber-800/60 opacity-100' : 'bg-slate-900/20 border-slate-800/50 opacity-40'
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-amber-300 font-mono flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>HIGH • message.ml.scam_intent</span>
                </span>
                <span className="text-[10px] font-mono text-amber-400 font-bold">+30 PTS</span>
              </div>
              <p className="text-[11px] text-slate-300 mt-1 leading-snug">
                Social-engineering urgency and account suspension pressure detected in text content.
              </p>
            </div>

            {/* Restrained Risk Decision Meter */}
            <div className="story-risk-meter p-3.5 rounded-xl bg-[#080d18] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Calibrated Risk Score:</span>
                <span className={`font-bold text-sm ${
                  activeStep >= 4 ? 'text-rose-400' : 'text-slate-400'
                }`}>
                  {activeStep >= 4 ? '88 / 100 (CRITICAL)' : '-- / 100'}
                </span>
              </div>

              {/* Animated Risk Spectrum Bar */}
              <div className="relative h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                <div className="absolute inset-0 bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-600 opacity-60" />
                <div
                  className="story-risk-indicator absolute top-0 bottom-0 w-2.5 bg-white rounded-full shadow-[0_0_10px_#fff] transition-all"
                  style={{ left: activeStep >= 4 ? '88%' : '10%' }}
                />
              </div>

              <div className="flex justify-between text-[9px] font-mono text-slate-500">
                <span>0 LOW</span>
                <span>40 ELEVATED</span>
                <span>70 HIGH</span>
                <span>85 CRITICAL</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Protected State & Action CTA */}
        <div className="relative z-20 border-t border-slate-800/80 pt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-950/80 border border-emerald-700/60 text-emerald-400 flex-shrink-0">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-bold text-white font-mono">Zero-Retention Architectural Guarantee</div>
              <div className="text-[11px] text-slate-400">
                Inputs and evidence are quarantined with full cryptographic provenance and right-to-erasure compliance.
              </div>
            </div>
          </div>

          <button
            onClick={() => navigate('/scanner')}
            className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs font-mono flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20 transition group flex-shrink-0 cursor-pointer"
          >
            <span>Launch Multi-Scanner</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>
      </div>
    </div>
  );
};
