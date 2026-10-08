import React, { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { Globe, MessageSquare, QrCode, Lock, Activity } from 'lucide-react';

interface ThreatVisualProps {
  isScanning?: boolean;
  onScanComplete?: () => void;
}

export const InteractiveThreatVisual: React.FC<ThreatVisualProps> = ({ isScanning = false, onScanComplete }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const shieldRef = useRef<HTMLDivElement>(null);
  const ringsRef = useRef<SVGSVGElement>(null);
  const nodesRef = useRef<HTMLDivElement>(null);
  const particlesRef = useRef<HTMLDivElement>(null);
  const linesRef = useRef<SVGSVGElement>(null);
  const sweepRef = useRef<HTMLDivElement>(null);

  const [isHovered, setIsHovered] = useState(false);

  // QuickTo animators for buttery smooth mouse parallax
  const xToCard = useRef<any>(null);
  const yToCard = useRef<any>(null);
  const xToShield = useRef<any>(null);
  const yToShield = useRef<any>(null);
  const xToNodes = useRef<any>(null);
  const yToNodes = useRef<any>(null);
  const xToParticles = useRef<any>(null);
  const yToParticles = useRef<any>(null);
  const xToRings = useRef<any>(null);
  const yToRings = useRef<any>(null);

  useEffect(() => {
    // Check reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion || !cardRef.current) return;

    // Initialize gsap quickTo for optimal 60fps interpolation
    xToCard.current = gsap.quickTo(cardRef.current, 'rotationY', { duration: 0.6, ease: 'power2.out' });
    yToCard.current = gsap.quickTo(cardRef.current, 'rotationX', { duration: 0.6, ease: 'power2.out' });

    if (shieldRef.current) {
      xToShield.current = gsap.quickTo(shieldRef.current, 'x', { duration: 0.7, ease: 'power2.out' });
      yToShield.current = gsap.quickTo(shieldRef.current, 'y', { duration: 0.7, ease: 'power2.out' });
    }

    if (nodesRef.current) {
      xToNodes.current = gsap.quickTo(nodesRef.current, 'x', { duration: 0.5, ease: 'power2.out' });
      yToNodes.current = gsap.quickTo(nodesRef.current, 'y', { duration: 0.5, ease: 'power2.out' });
    }

    if (particlesRef.current) {
      xToParticles.current = gsap.quickTo(particlesRef.current, 'x', { duration: 0.9, ease: 'power2.out' });
      yToParticles.current = gsap.quickTo(particlesRef.current, 'y', { duration: 0.9, ease: 'power2.out' });
    }

    if (ringsRef.current) {
      xToRings.current = gsap.quickTo(ringsRef.current, 'x', { duration: 0.6, ease: 'power2.out' });
      yToRings.current = gsap.quickTo(ringsRef.current, 'y', { duration: 0.6, ease: 'power2.out' });
    }

    // Continuous autonomous idle pulse & orbital rotation
    const ctx = gsap.context(() => {
      // Rotate orbital scanning rings
      gsap.to('.scanning-orbit-1', {
        rotation: 360,
        transformOrigin: 'center center',
        duration: 26,
        repeat: -1,
        ease: 'none'
      });

      gsap.to('.scanning-orbit-2', {
        rotation: -360,
        transformOrigin: 'center center',
        duration: 34,
        repeat: -1,
        ease: 'none'
      });

      // Gentle floating animation for the shield
      gsap.to(shieldRef.current, {
        y: '-=4',
        duration: 2.8,
        repeat: -1,
        yoyo: true,
        ease: 'sine.inOut'
      });

      // Subtle pulse on connection lines
      gsap.to('.threat-connection-line', {
        strokeOpacity: 0.65,
        duration: 2,
        repeat: -1,
        yoyo: true,
        stagger: 0.25,
        ease: 'sine.inOut'
      });

      // Subtle float on threat nodes
      gsap.to('.threat-node', {
        y: '-=3',
        duration: 2.4,
        repeat: -1,
        yoyo: true,
        stagger: {
          each: 0.3,
          from: 'random'
        },
        ease: 'sine.inOut'
      });
    }, containerRef);

    return () => ctx.revert();
  }, []);

  // Handle Mouse Parallax
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!containerRef.current || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const rect = containerRef.current.getBoundingClientRect();
    const xRel = e.clientX - rect.left;
    const yRel = e.clientY - rect.top;

    // Normalized from -1 to 1
    const xNorm = (xRel / rect.width) * 2 - 1;
    const yNorm = (yRel / rect.height) * 2 - 1;

    // Restrained rotations (±5-6 degrees max to prevent extreme tilt)
    const rotY = xNorm * 5.5;
    const rotX = -yNorm * 5.5;

    if (xToCard.current) xToCard.current(rotY);
    if (yToCard.current) yToCard.current(rotX);

    // Multi-depth parallax offsets
    if (xToShield.current) {
      xToShield.current(xNorm * 4);
      yToShield.current(yNorm * 4);
    }
    if (xToNodes.current) {
      xToNodes.current(xNorm * 9);
      yToNodes.current(yNorm * 9);
    }
    if (xToParticles.current) {
      xToParticles.current(xNorm * -6);
      yToParticles.current(yNorm * -6);
    }
    if (xToRings.current) {
      xToRings.current(xNorm * 5);
      yToRings.current(yNorm * 5);
    }
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    if (xToCard.current) xToCard.current(0);
    if (yToCard.current) yToCard.current(0);
    if (xToShield.current) {
      xToShield.current(0);
      yToShield.current(0);
    }
    if (xToNodes.current) {
      xToNodes.current(0);
      yToNodes.current(0);
    }
    if (xToParticles.current) {
      xToParticles.current(0);
      yToParticles.current(0);
    }
    if (xToRings.current) {
      xToRings.current(0);
      yToRings.current(0);
    }
  };

  const handleMouseEnter = () => {
    setIsHovered(true);
  };

  // Scan Surge Sequence triggered by scanner CTA
  useEffect(() => {
    if (!isScanning) return;

    const tl = gsap.timeline({
      onComplete: () => {
        if (onScanComplete) onScanComplete();
      }
    });

    // 1. Central sweep wave
    tl.to(sweepRef.current, {
      top: '120%',
      opacity: 1,
      duration: 0.35,
      ease: 'power2.inOut'
    }, 0);

    // 2. Expand scanning rings
    tl.to('.scanning-surge-ring', {
      scale: 1.35,
      opacity: 0,
      duration: 0.4,
      ease: 'expo.out',
      stagger: 0.08
    }, 0);

    // 3. Threat nodes illuminate
    tl.to('.threat-node', {
      scale: 1.1,
      borderColor: '#22d3ee',
      boxShadow: '0 0 16px rgba(34, 211, 238, 0.5)',
      duration: 0.2,
      yoyo: true,
      repeat: 1,
      stagger: 0.04
    }, 0.1);

    // 4. Shield core surge
    tl.to(shieldRef.current, {
      scale: 1.05,
      filter: 'drop-shadow(0 0 30px rgba(6, 182, 212, 0.8))',
      duration: 0.2,
      yoyo: true,
      repeat: 1
    }, 0.1);

  }, [isScanning, onScanComplete]);

  // Real Architecture Threat & Modality Nodes with calibrated percentages
  const threatNodes = [
    {
      id: 'url',
      label: 'URL ML',
      tag: 'XGBoost v2',
      status: 'VERIFIED',
      x: '18%',
      y: '20%',
      icon: <Globe className="w-3.5 h-3.5 text-cyan-400" />,
      color: 'border-cyan-500/50 bg-[#071326]/90 text-cyan-300'
    },
    {
      id: 'msg',
      label: 'MSG NLP',
      tag: 'TF-IDF + LR',
      status: 'CALIBRATED',
      x: '82%',
      y: '22%',
      icon: <MessageSquare className="w-3.5 h-3.5 text-purple-400" />,
      color: 'border-purple-500/50 bg-[#160c29]/90 text-purple-300'
    },
    {
      id: 'qr',
      label: 'QR MATRIX',
      tag: 'Deterministic',
      status: 'ACTIVE',
      x: '18%',
      y: '76%',
      icon: <QrCode className="w-3.5 h-3.5 text-amber-400" />,
      color: 'border-amber-500/50 bg-[#1f1606]/90 text-amber-300'
    },
    {
      id: 'web',
      label: 'WEB DOM',
      tag: 'SSRF Shield',
      status: 'GUARDED',
      x: '82%',
      y: '74%',
      icon: <Lock className="w-3.5 h-3.5 text-emerald-400" />,
      color: 'border-emerald-500/50 bg-[#061814]/90 text-emerald-300'
    },
    {
      id: 'risk',
      label: 'RISK ENGINE',
      tag: 'Arbitration',
      status: '0-100',
      x: '50%',
      y: '88%',
      icon: <Activity className="w-3.5 h-3.5 text-cyan-400" />,
      color: 'border-cyan-500/60 bg-[#0a1628]/95 text-cyan-200'
    }
  ];

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className="relative w-full max-w-[360px] sm:max-w-[420px] lg:max-w-[440px] aspect-square mx-auto select-none perspective-[1000px] flex items-center justify-center p-1 sm:p-2"
      aria-label="Interactive Scam Shield Threat Intelligence Visual"
    >
      {/* Outer 3D Card wrapper */}
      <div
        ref={cardRef}
        style={{ transformStyle: 'preserve-3d' }}
        className={`relative w-full h-full rounded-3xl bg-[#090d16]/75 border border-slate-800/80 backdrop-blur-xl p-3 sm:p-4 flex items-center justify-center shadow-xl transition-shadow duration-500 overflow-hidden ${
          isHovered
            ? 'shadow-[0_15px_45px_-10px_rgba(6,182,212,0.18)] border-slate-700'
            : 'shadow-[0_10px_30px_-15px_rgba(0,0,0,0.7)]'
        }`}
      >
        {/* Subtle Background Radial Grid & Particles */}
        <div ref={particlesRef} className="absolute inset-0 overflow-hidden rounded-3xl pointer-events-none">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[280px] h-[280px] bg-cyan-950/20 rounded-full blur-2xl" />
          <div className="absolute top-1/3 left-1/4 w-1.5 h-1.5 rounded-full bg-cyan-400/40 animate-ping" style={{ animationDuration: '4s' }} />
          <div className="absolute top-2/3 right-1/4 w-1.5 h-1.5 rounded-full bg-purple-400/30 animate-pulse" style={{ animationDuration: '3s' }} />
          <div className="absolute top-1/4 right-1/3 w-1 h-1 rounded-full bg-emerald-400/40" />
          <div className="absolute bottom-1/4 left-1/3 w-1 h-1 rounded-full bg-amber-400/40" />
        </div>

        {/* Dynamic Security Radar / Connection Lines SVG */}
        <svg
          ref={linesRef}
          className="absolute inset-0 w-full h-full pointer-events-none"
          viewBox="0 0 500 500"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="lineGradCyan" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#0891b2" stopOpacity="0.1" />
            </linearGradient>
            <linearGradient id="lineGradPurple" x1="100%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#c084fc" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#7e22ce" stopOpacity="0.1" />
            </linearGradient>
            <linearGradient id="lineGradAmber" x1="0%" y1="100%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#fbbf24" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#b45309" stopOpacity="0.1" />
            </linearGradient>
            <linearGradient id="lineGradEmerald" x1="100%" y1="100%" x2="0%" y2="0%">
              <stop offset="0%" stopColor="#34d399" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#059669" stopOpacity="0.1" />
            </linearGradient>
          </defs>

          {/* Connection Lines from Nodes to Center Shield (Center: 250, 235) */}
          <line
            x1="100" y1="110" x2="250" y2="235"
            className="threat-connection-line"
            stroke="url(#lineGradCyan)"
            strokeWidth={isHovered ? '1.5' : '1'}
            strokeDasharray="4 4"
          />
          <line
            x1="400" y1="115" x2="250" y2="235"
            className="threat-connection-line"
            stroke="url(#lineGradPurple)"
            strokeWidth={isHovered ? '1.5' : '1'}
            strokeDasharray="4 4"
          />
          <line
            x1="100" y1="370" x2="250" y2="235"
            className="threat-connection-line"
            stroke="url(#lineGradAmber)"
            strokeWidth={isHovered ? '1.5' : '1'}
            strokeDasharray="4 4"
          />
          <line
            x1="400" y1="365" x2="250" y2="235"
            className="threat-connection-line"
            stroke="url(#lineGradEmerald)"
            strokeWidth={isHovered ? '1.5' : '1'}
            strokeDasharray="4 4"
          />
          <line
            x1="250" y1="435" x2="250" y2="235"
            className="threat-connection-line"
            stroke="url(#lineGradCyan)"
            strokeWidth={isHovered ? '1.5' : '1'}
            strokeDasharray="3 3"
          />
        </svg>

        {/* Concentric Scanning Rings */}
        <svg
          ref={ringsRef}
          className="absolute inset-0 w-full h-full pointer-events-none"
          viewBox="0 0 500 500"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Inner Static Boundary */}
          <circle cx="250" cy="235" r="75" stroke="#1e293b" strokeWidth="1" strokeOpacity="0.8" />
          <circle cx="250" cy="235" r="115" stroke="#0e2238" strokeWidth="1" strokeDasharray="6 6" />

          {/* Rotating Orbit 1 */}
          <circle
            cx="250" cy="235" r="145"
            className="scanning-orbit-1"
            stroke="#0891b2"
            strokeWidth="1.2"
            strokeOpacity={isHovered ? '0.6' : '0.3'}
            strokeDasharray="25 150 50 100"
          />

          {/* Rotating Orbit 2 */}
          <circle
            cx="250" cy="235" r="180"
            className="scanning-orbit-2"
            stroke="#1e3a5f"
            strokeWidth="1"
            strokeOpacity={isHovered ? '0.65' : '0.35'}
            strokeDasharray="15 80 35 120"
          />

          {/* Surge Rings for Launch Interaction */}
          <circle
            cx="250" cy="235" r="90"
            className="scanning-surge-ring opacity-0 pointer-events-none"
            stroke="#22d3ee"
            strokeWidth="2"
          />
          <circle
            cx="250" cy="235" r="110"
            className="scanning-surge-ring opacity-0 pointer-events-none"
            stroke="#38bdf8"
            strokeWidth="1.5"
          />
        </svg>

        {/* Central Scan Sweep Beam for Scan Trigger */}
        <div
          ref={sweepRef}
          className="absolute top-[-20%] left-0 right-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-0 pointer-events-none blur-[1px] shadow-[0_0_15px_#22d3ee]"
        />

        {/* Core Shield & Security Identity */}
        <div
          ref={shieldRef}
          style={{ transform: 'translateZ(25px)' }}
          className="relative z-20 flex flex-col items-center justify-center p-2"
        >
          {/* Hex glow behind shield */}
          <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/20 to-blue-600/10 rounded-full blur-xl -z-10 scale-110" />

          <div className="relative group cursor-pointer flex justify-center items-center">
            <img
              src="/logo.png"
              alt="Scam Shield"
              className={`w-24 sm:w-28 md:w-32 max-h-[120px] sm:max-h-[140px] h-auto object-contain transition-transform duration-300 ${
                isHovered ? 'scale-105 filter drop-shadow-[0_0_20px_rgba(6,182,212,0.45)]' : 'filter drop-shadow-[0_0_12px_rgba(6,182,212,0.2)]'
              }`}
              loading="eager"
            />
          </div>

          {/* Core Status Badge */}
          <div className="mt-1.5 inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800/80 text-[10px] font-mono text-cyan-300 font-semibold tracking-wide shadow-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>PROTECTED • v2.0</span>
          </div>
        </div>

        {/* Threat / Modality Real Architecture Nodes */}
        <div ref={nodesRef} className="absolute inset-0 pointer-events-none">
          {threatNodes.map((node) => (
            <div
              key={node.id}
              style={{
                left: node.x,
                top: node.y,
                transform: 'translate(-50%, -50%) translateZ(35px)'
              }}
              className={`threat-node absolute pointer-events-auto p-1.5 sm:p-2 rounded-xl border backdrop-blur-md shadow-md transition-all duration-300 ${node.color} ${
                isHovered ? 'scale-105 border-opacity-90' : 'border-opacity-40'
              }`}
            >
              <div className="flex items-center gap-1">
                {node.icon}
                <span className="text-[10px] sm:text-[11px] font-extrabold font-mono tracking-tight">{node.label}</span>
              </div>
              <div className="flex items-center justify-between gap-1.5 mt-0.5 text-[8px] sm:text-[9px] font-mono opacity-85">
                <span>{node.tag}</span>
                <span className="text-emerald-400 font-bold">{node.status}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Bottom Narrative Flow Tag */}
        <div className="absolute bottom-2.5 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-lg bg-[#070b14]/85 border border-slate-800 text-[8px] sm:text-[9px] font-mono text-slate-400 flex items-center gap-1 tracking-wider uppercase z-30 whitespace-nowrap">
          <span className="text-cyan-400 font-bold">Detect</span>
          <span>→</span>
          <span className="text-purple-400 font-bold">Analyze</span>
          <span>→</span>
          <span className="text-amber-400 font-bold">Correlate</span>
          <span>→</span>
          <span className="text-emerald-400 font-bold">Protect</span>
        </div>
      </div>
    </div>
  );
};
