import React, { useEffect, useRef } from 'react';

export const CyberBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener('resize', handleResize);

    // Cyber Network Nodes
    const nodeCount = Math.min(Math.floor((width * height) / 22000), 55);
    const nodes: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      color: string;
      pulseSpeed: number;
      pulseVal: number;
      isHex?: boolean;
    }> = [];

    const colors = ['#06b6d4', '#38bdf8', '#818cf8', '#a855f7'];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        radius: Math.random() * 2 + 1.5,
        color: colors[Math.floor(Math.random() * colors.length)],
        pulseSpeed: 0.02 + Math.random() * 0.03,
        pulseVal: Math.random() * Math.PI,
        isHex: Math.random() > 0.75
      });
    }

    // Laser Radar Scan Line state
    let scanY = 0;
    const scanSpeed = 1.2;

    const drawHexagon = (context: CanvasRenderingContext2D, x: number, y: number, r: number) => {
      context.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        const hx = x + r * Math.cos(angle);
        const hy = y + r * Math.sin(angle);
        if (i === 0) context.moveTo(hx, hy);
        else context.lineTo(hx, hy);
      }
      context.closePath();
    };

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Advance Radar Scan Line
      scanY += scanSpeed;
      if (scanY > height + 100) scanY = -100;

      // Draw Radar Scan Line & Aura
      const scanGrad = ctx.createLinearGradient(0, scanY - 60, 0, scanY + 60);
      scanGrad.addColorStop(0, 'rgba(6, 182, 212, 0)');
      scanGrad.addColorStop(0.5, 'rgba(6, 182, 212, 0.08)');
      scanGrad.addColorStop(1, 'rgba(6, 182, 212, 0)');
      ctx.fillStyle = scanGrad;
      ctx.fillRect(0, scanY - 60, width, 120);

      // Fine Laser Beam
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.25)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, scanY);
      ctx.lineTo(width, scanY);
      ctx.stroke();

      // 2. Update and Draw Network Connections
      const maxDistance = 140;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.22;
            ctx.strokeStyle = `rgba(6, 182, 212, ${alpha})`;
            ctx.lineWidth = 0.75;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // 3. Draw Nodes & Hexagon Markers
      for (const node of nodes) {
        node.x += node.vx;
        node.y += node.vy;

        if (node.x < 0) node.x = width;
        else if (node.x > width) node.x = 0;
        if (node.y < 0) node.y = height;
        else if (node.y > height) node.y = 0;

        node.pulseVal += node.pulseSpeed;
        const currentRadius = node.radius + Math.sin(node.pulseVal) * 0.8;
        const alpha = 0.4 + Math.sin(node.pulseVal) * 0.25;

        if (node.isHex) {
          ctx.strokeStyle = node.color;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1;
          drawHexagon(ctx, node.x, node.y, currentRadius * 3);
          ctx.stroke();
          ctx.globalAlpha = 1;
        } else {
          ctx.fillStyle = node.color;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.arc(node.x, node.y, currentRadius, 0, Math.PI * 2);
          ctx.fill();

          // Outer Glow Ring
          ctx.strokeStyle = node.color;
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, currentRadius * 2.2, 0, Math.PI * 2);
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none bg-[#050914]"
      aria-hidden="true"
    >
      {/* Ambient Cyber Aurora Plasma Blooms */}
      <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-cyan-600/20 blur-[140px] animate-pulse" style={{ animationDuration: '8s' }} />
      <div className="absolute top-1/3 -right-40 w-[650px] h-[650px] rounded-full bg-blue-600/20 blur-[150px] animate-pulse" style={{ animationDuration: '10s' }} />
      <div className="absolute -bottom-40 left-1/4 w-[700px] h-[700px] rounded-full bg-indigo-600/18 blur-[160px] animate-pulse" style={{ animationDuration: '12s' }} />

      {/* Cyber Grid Vector Layer */}
      <div
        className="absolute inset-0 opacity-[0.14]"
        style={{
          backgroundImage: `
            linear-gradient(to right, #06b6d4 1px, transparent 1px),
            linear-gradient(to bottom, #06b6d4 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px'
        }}
      />

      {/* Dynamic Cyber Security Canvas (Nodes, Lasers, Hexagons) */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full block"
      />

      {/* Fine Horizontal Scanlines */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, #000, #000 2px, transparent 2px, transparent 4px)'
        }}
      />
    </div>
  );
};
