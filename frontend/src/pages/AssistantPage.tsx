import React from 'react';
import { SecurityCopilot } from '../components/SecurityCopilot';
import { Sparkles, ShieldCheck, LifeBuoy } from 'lucide-react';

export const AssistantPage: React.FC = () => {
  return (
    <div className="py-6 space-y-6">
      <div className="text-center max-w-2xl mx-auto space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Active Cyber Defense Copilot</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          AI Incident Response & Scam Advisory
        </h1>
        <p className="text-sm text-slate-400">
          Ask questions, get emergency recovery procedures for compromised accounts, or learn how to report cyber fraud directly to legal authorities.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-4xl mx-auto text-xs text-slate-300">
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <span className="font-semibold text-slate-200">Incident Recovery</span>
            <p className="text-slate-400 text-[11px] mt-0.5">Steps to freeze bank accounts, revoke compromised tokens, and remove malware APKs.</p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
            <LifeBuoy className="w-4 h-4" />
          </div>
          <div>
            <span className="font-semibold text-slate-200">Official Reporting</span>
            <p className="text-slate-400 text-[11px] mt-0.5">Guidance on filing formal police complaints via 1930 & cybercrime.gov.in.</p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-3">
          <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <span className="font-semibold text-slate-200">Real-time Intelligence</span>
            <p className="text-slate-400 text-[11px] mt-0.5">Powered by advanced threat models and Kawach real-time cyber defense engine.</p>
          </div>
        </div>
      </div>

      <div className="pt-2">
        <SecurityCopilot isPageMode={true} />
      </div>
    </div>
  );
};
