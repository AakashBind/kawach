import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { ApiService } from '../services/api';
import { AuthService } from '../services/auth';
import { FraudReport } from '../types';
import { useTranslation } from '../i18n';
import { FileText, Send, CheckCircle2, AlertCircle, ShieldAlert, Clock, Loader2, Lock, LogIn, UserPlus, ArrowLeft } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const initialScanId = searchParams.get('scan_id') || '';
  const initialTarget = searchParams.get('target') || '';

  const isAuthenticated = AuthService.isAuthenticated();

  const [scanId, setScanId] = useState(initialScanId);
  const [category, setCategory] = useState('phishing_lure');
  const [description, setDescription] = useState(initialTarget ? `Observed suspicious activity on target: ${initialTarget}` : '');
  const [reports, setReports] = useState<FraudReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  const loadReports = async () => {
    if (!isAuthenticated) return;
    try {
      const data = await ApiService.getReports();
      setReports(data);
    } catch {}
  };

  useEffect(() => {
    if (isAuthenticated) {
      loadReports();
    }
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    const returnUrl = encodeURIComponent(`/reports${initialScanId ? `?scan_id=${initialScanId}&target=${encodeURIComponent(initialTarget)}` : ''}`);
    return (
      <div className="max-w-2xl mx-auto py-12 px-4 space-y-6">
        <div className="p-8 rounded-2xl bg-[#0f172a] border border-[#1e293b] shadow-2xl text-center space-y-5">
          <div className="w-14 h-14 rounded-2xl bg-cyan-950/80 border border-cyan-700/60 flex items-center justify-center text-cyan-400 mx-auto shadow-inner">
            <Lock className="w-7 h-7" />
          </div>

          <div className="space-y-2">
            <h1 className="text-2xl font-extrabold text-white tracking-tight">
              Sign In Required
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-md mx-auto leading-relaxed">
              Create an account or sign in to submit and track a security incident report with verified audit provenance.
            </p>
          </div>

          {initialScanId && (
            <div className="p-3 rounded-xl bg-[#070b14] border border-slate-800 text-left font-mono text-xs space-y-1">
              <div className="text-slate-500 uppercase text-[10px]">Attached Scan Target:</div>
              <div className="text-cyan-300 font-bold truncate">{initialTarget || initialScanId}</div>
            </div>
          )}

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <Link
              to={`/login?redirect=${returnUrl}`}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/25 transition"
            >
              <LogIn className="w-4 h-4" />
              <span>{t('nav.signIn')}</span>
            </Link>

            <Link
              to={`/register?redirect=${returnUrl}`}
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-[#0b0f19] hover:bg-[#131d33] text-slate-200 border border-slate-800 hover:border-slate-600 font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 transition"
            >
              <UserPlus className="w-4 h-4 text-cyan-400" />
              <span>{t('nav.createAccount')}</span>
            </Link>

            <Link
              to="/scanner"
              className="w-full sm:w-auto px-5 py-3 rounded-xl text-slate-400 hover:text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Cancel</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!description.trim()) {
      setError(t('reports.descriptionRequired'));
      return;
    }
    setLoading(true);
    setError('');
    try {
      await ApiService.submitReport({
        scan_id: scanId || undefined,
        category,
        description: description.trim(),
        evidence_summary: initialTarget ? `Target: ${initialTarget}` : undefined
      });
      setSubmitted(true);
      setDescription('');
      loadReports();
      setTimeout(() => setSubmitted(false), 3000);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to file fraud report.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-8">
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-950/60 border border-rose-800/60 text-rose-400 text-xs font-mono font-semibold uppercase tracking-wider mb-2">
          <ShieldAlert className="w-3.5 h-3.5" />
          {t('reports.badge')}
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          {t('reports.title')}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
          {t('reports.subtitle')}
        </p>
      </div>

      {/* Submission Form */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 sm:p-8 shadow-xl space-y-6">
        <h2 className="text-base font-bold text-white flex items-center gap-2 border-b border-[#1e293b] pb-3">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>{t('reports.formTitle')}</span>
        </h2>

        {submitted ? (
          <div className="p-8 text-center bg-[#070a12] border border-emerald-800/60 rounded-xl space-y-2">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
            <h3 className="text-base font-bold text-white">{t('reports.filedSuccessTitle')}</h3>
            <p className="text-xs text-slate-300">
              {t('reports.filedSuccessDesc')}
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3 bg-rose-950/60 border border-rose-800 text-rose-300 text-xs rounded-xl flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5 font-mono">
                  {t('reports.threatCategory')}
                </label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-3 py-2.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-cyan-400"
                >
                  <option value="phishing_lure">{t('reports.catPhishing')}</option>
                  <option value="bank_impersonation">{t('reports.catBanking')}</option>
                  <option value="crypto_fraud">{t('reports.catCrypto')}</option>
                  <option value="lottery_prize">{t('reports.catLottery')}</option>
                  <option value="malicious_qr">{t('reports.catQr')}</option>
                  <option value="credential_harvester">{t('reports.catCredential')}</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5 font-mono">
                  {t('reports.scanIdOptional')}
                </label>
                <input
                  type="text"
                  value={scanId}
                  onChange={(e) => setScanId(e.target.value)}
                  placeholder="e.g. scn_5091aefc"
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5 font-mono">
                {t('reports.detailsLabel')}
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
                placeholder={t('reports.detailsPlaceholder')}
                className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl p-3.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 leading-relaxed"
              />
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center gap-2 shadow transition disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>{loading ? t('reports.btnSubmitting') : t('reports.btnSubmit')}</span>
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Incident Ledger */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 sm:p-8 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2 font-mono">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>{t('reports.ledgerTitle')} ({reports.length})</span>
          </h2>
          <span className="text-xs text-slate-500 font-mono">{t('reports.ledgerSubtitle')}</span>
        </div>

        {reports.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500 font-mono">
            {t('reports.noReports')}
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((rep) => (
              <div key={rep.id} className="p-4 rounded-xl bg-[#070a12] border border-[#1e293b] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                    {rep.category.replace(/_/g, ' ')}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                    {t('common.status')}: {rep.status}
                  </span>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed">{rep.description}</p>
                <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between pt-1">
                  <span>{t('reports.reportId')} {rep.id}</span>
                  <span>{new Date(rep.created_at).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
