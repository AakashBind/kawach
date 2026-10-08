import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ApiService } from '../services/api';
import { AuthService } from '../services/auth';
import { ScanResultData, ScanType, RiskLevel } from '../types';
import { useTranslation } from '../i18n';
import { RiskBadge } from '../components/RiskBadge';
import { History, Search, Trash2, Shield, Globe, MessageSquare, QrCode, AlertCircle, RefreshCw, ChevronRight, Lock, LogIn, UserPlus, ArrowLeft } from 'lucide-react';
import { ResultPage } from './ResultPage';

export const HistoryPage: React.FC = () => {
  const { t } = useTranslation();
  const isAuthenticated = AuthService.isAuthenticated();

  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedScan, setSelectedScan] = useState<ScanResultData | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('');
  const [filterRisk, setFilterRisk] = useState<string>('');

  const loadHistory = async () => {
    if (!isAuthenticated) return;
    setLoading(true);
    setError('');
    try {
      const data = await ApiService.getScans({
        type: filterType || undefined,
        risk_level: filterRisk || undefined,
        search: searchQuery || undefined
      });
      setScans(data);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to load scan history audit log.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      loadHistory();
    }
  }, [filterType, filterRisk, isAuthenticated]);

  if (!isAuthenticated) {
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
              Create an account or sign in to view and manage your private scan history and forensic audit logs.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <Link
              to="/login?redirect=/history"
              className="w-full sm:w-auto px-6 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/25 transition"
            >
              <LogIn className="w-4 h-4" />
              <span>{t('nav.signIn')}</span>
            </Link>

            <Link
              to="/register?redirect=/history"
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
              <span>Launch Scanner</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadHistory();
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(t('history.deleteConfirm'))) return;
    try {
      await ApiService.deleteScan(id);
      setScans(scans.filter(s => s.id !== id && s.scan_id !== id));
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to delete scan.');
    }
  };

  const handleClearAll = async () => {
    if (!confirm(t('history.purgeConfirm'))) return;
    try {
      await ApiService.clearAllScans();
      setScans([]);
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to clear scans.');
    }
  };

  const openScanDetail = async (scanSummary: any) => {
    try {
      const details = await ApiService.getScanDetails(scanSummary.id);
      const rawModelVersions = details.scan.model_versions;
      const modelVersionsList = typeof rawModelVersions === 'string'
        ? JSON.parse(rawModelVersions || '[]')
        : (Array.isArray(rawModelVersions) ? rawModelVersions : []);

      const scanIdStr = String(details.scan.id || scanSummary.id || 'scn_unknown');
      const targetText = String(details.scan.input_target || details.scan.target || 'Target');
      const summaryText = String(details.scan.raw_summary || details.scan.summary || 'Summary unavailable');
      const createdAtStr = String(details.scan.created_at || new Date().toISOString());

      const fullScan: ScanResultData = {
        scan_id: scanIdStr,
        scan_type: details.scan.scan_type as ScanType,
        target: targetText,
        summary: summaryText,
        risk_level: details.scan.risk_level as RiskLevel,
        risk_score: Number(details.scan.risk_score || 0),
        uncertainty: details.scan.uncertainty,
        reasons: details.evidence ? details.evidence.map((e: any) => e.explanation) : [],
        evidence: details.evidence || [],
        model_versions: modelVersionsList,
        recommended_actions: [
          'Verify destination through authentic, bookmarked domain entries.',
          'Do not share passwords, OTP codes, or identity numbers on untrusted origins.'
        ],
        generated_at: createdAtStr,
        analysis_id: scanIdStr
      };
      setSelectedScan(fullScan);
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to fetch scan detail.');
    }
  };

  const getModalityIcon = (type: ScanType) => {
    switch (type) {
      case 'url': return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'message': return <MessageSquare className="w-4 h-4 text-purple-400" />;
      case 'qr': return <QrCode className="w-4 h-4 text-amber-400" />;
      default: return <Shield className="w-4 h-4 text-emerald-400" />;
    }
  };

  if (selectedScan) {
    return (
      <ResultPage
        result={selectedScan}
        onNewScan={() => setSelectedScan(null)}
      />
    );
  }

  return (
    <div className="max-w-6xl mx-auto py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1e293b] pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <History className="w-6 h-6 text-cyan-400" />
            <span>{t('history.title')}</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            {t('history.subtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadHistory}
            className="p-2 rounded-xl bg-[#0f172a] border border-[#1e293b] text-slate-300 hover:text-white hover:border-slate-600 transition"
            title={t('history.refresh')}
            aria-label={t('history.refresh')}
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          {scans.length > 0 && (
            <button
              onClick={handleClearAll}
              className="px-3 py-2 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/40 text-xs font-semibold text-rose-300 flex items-center gap-1.5 transition"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{t('history.purge')}</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-4 flex flex-col md:flex-row items-center gap-3 shadow-lg">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t('history.searchPlaceholder')}
            className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl pl-10 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </form>

        <div className="flex items-center gap-2.5 w-full md:w-auto">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[#070a12] border border-[#1e293b] rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
          >
            <option value="">{t('history.allModalities')}</option>
            <option value="url">{t('history.urlScans')}</option>
            <option value="message">{t('history.messageScans')}</option>
            <option value="qr">{t('history.qrScans')}</option>
            <option value="website">{t('history.websiteCrawls')}</option>
          </select>

          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-[#070a12] border border-[#1e293b] rounded-xl px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-400"
          >
            <option value="">{t('history.allRiskTiers')}</option>
            <option value="LOW">{t('risk.low')}</option>
            <option value="MEDIUM">{t('risk.medium')}</option>
            <option value="HIGH">{t('risk.high')}</option>
            <option value="CRITICAL">{t('risk.critical')}</option>
            <option value="INSUFFICIENT_EVIDENCE">{t('risk.insufficient')}</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="py-16 text-center text-xs text-slate-400 font-mono bg-[#0f172a] border border-[#1e293b] rounded-2xl">
          {t('history.loadingText')}
        </div>
      ) : scans.length === 0 ? (
        <div className="py-16 text-center bg-[#0f172a] border border-[#1e293b] rounded-2xl p-8 space-y-3 shadow-lg">
          <Shield className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-slate-300">{t('history.noRecordsTitle')}</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            {t('history.noRecordsDesc')}
          </p>
        </div>
      ) : (
        <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl overflow-hidden shadow-xl">
          <div className="divide-y divide-[#1e293b]">
            {scans.map((scan: any) => (
              <div
                key={scan.id}
                onClick={() => openScanDetail(scan)}
                className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-[#131d33] cursor-pointer transition"
              >
                <div className="flex items-start sm:items-center gap-3.5 min-w-0">
                  <div className="p-2.5 rounded-xl bg-[#070a12] border border-[#1e293b] flex-shrink-0 mt-0.5 sm:mt-0">
                    {getModalityIcon(scan.scan_type)}
                  </div>
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase bg-cyan-950/50 border border-cyan-800/60 px-2 py-0.5 rounded">
                        {scan.scan_type}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        {new Date(scan.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs sm:text-sm font-mono text-slate-200 truncate max-w-2xl font-normal">
                      {scan.input_target || scan.target}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 flex-shrink-0">
                  <RiskBadge level={scan.risk_level as RiskLevel} size="sm" />
                  <span className="text-xs font-mono font-bold text-white px-2.5 py-1 rounded-md bg-[#070a12] border border-[#1e293b]">
                    {scan.risk_score}/100
                  </span>
                  <button
                    onClick={(e) => handleDelete(scan.id, e)}
                    className="p-1.5 text-slate-500 hover:text-rose-400 rounded-lg hover:bg-[#1e293b] transition"
                    title={t('history.deleteRecord')}
                    aria-label={t('history.deleteRecord')}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <ChevronRight className="w-4 h-4 text-slate-600 hidden sm:block" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
