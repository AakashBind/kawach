import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ApiService } from '../services/api';
import { ScanResultData, ScanType } from '../types';
import { useTranslation } from '../i18n';
import { Globe, MessageSquare, QrCode, Shield, Upload, Sparkles, AlertCircle, ArrowRight, Loader2, Terminal } from 'lucide-react';
import { ResultPage } from './ResultPage';

export const ScannerPage: React.FC = () => {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const tabParam = (searchParams.get('tab') as ScanType) || 'url';
  const [activeTab, setActiveTab] = useState<ScanType>(tabParam);

  // Input states
  const [urlInput, setUrlInput] = useState('');
  const [messageInput, setMessageInput] = useState('');
  const [contextInput, setContextInput] = useState('sms');
  const [websiteInput, setWebsiteInput] = useState('');
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);

  // Execution states
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState(t('scanner.stageValidating'));
  const [error, setError] = useState('');
  const [scanResult, setScanResult] = useState<ScanResultData | null>(null);

  useEffect(() => {
    const tab = searchParams.get('tab') as ScanType;
    if (tab && ['url', 'message', 'qr', 'website'].includes(tab)) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  const handleTabChange = (tab: ScanType) => {
    setActiveTab(tab);
    setSearchParams({ tab });
    setError('');
  };

  const handleQrFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 5 * 1024 * 1024) {
        setError(t('scanner.qrSizeError'));
        return;
      }
      setQrFile(file);
      setQrPreview(URL.createObjectURL(file));
      setError('');
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setLoadingStage(t('scanner.stageValidating'));
    setError('');
    setScanResult(null);

    try {
      let result: ScanResultData;
      if (activeTab === 'url') {
        if (!urlInput.trim()) throw new Error(t('scanner.errorUrlRequired'));
        setLoadingStage(t('scanner.stageUrlML'));
        result = await ApiService.scanUrl(urlInput.trim());
      } else if (activeTab === 'message') {
        if (!messageInput.trim()) throw new Error(t('scanner.errorMessageRequired'));
        setLoadingStage(t('scanner.stageMessageNLP'));
        result = await ApiService.scanMessage(messageInput.trim(), contextInput);
      } else if (activeTab === 'qr') {
        if (!qrFile) throw new Error(t('scanner.errorQrRequired'));
        setLoadingStage(t('scanner.stageQrDecode'));
        result = await ApiService.scanQr(qrFile);
      } else {
        if (!websiteInput.trim()) throw new Error(t('scanner.errorWebsiteRequired'));
        setLoadingStage(t('scanner.stageWebsiteSSRF'));
        result = await ApiService.scanWebsite(websiteInput.trim());
      }
      setScanResult(result);
    } catch (err: any) {
      const msg = err.response?.data?.error?.message || err.message || 'Scan request failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // Preset sample test lures
  const fillPreset = (type: string) => {
    setError('');
    if (type === 'phish_url') {
      setUrlInput('http://192.168.1.1/paypal-account-verification-alert99.tk/login.php');
      setActiveTab('url');
      setSearchParams({ tab: 'url' });
    } else if (type === 'benign_url') {
      setUrlInput('https://www.google.com/search?q=cybersecurity+defense');
      setActiveTab('url');
      setSearchParams({ tab: 'url' });
    } else if (type === 'bank_scam_sms') {
      setMessageInput('URGENT: Your Wells Fargo account has been suspended! Verify your credentials immediately at http://wellsfargo-verify-login.xyz to restore access.');
      setContextInput('sms');
      setActiveTab('message');
      setSearchParams({ tab: 'message' });
    } else if (type === 'lottery_scam') {
      setMessageInput('CONGRATULATIONS! You won $1,000,000 in the International Mobile Lottery. Send $500 processing fee via Bitcoin or UPI to claim prize.');
      setContextInput('email');
      setActiveTab('message');
      setSearchParams({ tab: 'message' });
    } else if (type === 'website_safe') {
      setWebsiteInput('https://example.com');
      setActiveTab('website');
      setSearchParams({ tab: 'website' });
    }
  };

  if (scanResult) {
    return (
      <ResultPage
        result={scanResult}
        onNewScan={() => {
          setScanResult(null);
          setUrlInput('');
          setMessageInput('');
          setWebsiteInput('');
          setQrFile(null);
          setQrPreview(null);
        }}
      />
    );
  }

  const tabConfigs = [
    { id: 'url', label: t('scanner.tabUrl'), icon: <Globe className="w-4 h-4 text-cyan-400" />, sub: t('scanner.tabUrlSub') },
    { id: 'message', label: t('scanner.tabMessage'), icon: <MessageSquare className="w-4 h-4 text-purple-400" />, sub: t('scanner.tabMessageSub') },
    { id: 'qr', label: t('scanner.tabQr'), icon: <QrCode className="w-4 h-4 text-amber-400" />, sub: t('scanner.tabQrSub') },
    { id: 'website', label: t('scanner.tabWebsite'), icon: <Shield className="w-4 h-4 text-emerald-400" />, sub: t('scanner.tabWebsiteSub') },
  ];

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-8">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-1">
          <Terminal className="w-3.5 h-3.5" />
          {t('scanner.badge')}
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          {t('scanner.title')}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
          {t('scanner.subtitle')}
        </p>
      </div>

      {/* Preset Test Cases Toolbar */}
      <div className="p-3.5 rounded-xl bg-[#0f172a] border border-[#1e293b] flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 font-mono font-semibold">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>{t('scanner.testScenarios')}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => fillPreset('phish_url')}
            className="px-2.5 py-1 rounded-md bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetPhishUrl')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('benign_url')}
            className="px-2.5 py-1 rounded-md bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBenignUrl')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('bank_scam_sms')}
            className="px-2.5 py-1 rounded-md bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border border-amber-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBankSms')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('lottery_scam')}
            className="px-2.5 py-1 rounded-md bg-purple-950/40 hover:bg-purple-900/60 text-purple-300 border border-purple-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetLotteryScam')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('website_safe')}
            className="px-2.5 py-1 rounded-md bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBenignDomain')}
          </button>
        </div>
      </div>

      {/* Main Scanner Card */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl shadow-xl overflow-hidden">
        {/* Modality Tabs */}
        <div className="grid grid-cols-2 md:grid-cols-4 border-b border-[#1e293b] bg-[#0b0f19]">
          {tabConfigs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => handleTabChange(tab.id as ScanType)}
                className={`py-4 px-3 text-left border-b-2 transition-colors flex flex-col justify-between ${
                  isActive
                    ? 'border-cyan-400 bg-[#0f172a]'
                    : 'border-transparent hover:bg-[#131d33]'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  {tab.icon}
                  <span className={`text-xs font-bold ${isActive ? 'text-white' : 'text-slate-400'}`}>
                    {tab.label}
                  </span>
                </div>
                <span className="text-[10px] text-slate-500 font-mono">{tab.sub}</span>
              </button>
            );
          })}
        </div>

        {/* Scanner Form Body */}
        <form onSubmit={handleScan} className="p-6 sm:p-8 space-y-6">
          {error && (
            <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-start gap-3">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">{t('scanner.validationError')} </span>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* TAB 1: URL */}
          {activeTab === 'url' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 font-mono">
                  {t('scanner.urlLabel')}
                </label>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder={t('scanner.urlPlaceholder')}
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-4 py-3.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
                />
              </div>
              <div className="p-3.5 rounded-xl bg-[#0b0f19] border border-[#1e293b] text-xs text-slate-400 flex items-start gap-2.5">
                <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                <span className="leading-relaxed">
                  {t('scanner.urlDesc')}
                </span>
              </div>
            </div>
          )}

          {/* TAB 2: Message / Email */}
          {activeTab === 'message' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                  {t('scanner.msgLabel')}
                </label>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400 font-mono">{t('scanner.msgChannel')}</span>
                  <select
                    value={contextInput}
                    onChange={(e) => setContextInput(e.target.value)}
                    className="bg-[#070a12] border border-[#1e293b] rounded-lg px-2.5 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-400"
                  >
                    <option value="sms">{t('scanner.msgChannelSms')}</option>
                    <option value="email">{t('scanner.msgChannelEmail')}</option>
                    <option value="chat">{t('scanner.msgChannelChat')}</option>
                    <option value="social">{t('scanner.msgChannelSocial')}</option>
                  </select>
                </div>
              </div>
              <textarea
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                rows={5}
                placeholder={t('scanner.msgPlaceholder')}
                className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl p-4 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-400 font-sans leading-relaxed"
              />
              <div className="p-3.5 rounded-xl bg-[#0b0f19] border border-[#1e293b] text-xs text-slate-400 flex items-start gap-2.5">
                <MessageSquare className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
                <span className="leading-relaxed">
                  {t('scanner.msgDesc')}
                </span>
              </div>
            </div>
          )}

          {/* TAB 3: QR Code */}
          {activeTab === 'qr' && (
            <div className="space-y-4">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                {t('scanner.qrLabel')}
              </label>
              <div className="border-2 border-dashed border-[#1e293b] rounded-xl p-8 text-center hover:border-amber-400/50 transition cursor-pointer bg-[#070a12] relative">
                <input
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={handleQrFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                />
                {qrPreview ? (
                  <div className="space-y-3 flex flex-col items-center">
                    <img src={qrPreview} alt="QR Preview" className="w-32 h-32 object-contain rounded-lg border border-[#1e293b] p-1.5 bg-white shadow" />
                    <div className="text-xs font-mono text-amber-400 font-bold">
                      {qrFile?.name} ({(qrFile!.size / 1024).toFixed(1)} KB)
                    </div>
                    <span className="text-[11px] text-slate-400">{t('scanner.qrReplace')}</span>
                  </div>
                ) : (
                  <div className="space-y-2 flex flex-col items-center">
                    <Upload className="w-8 h-8 text-amber-400 mb-1" />
                    <span className="text-xs sm:text-sm font-semibold text-slate-200">
                      {t('scanner.qrDropzone')}
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {t('scanner.qrLimit')}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: Website Analyzer */}
          {activeTab === 'website' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 font-mono">
                  {t('scanner.webLabel')}
                </label>
                <input
                  type="text"
                  value={websiteInput}
                  onChange={(e) => setWebsiteInput(e.target.value)}
                  placeholder={t('scanner.webPlaceholder')}
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-4 py-3.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-400 font-mono"
                />
              </div>
              <div className="p-3.5 rounded-xl bg-[#0b0f19] border border-[#1e293b] text-xs text-slate-400 flex items-start gap-2.5">
                <Shield className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <span className="leading-relaxed">
                  {t('scanner.webDesc')}
                </span>
              </div>
            </div>
          )}

          {/* Submit Action */}
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-t border-[#1e293b]">
            <div className="text-[11px] text-slate-400 font-mono">
              {loading ? (
                <span className="text-cyan-400 flex items-center gap-1.5">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>{loadingStage}</span>
                </span>
              ) : (
                <span>{t('scanner.zeroTelemetry')}</span>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto px-7 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/10 disabled:opacity-50 transition"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>{t('scanner.stageScanning') || t('scanner.btnAnalyzing')}</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>{t('scanner.btnAnalyze')}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
