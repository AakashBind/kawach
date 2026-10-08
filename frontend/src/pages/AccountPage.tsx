import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthService } from '../services/auth';
import { ApiService } from '../services/api';
import { User } from '../types';
import { useTranslation } from '../i18n';
import { LanguageSelector } from '../components/LanguageSelector';
import { User as UserIcon, Lock, Trash2, CheckCircle2, Globe } from 'lucide-react';

export const AccountPage: React.FC<{ onLogout?: () => void }> = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [user] = useState<User | null>(AuthService.getUser());
  const [loading, setLoading] = useState(false);
  const [cleared, setCleared] = useState(false);

  useEffect(() => {
    if (!AuthService.isAuthenticated()) {
      navigate('/login');
    }
  }, [navigate]);

  const handleClearHistory = async () => {
    if (!confirm(t('account.purgeConfirm'))) return;
    setLoading(true);
    try {
      await ApiService.clearAllScans();
      setCleared(true);
      setTimeout(() => setCleared(false), 3000);
    } catch {
      alert('Failed to clear scans.');
    } finally {
      setLoading(false);
    }
  };

  if (!user) return null;

  return (
    <div className="max-w-3xl mx-auto py-8 space-y-6">
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 text-xs font-mono font-semibold uppercase tracking-wider mb-2">
          <UserIcon className="w-3.5 h-3.5" />
          {t('account.badge')}
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          {t('account.title')}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          {t('account.subtitle')}
        </p>
      </div>

      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
        <div className="flex items-center gap-4 border-b border-[#1e293b] pb-6">
          <div className="w-14 h-14 rounded-2xl bg-[#0b0f19] border border-cyan-700/50 flex items-center justify-center text-cyan-400 font-bold text-xl font-mono shadow-inner">
            {user.email.charAt(0).toUpperCase()}
          </div>
          <div className="space-y-0.5">
            <div className="text-base font-bold text-white font-mono">{user.email}</div>
            <div className="text-xs text-slate-400 font-mono">
              {t('account.userId')} <span className="text-slate-300">{user.id}</span> • {t('account.role')} <span className="text-cyan-400 font-bold uppercase">{user.role}</span>
            </div>
          </div>
        </div>

        {/* Language Preferences */}
        <div className="space-y-3 border-b border-[#1e293b] pb-6">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              {t('account.languageTitle')}
            </h3>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed font-normal">
            {t('account.languageDesc')}
          </p>
          <div className="pt-1">
            <LanguageSelector />
          </div>
        </div>

        {/* Privacy & Retention Controls */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              {t('account.privacyTitle')}
            </h3>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed font-normal">
            {t('account.privacyDesc')}
          </p>

          {cleared && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs rounded-xl flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>{t('account.purgedSuccess')}</span>
            </div>
          )}

          <div className="pt-2">
            <button
              onClick={handleClearHistory}
              disabled={loading}
              className="px-4 py-2 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/40 text-xs font-semibold text-rose-300 rounded-xl flex items-center gap-2 transition disabled:opacity-50"
            >
              <Trash2 className="w-4 h-4" />
              <span>{loading ? t('account.btnPurging') : t('account.btnPurge')}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
