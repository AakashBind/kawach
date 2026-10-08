import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { AuthService } from '../services/auth';
import { useTranslation } from '../i18n';
import { LanguageSelector } from './LanguageSelector';
import { Logo } from './Logo';
import { Shield, Scan, History, FileText, Cpu, BookOpen, User as UserIcon, LogOut, Menu, X, Bot } from 'lucide-react';

interface NavbarProps {
  onLogout?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onLogout }) => {
  const { t } = useTranslation();
  const location = useLocation();
  const user = AuthService.getUser();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { to: '/', label: t('nav.overview'), icon: <Shield className="w-4 h-4" /> },
    { to: '/scanner', label: t('nav.scanner'), icon: <Scan className="w-4 h-4" /> },
    { to: '/assistant', label: 'AI Copilot', icon: <Bot className="w-4 h-4 text-cyan-400" /> },
    ...(user ? [
      { to: '/history', label: t('nav.history'), icon: <History className="w-4 h-4" /> },
      { to: '/reports', label: t('nav.reports'), icon: <FileText className="w-4 h-4" /> },
    ] : []),
    { to: '/models', label: t('nav.models'), icon: <Cpu className="w-4 h-4" /> },
    { to: '/education', label: t('nav.education'), icon: <BookOpen className="w-4 h-4" /> },
  ];

  return (
    <header className="sticky top-0 z-40 bg-[#0b0f19]/95 backdrop-blur-md border-b border-[#1e293b]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-2">
        {/* Scam Shield Official Logo */}
        <Link to="/" className="flex items-center group flex-shrink-0" title="Scam Shield">
          <Logo size="md" className="transition-transform group-hover:scale-[1.02]" />
        </Link>

        {/* Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1">
          {navLinks.map((item) => {
            const active = location.pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                  active
                    ? 'bg-[#1e293b] text-cyan-400 border border-[#334155]'
                    : 'text-slate-300 hover:text-white hover:bg-[#131d33]'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Language Selector, Auth status & Mobile Toggle */}
        <div className="flex items-center gap-2.5">
          {/* Language Selector */}
          <LanguageSelector />

          {user ? (
            <div className="flex items-center gap-2">
              <Link
                to="/account"
                className="flex items-center gap-2 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg bg-[#0f172a] border border-[#1e293b] hover:border-slate-600 transition"
              >
                <div className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-400 font-bold text-[10px] font-mono">
                  {user.email.charAt(0).toUpperCase()}
                </div>
                <span className="font-mono max-w-[110px] truncate text-[11px]">{user.email}</span>
              </Link>
              <button
                onClick={onLogout}
                className="p-1.5 text-slate-400 hover:text-rose-400 rounded-lg hover:bg-[#1e293b] transition"
                title={t('nav.signOut')}
                aria-label={t('nav.signOut')}
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Link
                to="/login"
                className="px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white rounded-lg hover:bg-[#1e293b] transition"
              >
                {t('nav.signIn')}
              </Link>
              <Link
                to="/register"
                className="px-3 py-1.5 text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg shadow-sm transition hidden sm:inline-block"
              >
                {t('nav.createAccount')}
              </Link>
            </div>
          )}

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 text-slate-400 hover:text-white lg:hidden rounded-lg hover:bg-[#1e293b]"
            aria-label={t('nav.toggleMenu')}
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-t border-[#1e293b] bg-[#0b0f19] px-4 py-3 space-y-1 animate-in fade-in slide-in-from-top-2 duration-200">
          {navLinks.map((item) => {
            const active = location.pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setMobileMenuOpen(false)}
                className={`px-3 py-2.5 rounded-lg text-xs font-semibold flex items-center gap-2.5 transition ${
                  active
                    ? 'bg-[#1e293b] text-cyan-400 border border-[#334155]'
                    : 'text-slate-300 hover:text-white hover:bg-[#131d33]'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            );
          })}

          <div className="pt-2 mt-2 border-t border-[#1e293b] flex flex-col gap-2">
            {user ? (
              <div className="flex items-center justify-between p-2 rounded-lg bg-[#0f172a] border border-[#1e293b]">
                <Link
                  to="/account"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex items-center gap-2 text-xs text-slate-200"
                >
                  <UserIcon className="w-4 h-4 text-cyan-400" />
                  <span className="font-mono text-xs truncate max-w-[180px]">{user.email}</span>
                </Link>
                <button
                  onClick={() => {
                    setMobileMenuOpen(false);
                    if (onLogout) onLogout();
                  }}
                  className="text-xs text-rose-400 hover:text-rose-300 font-semibold flex items-center gap-1 p-1"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>{t('nav.signOut')}</span>
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-2 pt-1">
                <Link
                  to="/login"
                  onClick={() => setMobileMenuOpen(false)}
                  className="px-3 py-2 text-center text-xs font-semibold text-slate-200 bg-[#0f172a] border border-[#1e293b] rounded-lg hover:bg-[#131d33]"
                >
                  {t('nav.signIn')}
                </Link>
                <Link
                  to="/register"
                  onClick={() => setMobileMenuOpen(false)}
                  className="px-3 py-2 text-center text-xs font-bold text-white bg-cyan-600 rounded-lg hover:bg-cyan-500 shadow-sm"
                >
                  {t('nav.createAccount')}
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </header>
  );
};
