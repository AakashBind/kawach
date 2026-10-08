import React, { useState, useRef, useEffect } from 'react';
import { useLanguage, SUPPORTED_LANGUAGES } from '../i18n';
import { Globe, ChevronDown, Check } from 'lucide-react';
import { Language } from '../i18n/types';

interface LanguageSelectorProps {
  variant?: 'nav' | 'compact' | 'dropdown';
  className?: string;
}

export const LanguageSelector: React.FC<LanguageSelectorProps> = ({ variant = 'nav', className = '' }) => {
  const { language, setLanguage } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentLang = SUPPORTED_LANGUAGES.find((l) => l.code === language) || SUPPORTED_LANGUAGES[0];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelect = (code: Language) => {
    setLanguage(code);
    setIsOpen(false);
  };

  return (
    <div className={`relative inline-block text-left ${className}`} ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#0f172a] border border-[#1e293b] hover:border-slate-600 text-xs font-semibold text-slate-200 hover:text-white transition focus-visible:outline-cyan-400"
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label={`Select Language (Current: ${currentLang.nativeName})`}
      >
        <Globe className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
        <span className="font-sans font-medium">{currentLang.nativeName}</span>
        <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div
          className="absolute right-0 mt-1.5 w-36 rounded-xl bg-[#0b0f19] border border-[#1e293b] shadow-2xl z-50 py-1 overflow-hidden backdrop-blur-md"
          role="menu"
          aria-orientation="vertical"
        >
          {SUPPORTED_LANGUAGES.map((lang) => {
            const isSelected = lang.code === language;
            return (
              <button
                key={lang.code}
                onClick={() => handleSelect(lang.code)}
                className={`w-full px-3 py-2 text-xs flex items-center justify-between text-left transition ${
                  isSelected
                    ? 'bg-cyan-950/60 text-cyan-300 font-bold'
                    : 'text-slate-300 hover:text-white hover:bg-[#131d33]'
                }`}
                role="menuitem"
              >
                <div className="flex flex-col">
                  <span className="font-medium">{lang.nativeName}</span>
                  <span className="text-[10px] text-slate-500 font-mono">{lang.name}</span>
                </div>
                {isSelected && <Check className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};
