import React, { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { LanguageProvider } from './i18n';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { CyberBackground } from './components/CyberBackground';
import { HomePage } from './pages/HomePage';
import { ScannerPage } from './pages/ScannerPage';
import { HistoryPage } from './pages/HistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { ModelsPage } from './pages/ModelsPage';
import { EducationPage } from './pages/EducationPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { AccountPage } from './pages/AccountPage';
import { AssistantPage } from './pages/AssistantPage';
import { SecurityCopilot } from './components/SecurityCopilot';
import { AuthService } from './services/auth';

export const App: React.FC = () => {
  const [, setAuthTick] = useState(0);

  const handleAuthChange = () => {
    setAuthTick((t) => t + 1);
  };

  const handleLogout = () => {
    AuthService.logout();
    handleAuthChange();
  };

  return (
    <LanguageProvider>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col bg-transparent text-slate-100 selection:bg-cyan-500 selection:text-white relative">
          <CyberBackground />
          <div className="relative z-10 flex flex-col min-h-screen">
            <Navbar onLogout={handleLogout} />
            <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-4">
              <Routes>
                <Route path="/" element={<HomePage />} />
                <Route path="/scanner" element={<ScannerPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/models" element={<ModelsPage />} />
                <Route path="/education" element={<EducationPage />} />
                <Route path="/login" element={<LoginPage onLoginSuccess={handleAuthChange} />} />
                <Route path="/register" element={<RegisterPage onRegisterSuccess={handleAuthChange} />} />
                <Route path="/account" element={<AccountPage onLogout={handleLogout} />} />
                <Route path="/assistant" element={<AssistantPage />} />
              </Routes>
            </main>
            <Footer />
            <SecurityCopilot />
          </div>
        </div>
      </BrowserRouter>
    </LanguageProvider>
  );
};

