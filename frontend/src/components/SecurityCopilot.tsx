import React, { useState, useRef, useEffect } from 'react';
import { Send, ShieldAlert, Bot, User, Sparkles, X, Minimize2, Maximize2, AlertTriangle, PhoneCall } from 'lucide-react';
import { ApiService } from '../services/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  time: string;
}

const QUICK_PROMPTS = [
  '🚨 I gave an OTP & money was debited!',
  '📞 How do I report fraud to 1930 / cybercrime.gov.in?',
  '📲 I downloaded a suspicious APK app',
  '💳 How do I freeze my bank account & UPI?',
  '🔗 How do I know if a courier SMS link is fake?'
];

export const SecurityCopilot: React.FC<{ defaultOpen?: boolean; isPageMode?: boolean }> = ({
  defaultOpen = false,
  isPageMode = false
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen || isPageMode);
  const [isMinimized, setIsMinimized] = useState(false);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `🛡️ **Hello, I am your Kawach AI Security Copilot.**\n\nI provide instant incident response guidance for online scams, financial fraud, phishing links, and compromised accounts.\n\n*If you are facing an ongoing cyber crime, you can ask for immediate steps or report to authorities below:*`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen && !isMinimized) {
      scrollToBottom();
    }
  }, [messages, isOpen, isMinimized]);

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || input).trim();
    if (!text || loading) return;

    const userMsg: Message = {
      role: 'user',
      content: text,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInput('');
    setLoading(true);

    try {
      const history = messages.slice(-6).map((m) => ({
        role: m.role,
        content: m.content
      }));

      const reply = await ApiService.askAssistant(text, history);

      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: reply,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ **Security Connection Advisory**\n\nUnable to reach AI intelligence node. If you suffered a financial loss, call **1930** immediately or report to **cybercrime.gov.in** and inform your bank right away.`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Render markdown bold and line breaks safely
  const formatContent = (content: string) => {
    const lines = content.split('\n');
    return lines.map((line, idx) => {
      // Bold replacement
      const parts = line.split(/(\*\*.*?\*\*)/g);
      return (
        <div key={idx} className={line.trim() === '' ? 'h-2' : 'min-h-[1.25rem]'}>
          {parts.map((part, pIdx) => {
            if (part.startsWith('**') && part.endsWith('**')) {
              return (
                <strong key={pIdx} className="font-semibold text-cyan-300">
                  {part.slice(2, -2)}
                </strong>
              );
            }
            return part;
          })}
        </div>
      );
    });
  };

  if (!isOpen && !isPageMode) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-full shadow-2xl shadow-cyan-500/30 border border-cyan-400/40 transition-all transform hover:scale-105 active:scale-95 group"
      >
        <div className="relative">
          <Sparkles className="w-5 h-5 text-cyan-200 animate-pulse" />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-slate-900"></span>
        </div>
        <span className="font-medium text-sm tracking-wide">Security Copilot</span>
      </button>
    );
  }

  return (
    <div
      className={
        isPageMode
          ? 'w-full max-w-4xl mx-auto rounded-2xl bg-slate-900/90 border border-cyan-500/30 backdrop-blur-xl shadow-2xl flex flex-col h-[750px] overflow-hidden'
          : `fixed bottom-6 right-6 z-50 w-[95vw] sm:w-[460px] ${
              isMinimized ? 'h-16' : 'h-[620px]'
            } rounded-2xl bg-slate-900/95 border border-cyan-500/40 backdrop-blur-2xl shadow-2xl shadow-cyan-950/80 flex flex-col transition-all duration-200 overflow-hidden`
      }
    >
      {/* Header */}
      <div className="px-4 py-3.5 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-b border-cyan-500/20 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 relative">
            <ShieldAlert className="w-5 h-5" />
            <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full border border-slate-900"></span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm text-slate-100">Kawach Copilot</span>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Security Advisor
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Emergency Incident & Scam Guidance</p>
          </div>
        </div>

        {!isPageMode && (
          <div className="flex items-center gap-1.5 text-slate-400">
            <button
              onClick={() => setIsMinimized(!isMinimized)}
              className="p-1 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
              title={isMinimized ? 'Expand' : 'Minimize'}
            >
              {isMinimized ? <Maximize2 className="w-4 h-4" /> : <Minimize2 className="w-4 h-4" />}
            </button>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition"
              title="Close"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {!isMinimized && (
        <>
          {/* Quick Helpline Alert Bar */}
          <div className="bg-amber-500/10 border-b border-amber-500/20 px-3.5 py-2 flex items-center justify-between text-xs text-amber-300">
            <span className="flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              National Cyber Helpline:
            </span>
            <a
              href="tel:1930"
              className="flex items-center gap-1 font-bold text-amber-200 hover:text-white bg-amber-500/20 px-2 py-0.5 rounded transition"
            >
              <PhoneCall className="w-3 h-3" /> Dial 1930
            </a>
          </div>

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs sm:text-sm">
            {messages.map((msg, index) => (
              <div
                key={index}
                className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 flex-shrink-0 mt-0.5">
                    <Bot className="w-4 h-4" />
                  </div>
                )}
                <div
                  className={`max-w-[85%] rounded-2xl px-4 py-3 leading-relaxed shadow-md ${
                    msg.role === 'user'
                      ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-br-xs'
                      : 'bg-slate-800/90 text-slate-200 border border-slate-700/80 rounded-bl-xs'
                  }`}
                >
                  <div>{formatContent(msg.content)}</div>
                  <div
                    className={`text-[10px] mt-1.5 ${
                      msg.role === 'user' ? 'text-cyan-200 text-right' : 'text-slate-400'
                    }`}
                  >
                    {msg.time}
                  </div>
                </div>
                {msg.role === 'user' && (
                  <div className="w-7 h-7 rounded-lg bg-blue-900 border border-blue-500/30 flex items-center justify-center text-blue-200 flex-shrink-0 mt-0.5">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {loading && (
              <div className="flex gap-3 items-center text-cyan-400 text-xs py-2">
                <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center animate-spin">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div className="flex items-center gap-1.5 text-slate-400">
                  <span>Analyzing cyber intelligence</span>
                  <span className="animate-bounce">.</span>
                  <span className="animate-bounce delay-100">.</span>
                  <span className="animate-bounce delay-200">.</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Carousel */}
          <div className="px-3 pb-2 pt-1 border-t border-slate-800/80 bg-slate-900/60 flex items-center gap-2 overflow-x-auto no-scrollbar">
            {QUICK_PROMPTS.map((prompt, i) => (
              <button
                key={i}
                onClick={() => handleSend(prompt)}
                disabled={loading}
                className="whitespace-nowrap px-2.5 py-1 text-[11px] rounded-full bg-slate-800/80 hover:bg-cyan-950 hover:text-cyan-300 hover:border-cyan-500/40 border border-slate-700/60 text-slate-300 transition flex-shrink-0"
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 bg-slate-950/80 border-t border-cyan-500/20 flex items-center gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about a scam, OTP leak, or how to report..."
              disabled={loading}
              className="flex-1 bg-slate-900/90 border border-slate-700/80 focus:border-cyan-400 text-slate-100 rounded-xl px-3.5 py-2.5 text-xs sm:text-sm placeholder-slate-500 outline-none transition"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="p-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold transition flex items-center justify-center shadow-lg shadow-cyan-500/20"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </>
      )}
    </div>
  );
};
