import React, { useState } from 'react';
import { ApiService } from '../services/api';
import { useTranslation } from '../i18n';
import { X, Send, CheckCircle2, MessageSquare, AlertCircle, Loader2 } from 'lucide-react';

interface FeedbackModalProps {
  scanId: string;
  isOpen: boolean;
  onClose: () => void;
}

export const FeedbackModal: React.FC<FeedbackModalProps> = ({ scanId, isOpen, onClose }) => {
  const { t } = useTranslation();
  const [feedbackType, setFeedbackType] = useState<'false_positive' | 'false_negative' | 'correct'>('false_positive');
  const [comments, setComments] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await ApiService.submitFeedback({
        scan_id: scanId,
        feedback_type: feedbackType,
        user_comments: comments
      });
      setSubmitted(true);
      setTimeout(() => {
        setSubmitted(false);
        onClose();
      }, 2000);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to submit feedback.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="bg-[#0f172a] border border-[#334155] rounded-2xl max-w-md w-full p-6 shadow-2xl relative space-y-4">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-[#1e293b] transition"
          aria-label={t('common.close')}
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-amber-950/80 border border-amber-800/80 text-amber-400">
            <MessageSquare className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-mono">{t('modals.feedbackTitle')}</h3>
            <span className="text-xs text-slate-400 font-mono">{t('modals.feedbackSubtitle')} {scanId}</span>
          </div>
        </div>

        {submitted ? (
          <div className="py-8 text-center space-y-2">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
            <h4 className="text-base font-bold text-white">{t('modals.feedbackLoggedTitle')}</h4>
            <p className="text-xs text-slate-300">
              {t('modals.feedbackLoggedDesc')}
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-slate-300 leading-relaxed">
              {t('modals.feedbackLoggedDesc')}
            </p>

            {error && (
              <div className="p-3 text-xs bg-rose-950/60 border border-rose-800 rounded-lg text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-2">
              <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono">
                {t('modals.feedbackTypeLabel')}
              </label>
              <div className="space-y-2">
                <label className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition ${
                  feedbackType === 'false_positive'
                    ? 'border-cyan-500 bg-cyan-950/20'
                    : 'border-[#1e293b] bg-[#0b0f19] hover:border-slate-600'
                }`}>
                  <input
                    type="radio"
                    name="fbType"
                    checked={feedbackType === 'false_positive'}
                    onChange={() => setFeedbackType('false_positive')}
                    className="mt-1 text-cyan-500 focus:ring-0"
                  />
                  <div>
                    <div className="text-xs font-bold text-white">{t('modals.feedbackFalsePos')}</div>
                  </div>
                </label>

                <label className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition ${
                  feedbackType === 'false_negative'
                    ? 'border-cyan-500 bg-cyan-950/20'
                    : 'border-[#1e293b] bg-[#0b0f19] hover:border-slate-600'
                }`}>
                  <input
                    type="radio"
                    name="fbType"
                    checked={feedbackType === 'false_negative'}
                    onChange={() => setFeedbackType('false_negative')}
                    className="mt-1 text-cyan-500 focus:ring-0"
                  />
                  <div>
                    <div className="text-xs font-bold text-white">{t('modals.feedbackFalseNeg')}</div>
                  </div>
                </label>

                <label className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition ${
                  feedbackType === 'correct'
                    ? 'border-cyan-500 bg-cyan-950/20'
                    : 'border-[#1e293b] bg-[#0b0f19] hover:border-slate-600'
                }`}>
                  <input
                    type="radio"
                    name="fbType"
                    checked={feedbackType === 'correct'}
                    onChange={() => setFeedbackType('correct')}
                    className="mt-1 text-cyan-500 focus:ring-0"
                  />
                  <div>
                    <div className="text-xs font-bold text-white">{t('modals.feedbackCorrect')}</div>
                  </div>
                </label>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono mb-1.5">
                {t('modals.feedbackCommentsLabel')}
              </label>
              <textarea
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                rows={3}
                placeholder={t('modals.feedbackCommentsPlaceholder')}
                className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white rounded-lg hover:bg-[#1e293b] transition"
              >
                {t('common.cancel')}
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-5 py-2 text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-2 shadow transition disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>{loading ? t('modals.btnSubmittingFeedback') : t('modals.btnSubmitFeedback')}</span>
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
