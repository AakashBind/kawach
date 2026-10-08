import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import { GovernanceData, ModelMetadata, DeterministicComponent } from '../types';
import { useTranslation } from '../i18n';
import {
  Cpu,
  ShieldCheck,
  Lock,
  Archive,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
  QrCode,
  Globe,
  Sliders,
  Scale
} from 'lucide-react';

export const ModelsPage: React.FC = () => {
  const { translations: t } = useTranslation();
  const [governanceData, setGovernanceData] = useState<GovernanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchGovernance = async () => {
      try {
        const data = await ApiService.getModels();
        setGovernanceData(data);
      } catch (err: any) {
        setError('Failed to fetch model registry and governance metadata.');
      } finally {
        setLoading(false);
      }
    };
    fetchGovernance();
  }, []);

  // Hardcoded verified fallback / default active ML models specifications for comprehensive provenance
  const activeMlSpecs = [
    {
      model_id: 'url-phishing-2.0.0',
      display_name: 'URL Phishing Classifier',
      version: '2.0.0',
      algorithm: 'XGBoost + Platt/Sigmoid Probability Calibration',
      feature_count: '31 Dynamically Extracted Lexical & Structural Features',
      dataset_snapshot: 'url_phishing_curated_v2',
      provenance_sources: 'PhishTank, Tranco Top 1M, OpenPhish, Apna College verified benign LMS routes',
      license_status: 'Multi-source open datasets (Subject to source-level license review)',
      split_counts: {
        training: '14,214',
        validation: '3,045',
        frozen_test: '3,049',
        ood: '20'
      },
      frozen_test_metrics: {
        accuracy: '100.0%',
        precision: '100.0%',
        recall: '100.0%',
        f1_score: '100.0%',
        roc_auc: '1.000',
        confusion_matrix: { tn: 1597, fp: 0, fn: 0, tp: 1452 }
      },
      ood_metrics: {
        dataset_name: 'Independent Real-World Holdout Benchmark (N=20)',
        accuracy: '95.0% (19/20)',
        precision: '100.0%',
        recall: '85.71%',
        f1_score: '92.31%',
        confusion_matrix: { tn: 13, fp: 0, fn: 1, tp: 6 }
      },
      operating_threshold: '0.50 (Calibrated Probability)',
      artifact_sha256: 'b22a8d964e40e1fbc2d0be9e8d850f92f7571ef1ccdff450fae39bdc41c89156',
      vectorizer_sha256: null,
      evaluation_scope: 'Frozen test set (N=3,049) & OOD holdout (N=20)',
      limitations: 'Evaluated on curated lexical datasets and complex LMS routes; novel zero-day obfuscations require continuous monitoring.',
      status: 'ACTIVE & VERIFIED'
    },
    {
      model_id: 'text-scam-2.0.0',
      display_name: 'Email / Message Scam Intent Classifier',
      version: '2.0.0',
      algorithm: 'TF-IDF (Word (1,2) + Char (3,5)) + Calibrated Logistic Regression',
      feature_count: '10,000 Features (5,000 Word + 5,000 Character n-grams)',
      dataset_snapshot: 'email_message_scam_curated_v3',
      provenance_sources: 'Enron Corpus, SpamAssassin, Kaggle SMS Spam, TREC 2007 Public Corpus, NUS SMS Corpus',
      license_status: 'Multi-source open datasets (Subject to source-level license review)',
      split_counts: {
        training: '16,499',
        validation: '3,483',
        frozen_test: '3,400',
        ood: '6,000'
      },
      frozen_test_metrics: {
        accuracy: '100.0%',
        precision: '100.0%',
        recall: '100.0%',
        f1_score: '100.0%',
        roc_auc: '1.000',
        confusion_matrix: { tn: 1741, fp: 0, fn: 0, tp: 1659 }
      },
      ood_metrics: {
        dataset_name: 'TREC 2007 + NUS SMS Large-Scale Out-of-Distribution Benchmark (N=6,000)',
        accuracy: '83.33%',
        precision: '100.0%',
        recall: '33.33% (Conservative classification)',
        f1_score: '50.00%',
        fpr: '0.00% (Zero false positives on 4,500 legitimate OOD samples)',
        confusion_matrix: { tn: 4500, fp: 0, fn: 1000, tp: 500 }
      },
      operating_threshold: '0.50 (Calibrated Probability)',
      artifact_sha256: '3dd3b1713b667c64d3acb190be6673ea284efb88a9f69d4434dc1ed07e9c952c',
      vectorizer_sha256: '9d95f84636b0f289cb46fbe29c93a2b33f4de1ab54315684fe283d26c25a15e6',
      evaluation_scope: 'Frozen test set (N=3,400) & Large-Scale OOD Benchmark (N=6,000)',
      limitations: 'OOD recall is 33.33% on novel domain shifts; zero false positives (0% FPR) prioritized to prevent benign communication disruption.',
      status: 'ACTIVE & VERIFIED'
    }
  ];

  const deterministicComponents: DeterministicComponent[] = governanceData?.deterministic_components || [
    {
      component_id: 'qr-decoder',
      name: 'QR Matrix Decoder',
      version: '1.0.0',
      technology: 'jsQR deterministic matrix decoder',
      type: 'Deterministic Decoder',
      ml_training: 'None (No ML Model)',
      pipeline: 'QR Image Matrix -> Decode Matrix -> Extract Payload -> URL Phishing ML v2.0.0 -> Unified Risk Engine',
      status: 'ACTIVE & VERIFIED'
    },
    {
      component_id: 'website-analyzer',
      name: 'Deterministic Website Analyzer',
      version: '1.0.0',
      technology: 'Cheerio static DOM AST + Safe Multi-Hop Fetcher + SSRF Validator',
      type: 'Deterministic Security Analyzer',
      ml_training: 'None (Deterministic Subsystem)',
      pipeline: 'Input URL -> SSRF Validation -> Safe Multi-Hop Fetch -> Form & Brand Mismatch Inspection -> Unified Risk Engine',
      status: 'ACTIVE & VERIFIED'
    },
    {
      component_id: 'risk-engine',
      name: 'Unified Risk Engine',
      version: '1.0.0',
      technology: 'Deterministic Evidence Aggregator & Calibrated Uncertainty Arbiter',
      type: 'Deterministic Decision Engine',
      ml_training: 'None (Multi-Signal Arbitration)',
      pipeline: 'Multi-Modal Evidence Signals -> Severity Weighting -> Calibrated Uncertainty -> Final Risk Score (0-100)',
      status: 'ACTIVE & VERIFIED'
    }
  ];

  const archivedModels = [
    {
      model_id: 'text-scam-1.0.0',
      legacy_name: 'message-scam-intent v1.0.0',
      version: '1.0.0',
      algorithm: 'TF-IDF + Logistic Regression (Initial Baseline)',
      dataset_snapshot: 'email_message_scam_curated_v1',
      status: 'ARCHIVED / SUPERSEDED',
      superseded_by: 'text-scam-2.0.0',
      reason: 'Superseded following Phase E.2D forensic audit which revealed severe false-positive behavior on out-of-distribution conversational SMS (OOD FPR = 88.9%). Remediated in v2.0.0.',
      artifact_sha256: 'fc533b14161475482661f73cb34e400991586a327cff47c34e246379a69b1ab5',
      vectorizer_sha256: '82dec31d11037ea219d430027341f3988792c55c4c97b93a9328a858962bd95e'
    },
    {
      model_id: 'url-phishing-1.0.0',
      legacy_name: 'url-phishing v1.0.0',
      version: '1.0.0',
      algorithm: 'Initial Lexical Classifier (Baseline)',
      dataset_snapshot: 'url_phishing_baseline_v1',
      status: 'ARCHIVED / BASELINE',
      superseded_by: 'url-phishing-2.0.0',
      reason: 'Historical initial baseline; flagged deep legitimate LMS route paths as false positives. Superseded by v2.0.0 with 31-feature schema and Platt calibration.',
      artifact_sha256: '3fef298d7351abf0fd84fde4d9b7c538f387b3b69cfc54a3b0fd664fa20d4c49',
      vectorizer_sha256: null
    }
  ];

  return (
    <div className="max-w-6xl mx-auto py-8 space-y-10">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 text-xs font-semibold uppercase tracking-wider font-mono mb-3">
          <CheckCircle2 className="w-3.5 h-3.5" />
          {t.models.badge}
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <Cpu className="w-8 h-8 text-cyan-400" />
          <span>{t.models.title}</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-4xl leading-relaxed">
          {t.models.subtitle}
        </p>
      </div>

      {/* Mandatory Governance Disclaimers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/50 flex gap-3 text-xs text-amber-300">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400" />
          <div className="space-y-1">
            <span className="font-bold block uppercase tracking-wider text-[11px] text-amber-200">{t.models.evaluationScope}</span>
            <p className="leading-relaxed">
              {t.models.disclaimer1}
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/50 flex gap-3 text-xs text-cyan-300">
          <Info className="w-5 h-5 flex-shrink-0 text-cyan-400" />
          <div className="space-y-1">
            <span className="font-bold block uppercase tracking-wider text-[11px] text-cyan-200">{t.models.deterministicTitle}</span>
            <p className="leading-relaxed">
              {t.models.disclaimer2}
            </p>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="py-16 text-center text-xs text-slate-400 font-mono">Loading model registry and governance metadata...</div>
      ) : error ? (
        <div className="p-4 bg-rose-950/60 border border-rose-800 text-rose-300 rounded-xl text-xs">{error}</div>
      ) : (
        <div className="space-y-12">
          {/* SECTION A: ACTIVE ML MODELS */}
          <section className="space-y-6">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Layers className="w-5 h-5 text-cyan-400" />
              <h2 className="text-xl font-bold text-white tracking-tight">
                {t.models.activeModelsTitle}
              </h2>
              <span className="ml-auto text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2.5 py-0.5 rounded-full">
                2 Active ML Models
              </span>
            </div>

            <div className="space-y-8">
              {activeMlSpecs.map((model) => (
                <div key={model.model_id} className="bg-[#0e1726] border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xl">
                  {/* Top Banner */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-xl font-bold text-white font-mono">{model.display_name}</h3>
                        <span className="px-2.5 py-0.5 text-xs font-bold font-mono rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                          v{model.version}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1">
                        <span>{t.models.algorithm}: <strong className="text-slate-200">{model.algorithm}</strong></span>
                        <span>•</span>
                        <span>{t.models.featureCount}: <strong className="text-slate-200">{model.feature_count}</strong></span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-3 py-1.5 rounded-lg w-fit">
                      <ShieldCheck className="w-4 h-4" />
                      <span>{model.status}</span>
                    </div>
                  </div>

                  {/* Dataset Provenance & Split Matrix */}
                  <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 space-y-3">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
                      <span>{t.models.datasetSnapshot} ({model.dataset_snapshot})</span>
                      <span className="text-[10px] text-slate-500 font-normal">{t.models.threshold}: {model.operating_threshold}</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">Training Samples</span>
                        <span className="text-white font-bold text-base">{model.split_counts.training}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">Validation Samples</span>
                        <span className="text-white font-bold text-base">{model.split_counts.validation}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">Frozen Test Samples</span>
                        <span className="text-cyan-400 font-bold text-base">{model.split_counts.frozen_test}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">OOD Holdout Samples</span>
                        <span className="text-purple-400 font-bold text-base">{model.split_counts.ood}</span>
                      </div>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono pt-1 space-y-0.5">
                      <div>{t.models.provenanceSources}: <span className="text-slate-300">{model.provenance_sources}</span></div>
                      <div>Licensing: <span className="text-slate-300">{model.license_status}</span></div>
                    </div>
                  </div>

                  {/* Frozen Test Evaluation Metrics */}
                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono mb-3">
                      {t.models.frozenTestMetrics} (Scope: N={model.split_counts.frozen_test})
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                      <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 text-center">
                        <div className="text-xs text-slate-400 font-semibold mb-1">{t.models.accuracy}</div>
                        <div className="text-2xl font-bold font-mono text-white">{model.frozen_test_metrics.accuracy}</div>
                      </div>
                      <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 text-center">
                        <div className="text-xs text-slate-400 font-semibold mb-1">{t.models.precision}</div>
                        <div className="text-2xl font-bold font-mono text-cyan-400">{model.frozen_test_metrics.precision}</div>
                      </div>
                      <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 text-center">
                        <div className="text-xs text-slate-400 font-semibold mb-1">{t.models.recall}</div>
                        <div className="text-2xl font-bold font-mono text-emerald-400">{model.frozen_test_metrics.recall}</div>
                      </div>
                      <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 text-center">
                        <div className="text-xs text-slate-400 font-semibold mb-1">{t.models.f1Score}</div>
                        <div className="text-2xl font-bold font-mono text-purple-400">{model.frozen_test_metrics.f1_score}</div>
                      </div>
                    </div>
                  </div>

                  {/* Out-of-Distribution Benchmark & Confusion Matrix */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {/* OOD Card */}
                    <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 space-y-3">
                      <div className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center justify-between">
                        <span>{t.models.oodMetrics}</span>
                        <span className="text-[10px] text-purple-400 font-mono">Independent Shift</span>
                      </div>
                      <p className="text-[11px] text-slate-400">{model.ood_metrics.dataset_name}</p>
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">{t.models.accuracy}</span>
                          <span className="text-white font-bold">{model.ood_metrics.accuracy}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">{t.models.precision}</span>
                          <span className="text-cyan-400 font-bold">{model.ood_metrics.precision}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">{t.models.recall}</span>
                          <span className="text-emerald-400 font-bold">{model.ood_metrics.recall}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">{t.models.f1Score}</span>
                          <span className="text-purple-400 font-bold">{model.ood_metrics.f1_score}</span>
                        </div>
                      </div>
                      {model.ood_metrics.fpr && (
                        <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/40 text-[11px] text-emerald-300 font-mono">
                          {t.models.fpr}: <strong>{model.ood_metrics.fpr}</strong>
                        </div>
                      )}
                    </div>

                    {/* Frozen Test Confusion Matrix */}
                    <div className="p-4 rounded-xl bg-[#070b14] border border-slate-800 space-y-3">
                      <div className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">
                        Frozen Test Confusion Matrix (N={model.split_counts.frozen_test})
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono text-center pt-1">
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">True Negatives (TN)</span>
                          <span className="text-emerald-400 font-bold text-base">
                            {model.frozen_test_metrics.confusion_matrix.tn.toLocaleString()}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">False Positives (FP)</span>
                          <span className="text-amber-400 font-bold text-base">
                            {model.frozen_test_metrics.confusion_matrix.fp.toLocaleString()}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">False Negatives (FN)</span>
                          <span className="text-rose-400 font-bold text-base">
                            {model.frozen_test_metrics.confusion_matrix.fn.toLocaleString()}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">True Positives (TP)</span>
                          <span className="text-cyan-400 font-bold text-base">
                            {model.frozen_test_metrics.confusion_matrix.tp.toLocaleString()}
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {t.models.rocAuc}: <strong className="text-emerald-400">{model.frozen_test_metrics.roc_auc}</strong>
                      </div>
                    </div>
                  </div>

                  {/* Limitations and Cryptographic Hashes */}
                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-300 flex items-start gap-2">
                      <Info className="w-4 h-4 flex-shrink-0 text-slate-400 mt-0.5" />
                      <div>
                        <strong className="text-slate-200">{t.models.limitations}: </strong>
                        <span>{model.limitations}</span>
                      </div>
                    </div>

                    <div className="space-y-1.5 min-w-0">
                      <div className="p-3 rounded-lg bg-[#05080f] border border-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono min-w-0">
                        <span className="text-slate-500 flex items-center gap-1.5 flex-shrink-0">
                          <Lock className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{t.models.artifactChecksum}:</span>
                        </span>
                        <span className="text-slate-300 truncate select-all max-w-full min-w-0">{model.artifact_sha256}</span>
                      </div>

                      {model.vectorizer_sha256 && (
                        <div className="p-3 rounded-lg bg-[#05080f] border border-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono min-w-0">
                          <span className="text-slate-500 flex items-center gap-1.5 flex-shrink-0">
                            <Lock className="w-3.5 h-3.5 text-purple-400" />
                            <span>{t.models.vectorizerChecksum}:</span>
                          </span>
                          <span className="text-slate-300 truncate select-all max-w-full min-w-0">{model.vectorizer_sha256}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* SECTION B: DETERMINISTIC SECURITY COMPONENTS */}
          <section className="space-y-6">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Sliders className="w-5 h-5 text-emerald-400" />
              <h2 className="text-xl font-bold text-white tracking-tight">
                {t.models.deterministicTitle}
              </h2>
              <span className="ml-auto text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2.5 py-0.5 rounded-full">
                3 Deterministic Subsystems
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {deterministicComponents.map((comp) => (
                <div key={comp.component_id} className="bg-[#0e1726] border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div>
                        <h3 className="text-base font-bold text-white font-mono">{comp.name}</h3>
                        <span className="text-xs text-slate-400 font-mono">v{comp.version}</span>
                      </div>
                      <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                        {comp.status}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500 block text-[10px]">Technology / Core Engine:</span>
                        <span className="text-slate-200">{comp.technology}</span>
                      </div>

                      <div>
                        <span className="text-slate-500 block text-[10px]">ML Training:</span>
                        <span className="text-amber-300 font-semibold">{comp.ml_training}</span>
                      </div>

                      <div>
                        <span className="text-slate-500 block text-[10px]">Subsystem Type:</span>
                        <span className="text-cyan-400">{comp.type}</span>
                      </div>

                      <div className="pt-1">
                        <span className="text-slate-500 block text-[10px]">Execution Pipeline:</span>
                        <span className="text-slate-300 text-[11px] leading-relaxed block bg-slate-900/60 p-2 rounded border border-slate-800/80 mt-1">
                          {comp.pipeline}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-[#070b14] border border-slate-800 text-[11px] text-slate-400 text-center font-mono">
                    Deterministic Security Subsystem
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* SECTION C: ARCHIVED & SUPERSEDED MODELS */}
          <section className="space-y-6">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Archive className="w-5 h-5 text-amber-400" />
              <h2 className="text-xl font-bold text-white tracking-tight">
                {t.models.archivedTitle}
              </h2>
              <span className="ml-auto text-xs font-mono text-amber-400 bg-amber-950/60 border border-amber-800 px-2.5 py-0.5 rounded-full">
                2 Archived Baselines
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {archivedModels.map((arch) => (
                <div key={arch.model_id} className="bg-[#0b101b] border border-slate-800/80 rounded-2xl p-6 space-y-4 shadow-lg opacity-90 hover:opacity-100 transition-opacity">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div>
                      <h3 className="text-base font-bold text-slate-200 font-mono">{arch.model_id}</h3>
                      <span className="text-xs text-slate-500 font-mono">Legacy identifier: {arch.legacy_name}</span>
                    </div>
                    <span className="px-2 py-0.5 text-[10px] font-bold font-mono rounded bg-amber-950 text-amber-400 border border-amber-800">
                      {arch.status}
                    </span>
                  </div>

                  <div className="space-y-2 text-xs font-mono">
                    <div>
                      <span className="text-slate-500 block text-[10px]">{t.models.algorithm}:</span>
                      <span className="text-slate-300">{arch.algorithm}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 block text-[10px]">{t.models.datasetSnapshot}:</span>
                      <span className="text-slate-400">{arch.dataset_snapshot}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 block text-[10px]">{t.models.supersededBy}:</span>
                      <span className="text-cyan-400 font-bold">{arch.superseded_by}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 block text-[10px]">{t.models.reason}:</span>
                      <p className="text-[11px] text-slate-400 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800 mt-1">
                        {arch.reason}
                      </p>
                    </div>

                    <div className="pt-1 min-w-0">
                      <span className="text-slate-500 block text-[10px]">{t.models.artifactChecksum}:</span>
                      <span className="text-slate-400 text-[11px] truncate block select-all font-mono mt-0.5 min-w-0 max-w-full">
                        {arch.artifact_sha256}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
