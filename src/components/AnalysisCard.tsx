import { useState } from 'react';
import {
  AlertOctagon,
  CheckCircle,
  Copy,
  ExternalLink,
  PhoneCall,
  Shield,
  Check,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { AnalysisResult } from '../types.ts';
import { VerdictBadge } from './VerdictBadge.tsx';

interface AnalysisCardProps {
  analysis: AnalysisResult;
  originalText?: string;
}

export const AnalysisCard = ({ analysis, originalText }: AnalysisCardProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopyReport = () => {
    const reportText = `[UPI Safety Coach Analysis]
Verdict: ${analysis.verdict} (${analysis.riskLevel} Risk)
Type: ${analysis.scamType}

Summary: ${analysis.summary}

Explanation: ${analysis.explanation}

Warning Signs:
${analysis.warningSigns.map((w) => `• ${w}`).join('\n')}

Recommended Next Steps:
${analysis.recommendedActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}

${
  analysis.goldenRuleViolation
    ? `Fundamental Rule Violated: ${analysis.goldenRuleViolation}\n`
    : ''
}
Need Help? Call National Cyber Crime Helpline: 1930 or visit https://cybercrime.gov.in/
(Always verify with your bank directly; never share OTP or UPI PIN).`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isScamOrSuspicious =
    analysis.verdict === 'LIKELY SCAM' || analysis.verdict === 'SUSPICIOUS';

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm transition-all hover:border-slate-300">
      {/* Top Header Strip */}
      <div className="p-5 pb-4 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3 bg-slate-50/70">
        <div className="flex flex-wrap items-center gap-2.5">
          <VerdictBadge
            verdict={analysis.verdict}
            riskLevel={analysis.riskLevel}
            size="md"
          />
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-800 bg-emerald-100/70 px-2 py-0.5 rounded border border-emerald-200">
            <Shield className="w-3 h-3 text-emerald-700" />
            AI Scam Verdict
          </span>
          <span className="text-xs text-slate-500 font-mono">
            Confidence: {analysis.confidenceScore}%
          </span>
        </div>
        <button
          onClick={handleCopyReport}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-emerald-700 bg-white px-2.5 py-1.5 rounded-md border border-slate-200 hover:border-emerald-300 transition-colors"
          title="Copy this security analysis to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-600" />
              <span className="text-emerald-700">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-slate-500" />
              <span>Copy Report</span>
            </>
          )}
        </button>
      </div>

      <div className="p-6 space-y-5">
        {/* Scam Classification & Executive Summary */}
        <div>
          <div className="text-xs uppercase tracking-wider font-semibold text-slate-400 mb-1">
            Category
          </div>
          <h3 className="text-base font-semibold text-slate-900 mb-2">
            {analysis.scamType}
          </h3>
          <p className="text-sm text-slate-700 leading-relaxed bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            {analysis.summary}
          </p>
        </div>

        {/* Golden Rule Violation Callout */}
        {analysis.goldenRuleViolation && (
          <div className="p-3.5 bg-amber-50/90 rounded-lg border border-amber-200 flex items-start gap-3 text-amber-950">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="text-xs leading-relaxed">
              <strong className="font-semibold block text-amber-900 mb-0.5">
                Golden UPI Safety Principle
              </strong>
              {analysis.goldenRuleViolation}
            </div>
          </div>
        )}

        {/* Explanation Section */}
        <div>
          <h4 className="text-xs uppercase tracking-wider font-semibold text-slate-400 mb-1.5 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-slate-400" />
            Detailed Analysis
          </h4>
          <p className="text-sm text-slate-600 leading-relaxed">
            {analysis.explanation}
          </p>
        </div>

        {/* Red Flags / Warning Signs */}
        {analysis.warningSigns && analysis.warningSigns.length > 0 && (
          <div>
            <h4 className="text-xs uppercase tracking-wider font-semibold text-slate-400 mb-2 flex items-center gap-1.5">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-500" />
              {isScamOrSuspicious ? 'Identified Red Flags & Risk Indicators' : 'Authenticity Markers'}
            </h4>
            <div className="space-y-1.5">
              {analysis.warningSigns.map((sign, index) => (
                <div
                  key={index}
                  className="flex items-start gap-2.5 text-xs text-slate-700 bg-slate-50 p-2.5 rounded-md border border-slate-100"
                >
                  <span className="text-rose-500 font-bold shrink-0 mt-0.5">
                    {isScamOrSuspicious ? '✕' : '✓'}
                  </span>
                  <span className="leading-relaxed">{sign}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Actions */}
        {analysis.recommendedActions && analysis.recommendedActions.length > 0 && (
          <div>
            <h4 className="text-xs uppercase tracking-wider font-semibold text-emerald-800 mb-2 flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
              Recommended Immediate Actions
            </h4>
            <ul className="space-y-2">
              {analysis.recommendedActions.map((action, index) => (
                <li
                  key={index}
                  className="flex items-start gap-3 text-xs text-slate-800 bg-emerald-50/50 p-2.5 rounded-lg border border-emerald-100/80"
                >
                  <span className="flex items-center justify-center w-4 h-4 rounded-full bg-emerald-600 text-white font-mono text-[10px] font-bold shrink-0 mt-0.5">
                    {index + 1}
                  </span>
                  <span className="leading-relaxed">{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Cybercrime Helpline Information Callout */}
        <div className="mt-5 p-4 rounded-xl bg-gradient-to-r from-emerald-900 to-slate-900 text-white">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-semibold uppercase tracking-wider">
                <Shield className="w-3.5 h-3.5" />
                Indian Cybercrime Assistance
              </div>
              <p className="text-xs text-slate-200">
                If money was deducted or you are being harassed, act within the{' '}
                <strong className="text-white font-semibold">Golden Hours</strong> to stop fund withdrawal.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <a
                href="tel:1930"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition-colors"
              >
                <PhoneCall className="w-3.5 h-3.5" />
                Call 1930
              </a>
              <a
                href="https://cybercrime.gov.in/"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white font-medium text-xs transition-colors"
              >
                cybercrime.gov.in
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Safety Disclaimer */}
        <div className="pt-2 text-[11px] text-slate-400 leading-normal border-t border-slate-100">
          <strong>Security Note:</strong> This assessment is generated by automated linguistic, structural, and behavioral threat analysis. Fraud techniques evolve constantly; never treat any communication as 100% guaranteed safe. Always verify transactions directly via your official banking app.
        </div>
      </div>
    </div>
  );
};
