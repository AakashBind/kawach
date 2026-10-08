import axios from 'axios';
import { CONFIG } from '../config.js';

const CYBER_SECURITY_SYSTEM_PROMPT = `You are "Kawach AI Security Copilot", an elite cybersecurity emergency responder and anti-scam intelligence advisor.
Your primary mission is to protect everyday users against online fraud, phishing, financial scams, identity theft, and cyber threats.

Key directives:
1. Incident Response: If a user shares that they lost money, entered OTP, downloaded a suspicious APK, or clicked a link, immediately provide urgent actionable steps:
   - For Financial/UPI fraud in India: Call national cyber helpline 1930 immediately within the "Golden Hour" and report on cybercrime.gov.in. Call bank to freeze account/cards.
   - For OTP/Credential leaks: Change passwords immediately, enable 2FA with an authenticator app, revoke active sessions.
   - For Malicious APKs/Apps: Turn off Wi-Fi/mobile data immediately, boot into safe mode, uninstall the suspicious app, and scan device.
2. Authority Reporting: Clearly explain how to file a formal complaint with appropriate cyber crime cells and legal authorities.
3. Tone: Calm, empathetic, highly actionable, authoritative, and concise. Avoid dense technical jargon unless explaining it simply.
4. Format: Use clear bullet points and bold highlights for critical emergency actions.`;

export interface ChatMessage {
  role: 'user' | 'assistant' | 'model';
  content: string;
}

export const GeminiService = {
  async askSecurityCopilot(userPrompt: string, history: ChatMessage[] = []): Promise<string> {
    const apiKey = CONFIG.GEMINI_API_KEY;

    if (!apiKey) {
      return this.getLocalCybersecurityFallback(userPrompt);
    }

    try {
      // Map history to Gemini API contents format
      const contents = history.map((msg) => ({
        role: msg.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: msg.content }]
      }));

      contents.push({
        role: 'user',
        parts: [{ text: userPrompt }]
      });

      // Support Gemini 2.0 / 1.5 flash free tier
      const modelsToTry = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-flash-8b'];
      let lastError: any = null;

      for (const model of modelsToTry) {
        try {
          const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
          const response = await axios.post(
            endpoint,
            {
              contents,
              systemInstruction: {
                parts: [{ text: CYBER_SECURITY_SYSTEM_PROMPT }]
              },
              generationConfig: {
                temperature: 0.4,
                maxOutputTokens: 1000
              }
            },
            {
              headers: { 'Content-Type': 'application/json' },
              timeout: 15000
            }
          );

          const candidate = response.data?.candidates?.[0];
          const text = candidate?.content?.parts?.[0]?.text;
          if (text) {
            return text;
          }
        } catch (err: any) {
          lastError = err;
          // If model not found or rate limit, try next model
          continue;
        }
      }

      console.warn('[GeminiService API Notice]:', lastError?.response?.data || lastError?.message);
      return this.getLocalCybersecurityFallback(userPrompt);
    } catch (err: any) {
      console.error('[GeminiService Exception]:', err.message);
      return this.getLocalCybersecurityFallback(userPrompt);
    }
  },

  getLocalCybersecurityFallback(query: string): string {
    const q = query.toLowerCase();

    if (q.includes('otp') || q.includes('shared otp') || q.includes('gave otp')) {
      return `⚠️ **CRITICAL EMERGENCY ACTION (OTP COMPROMISE)**\n\n1. **Call Your Bank Immediately**: Ask them to freeze your net banking, UPI, and debit cards right away.\n2. **Dial 1930 (Cyber Helpline)**: If in India, report the incident immediately on the National Cyber Crime Reporting Portal (**cybercrime.gov.in**).\n3. **Change All Passwords**: Change credentials for your email, bank app, and social accounts immediately.\n4. **Revoke Active Device Sessions**: Log out of all active web and mobile sessions.`;
    }

    if (q.includes('report') || q.includes('authority') || q.includes('police') || q.includes('1930') || q.includes('complaint')) {
      return `🛡️ **HOW TO REPORT CYBER FRAUD TO AUTHORITIES**\n\n- **National Cyber Crime Helpline (India)**: Dial **1930** immediately.\n- **Official Reporting Portal**: Visit **https://cybercrime.gov.in** and click *Report Cyber Crime*.\n- **Keep Evidence Ready**: Save transaction IDs (UTR/RRN), screenshots of scam messages, caller phone numbers, and phishing URLs.\n- **Local Cyber Cell**: You can also file a written complaint at your nearest Police Station / Cyber Crime Police Station with the acknowledgment from cybercrime.gov.in.`;
    }

    if (q.includes('apk') || q.includes('app') || q.includes('download')) {
      return `🚨 **EMERGENCY RESPONSE FOR MALICIOUS APKS**\n\n1. **Turn Off Network**: Put your phone on Airplane Mode and disconnect from Wi-Fi immediately.\n2. **Boot Into Safe Mode**: Restart your Android phone into Safe Mode (this stops third-party apps from running).\n3. **Remove Device Admin Privileges**: Go to *Settings > Security > Device Administrators* and deactivate the suspicious app.\n4. **Uninstall the App**: Uninstall the suspicious APK from *Settings > Apps*.\n5. **Check Bank Accounts**: From a separate safe device, check your bank transactions and freeze UPI if necessary.`;
    }

    return `🛡️ **Kawach Security Advisory**\n\nI am your Kawach AI Security Copilot. To protect yourself from scams:\n\n1. **Never share OTPs, UPI PINs, or bank passwords** with anyone claiming to be from customer care, courier delivery, or government agencies.\n2. **If money was debited without consent**, call **1930** or your bank immediately within the Golden Hour.\n3. **To verify any link or message**, use our Kawach scanner tab to run machine learning threat analysis.\n\n*(Note: Add your GEMINI_API_KEY in Railway Variables for full generative real-time intelligence).*`;
  }
};
