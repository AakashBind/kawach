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
    const apiKey =
      process.env.GEMINI_API_KEY ||
      process.env.GOOGLE_API_KEY ||
      process.env.GEMINI_KEY ||
      CONFIG.GEMINI_API_KEY;

    if (!apiKey) {
      console.warn('[GeminiService]: No GEMINI_API_KEY set in environment.');
      return this.getLocalCybersecurityFallback(userPrompt);
    }

    try {
      // Gemini API rule: First message MUST be 'user', and roles must alternate
      const validContents: { role: 'user' | 'model'; parts: { text: string }[] }[] = [];

      for (const msg of history) {
        if (!msg || !msg.content) continue;
        const mappedRole: 'user' | 'model' = msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user';

        // Do not add 'model' as the first message
        if (validContents.length === 0 && mappedRole === 'model') {
          continue;
        }

        if (validContents.length > 0 && validContents[validContents.length - 1].role === mappedRole) {
          // Merge consecutive identical roles
          validContents[validContents.length - 1].parts[0].text += '\n' + msg.content;
        } else {
          validContents.push({ role: mappedRole, parts: [{ text: msg.content }] });
        }
      }

      // Add current user prompt
      if (validContents.length > 0 && validContents[validContents.length - 1].role === 'user') {
        validContents[validContents.length - 1].parts[0].text += '\n' + userPrompt;
      } else {
        validContents.push({ role: 'user', parts: [{ text: userPrompt }] });
      }

      // High-availability verified model sequence
      const modelsToTry = [
        'gemini-3.5-flash-lite',
        'gemini-3.8-flash',
        'gemini-flash-lite-latest',
        'gemini-3.7-flash',
        'gemini-flash-latest'
      ];
      let lastError: any = null;

      for (const model of modelsToTry) {
        try {
          const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
          const response = await axios.post(
            endpoint,
            {
              contents: validContents,
              systemInstruction: {
                parts: [{ text: CYBER_SECURITY_SYSTEM_PROMPT }]
              },
              generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 1024
              }
            },
            {
              headers: {
                'Content-Type': 'application/json',
                'X-goog-api-key': apiKey
              },
              timeout: 12000
            }
          );

          const candidate = response.data?.candidates?.[0];
          const text = candidate?.content?.parts?.[0]?.text;
          if (text) {
            return text;
          }
        } catch (err: any) {
          lastError = err;
          continue;
        }
      }

      console.warn('[GeminiService Warning]: All models fell back. Detail:', lastError?.response?.data || lastError?.message);
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

    return `🛡️ **Kawach Security Advisory**\n\nI am your Kawach AI Security Copilot. To protect yourself from scams:\n\n1. **Never share OTPs, UPI PINs, or bank passwords** with anyone claiming to be from customer care, courier delivery, or government agencies.\n2. **If money was debited without consent**, call **1930** or your bank immediately within the Golden Hour.\n3. **To verify any link or message**, use our Kawach scanner tab to run machine learning threat analysis.`;
  }
};
