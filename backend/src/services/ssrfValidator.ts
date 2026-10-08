import dns from 'dns/promises';
import { URL } from 'url';

export interface SSRFValidationResult {
  allowed: boolean;
  reason?: string;
  resolvedIps?: string[];
  primaryIp?: string;
  parsedUrl?: URL;
  canonicalUrl?: string;
}

// Blocked Hostnames (exact or suffix match)
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'instance-data',
  'metadata.google.internal',
  'metadata.local',
  '169.254.169.254'
]);

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']); // Standard web ports

/**
 * Checks if an IPv4 address falls within private, loopback, link-local, or reserved ranges.
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private RFC 1918)
  if (a === 10) return true;

  // 100.64.0.0/10 (Shared Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-local & Cloud metadata e.g. 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private RFC 1918: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.88.99.0/24 (6to4 Relay Anycast)
  if (a === 192 && b === 88 && c === 99) return true;

  // 192.168.0.0/16 (Private RFC 1918)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Network Interconnect Device Benchmark)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast 224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved for future use 240.0.0.0 - 255.255.255.254)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks if an IPv6 address falls within private, loopback, link-local, or unique local ranges.
 */
export function isPrivateIPv6(ip: string): boolean {
  const clean = ip.toLowerCase().trim();

  // ::1 / :: (Loopback & Unspecified)
  if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:1' || clean === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:192.168.1.1 or ::ffff:7f00:1)
  if (clean.startsWith('::ffff:') || clean.startsWith('0:0:0:0:0:ffff:')) {
    const mappedPart = clean.replace(/^.*:ffff:/, '');
    if (mappedPart.includes('.')) {
      return isPrivateIPv4(mappedPart);
    }
  }

  // fe80::/10 (Link-local)
  if (clean.startsWith('fe80:') || clean.startsWith('fe8') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) {
    return true;
  }

  // fc00::/7 (Unique Local Address fc00:: - fdff::)
  if (clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }

  // ff00::/8 (Multicast)
  if (clean.startsWith('ff')) {
    return true;
  }

  return false;
}

/**
 * Decodes potential integer, octal, or hex IPv4 notation.
 */
export function normalizeIpString(str: string): string | null {
  const trimmed = str.trim();

  // Pure integer decimal IP representation e.g. 2130706433 = 127.0.0.1
  if (/^\d+$/.test(trimmed)) {
    const intVal = parseInt(trimmed, 10);
    if (intVal >= 0 && intVal <= 4294967295) {
      const a = (intVal >>> 24) & 255;
      const b = (intVal >>> 16) & 255;
      const c = (intVal >>> 8) & 255;
      const d = intVal & 255;
      return `${a}.${b}.${c}.${d}`;
    }
  }

  // Hexadecimal notation e.g. 0x7f000001
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) {
    const intVal = parseInt(trimmed, 16);
    if (intVal >= 0 && intVal <= 4294967295) {
      const a = (intVal >>> 24) & 255;
      const b = (intVal >>> 16) & 255;
      const c = (intVal >>> 8) & 255;
      const d = intVal & 255;
      return `${a}.${b}.${c}.${d}`;
    }
  }

  return null;
}

/**
 * Validates any target URL before fetching to prevent SSRF and internal network exposure.
 */
export async function validateUrlForSSRF(rawUrl: string): Promise<SSRFValidationResult> {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { allowed: false, reason: 'URL must be a non-empty string.' };
  }

  let parsed: URL;
  try {
    const urlString = rawUrl.includes('://') ? rawUrl : `http://${rawUrl}`;
    parsed = new URL(urlString);
  } catch {
    return { allowed: false, reason: 'Invalid or malformed URL syntax.' };
  }

  // 1. Protocol Restriction: strictly http: or https:
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return {
      allowed: false,
      reason: `Forbidden scheme '${parsed.protocol}'. Only standard HTTP and HTTPS protocols are permitted.`
    };
  }

  // 2. Port Restriction
  if (parsed.port && !ALLOWED_PORTS.has(parsed.port)) {
    return {
      allowed: false,
      reason: `Forbidden port '${parsed.port}'. Scans are restricted to standard web ports (80, 443).`
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { allowed: false, reason: 'Hostname is missing or empty.' };
  }

  // 3. Blocked Hostnames & Internal Suffixes
  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.home') ||
    hostname.endsWith('.corp')
  ) {
    return {
      allowed: false,
      reason: `Destination hostname '${hostname}' belongs to a reserved internal network zone.`
    };
  }

  // 4. Encoded / Alternate IP representations in Hostname
  const normalizedDecimalIp = normalizeIpString(hostname);
  if (normalizedDecimalIp) {
    if (isPrivateIPv4(normalizedDecimalIp)) {
      return {
        allowed: false,
        reason: `Encoded IP address (${hostname} -> ${normalizedDecimalIp}) resolves to a restricted private/loopback network.`
      };
    }
  }

  // Direct IPv4 validation
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(hostname)) {
    if (isPrivateIPv4(hostname)) {
      return {
        allowed: false,
        reason: `Direct IPv4 address '${hostname}' is inside a private, loopback, or link-local subnet.`
      };
    }
    return {
      allowed: true,
      resolvedIps: [hostname],
      primaryIp: hostname,
      parsedUrl: parsed,
      canonicalUrl: parsed.toString()
    };
  }

  // Direct IPv6 validation
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    const rawIpv6 = hostname.slice(1, -1);
    if (isPrivateIPv6(rawIpv6)) {
      return {
        allowed: false,
        reason: `Direct IPv6 address '${rawIpv6}' belongs to a local, loopback, or private subnet.`
      };
    }
  }

  // 5. Pre-connection DNS Resolution with Rebinding Protection
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return { allowed: false, reason: `DNS resolution failed: no IP address returned for '${hostname}'.` };
    }

    const resolvedIps: string[] = [];
    for (const record of addresses) {
      const ip = record.address;
      resolvedIps.push(ip);

      if (record.family === 4 || ip.includes('.')) {
        if (isPrivateIPv4(ip)) {
          return {
            allowed: false,
            reason: `Hostname '${hostname}' resolves to private/reserved IPv4 address (${ip}).`
          };
        }
      } else if (record.family === 6 || ip.includes(':')) {
        if (isPrivateIPv6(ip)) {
          return {
            allowed: false,
            reason: `Hostname '${hostname}' resolves to private/loopback IPv6 address (${ip}).`
          };
        }
      }
    }

    return {
      allowed: true,
      resolvedIps,
      primaryIp: resolvedIps[0],
      parsedUrl: parsed,
      canonicalUrl: parsed.toString()
    };
  } catch (err: any) {
    return {
      allowed: false,
      reason: `DNS lookup failed for hostname '${hostname}': ${err.message}`
    };
  }
}
