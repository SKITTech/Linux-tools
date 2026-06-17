import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Rate limiting config: max requests per window per IP
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MINUTES = 1;

interface PortCheckRequest {
  host: string;
  port: number;
  timeout?: number;
}

interface PortCheckResponse {
  host: string;
  port: number;
  status: 'open' | 'closed' | 'timeout' | 'error';
  responseTime?: number;
  service?: string;
  error?: string;
  ipVersion?: 'IPv4' | 'IPv6';
}

// Common service names for ports
const serviceNames: { [key: number]: string } = {
  20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "SMTP (Submission)", 993: "IMAPS", 995: "POP3S",
  3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
};

// --- SSRF Protection ---

function isPrivateIPv4(host: string): boolean {
  const octets = host.split('.').map(Number);
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 127) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  if (octets.every(o => o === 0)) return true;
  return false;
}

function isBlockedHostname(host: string): boolean {
  const blocked = ['localhost', 'ip6-localhost', 'ip6-loopback'];
  return blocked.includes(host.toLowerCase());
}

function isPrivateIPv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h === '::1' || h === '::') return true;
  if (h.startsWith('fe80:') || h.startsWith('fe80::')) return true; // link-local
  if (h.startsWith('fc') || h.startsWith('fd')) return true; // ULA
  if (h.startsWith('ff')) return true; // multicast
  if (h.startsWith('::ffff:')) {
    const v4 = h.slice(7);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v4)) return isPrivateIPv4(v4);
  }
  if (h.startsWith('64:ff9b::')) return true; // NAT64
  if (h.startsWith('2001:db8')) return true; // documentation
  return false;
}

function isPrivateAddress(ip: string): boolean {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return isPrivateIPv4(ip);
  return isPrivateIPv6(ip);
}

function validateHost(host: string): { valid: boolean; error?: string; isIPv6: boolean } {
  if (isBlockedHostname(host)) {
    return { valid: false, error: 'Scanning internal/private addresses is not allowed', isIPv6: false };
  }

  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))$/;
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

  if (ipv6Pattern.test(host)) {
    if (isPrivateIPv6(host)) {
      return { valid: false, error: 'Scanning internal/private addresses is not allowed', isIPv6: true };
    }
    return { valid: true, isIPv6: true };
  }

  if (ipv4Pattern.test(host)) {
    const octets = host.split('.').map(Number);
    if (octets.some(octet => octet < 0 || octet > 255)) {
      return { valid: false, error: 'Invalid IPv4 address', isIPv6: false };
    }
    if (isPrivateIPv4(host)) {
      return { valid: false, error: 'Scanning internal/private addresses is not allowed', isIPv6: false };
    }
    return { valid: true, isIPv6: false };
  }

  if (domainPattern.test(host)) {
    return { valid: true, isIPv6: false };
  }

  return { valid: false, error: 'Invalid hostname or IP address', isIPv6: false };
}

// Resolve a domain to IPs and ensure none point to private/internal ranges
// (DNS-rebinding / DNS-based SSRF defense). Literal IPs are passed through
// because validateHost() already gated them.
async function resolveAndValidateHost(host: string): Promise<{ ok: boolean; ip?: string; isIPv6?: boolean; error?: string }> {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return { ok: true, ip: host, isIPv6: false };
  if (host.includes(':')) return { ok: true, ip: host, isIPv6: true };

  const records: string[] = [];
  for (const type of ['A', 'AAAA'] as const) {
    try {
      const r = await Deno.resolveDns(host, type);
      records.push(...r);
    } catch {
      // ignore — record type may not exist
    }
  }
  if (records.length === 0) return { ok: false, error: 'Unable to resolve hostname' };
  for (const ip of records) {
    if (isPrivateAddress(ip)) {
      return { ok: false, error: 'Hostname resolves to an internal/private address' };
    }
  }
  const v4 = records.find((r) => /^(\d{1,3}\.){3}\d{1,3}$/.test(r));
  const chosen = v4 ?? records[0];
  return { ok: true, ip: chosen, isIPv6: !v4 };
}

// --- Rate Limiting ---

async function checkRateLimit(ip: string): Promise<{ allowed: boolean; remaining: number }> {
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );

  const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000).toISOString();
  const endpoint = 'check-port';

  // Get current count in this window
  const { data: existing } = await supabase
    .from('rate_limits')
    .select('id, request_count')
    .eq('ip_address', ip)
    .eq('endpoint', endpoint)
    .gte('window_start', windowStart)
    .order('window_start', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!existing) {
    // First request in this window — insert new record
    await supabase.from('rate_limits').insert({
      ip_address: ip,
      endpoint,
      request_count: 1,
      window_start: new Date().toISOString(),
    });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }

  if (existing.request_count >= RATE_LIMIT_MAX) {
    return { allowed: false, remaining: 0 };
  }

  // Increment the count
  await supabase
    .from('rate_limits')
    .update({ request_count: existing.request_count + 1 })
    .eq('id', existing.id);

  // Occasionally clean up old windows (roughly 5% of requests)
  if (Math.random() < 0.05) {
    await supabase.rpc('cleanup_rate_limits');
  }

  return { allowed: true, remaining: RATE_LIMIT_MAX - (existing.request_count + 1) };
}

// --- Port Check ---

async function checkPort(host: string, port: number, timeout: number = 5000): Promise<PortCheckResponse> {
  const startTime = Date.now();

  try {
    const hostValidation = validateHost(host);
    if (!hostValidation.valid) {
      return { host, port, status: 'error', error: hostValidation.error };
    }

    // DNS-based SSRF defense: resolve and ensure no resolved IP is private.
    const resolved = await resolveAndValidateHost(host);
    if (!resolved.ok || !resolved.ip) {
      return { host, port, status: 'error', error: resolved.error || 'Hostname resolution blocked' };
    }

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), timeout);
    });

    // Connect to the resolved IP (not the original hostname) to prevent
    // DNS rebinding between validation and connect.
    const connectPromise = (async () => {
      const conn = await Deno.connect({ hostname: resolved.ip!, port, transport: 'tcp' });
      conn.close();
      return conn;
    })();

    await Promise.race([connectPromise, timeoutPromise]);

    const responseTime = Date.now() - startTime;
    return {
      host, port, status: 'open', responseTime,
      service: serviceNames[port] || 'Unknown',
      ipVersion: hostValidation.isIPv6 ? 'IPv6' : 'IPv4',
    };
  } catch (err) {
    const responseTime = Date.now() - startTime;
    const error = err as Error;
    const errorMessage = error.message.toLowerCase();

    if (errorMessage.includes('timeout')) {
      return { host, port, status: 'timeout', responseTime, error: 'Connection timeout' };
    } else if (errorMessage.includes('refused') || errorMessage.includes('connect')) {
      return { host, port, status: 'closed', responseTime, error: 'Connection refused' };
    } else {
      return { host, port, status: 'error', responseTime, error: 'Connection failed' };
    }
  }
}

// --- Main Handler ---

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Extract client IP for rate limiting. Use the LAST entry of
    // x-forwarded-for — Supabase's edge appends the real client IP at the
    // end, so reading the rightmost value prevents trivial spoofing via a
    // forged left-most header value. cf-connecting-ip is preferred when
    // present (set by Cloudflare, not user-controllable end-to-end).
    const xff = req.headers.get('x-forwarded-for') ?? '';
    const xffParts = xff.split(',').map((s) => s.trim()).filter(Boolean);
    const clientIP =
      req.headers.get('cf-connecting-ip') ||
      (xffParts.length > 0 ? xffParts[xffParts.length - 1] : '') ||
      req.headers.get('x-real-ip') ||
      'unknown';

    // Rate limit check
    const rateLimit = await checkRateLimit(clientIP);
    if (!rateLimit.allowed) {
      return new Response(
        JSON.stringify({ error: 'Rate limit exceeded. Please wait before making more requests.' }),
        {
          status: 429,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
            'X-RateLimit-Limit': String(RATE_LIMIT_MAX),
            'X-RateLimit-Remaining': '0',
            'Retry-After': String(RATE_LIMIT_WINDOW_MINUTES * 60),
          },
        }
      );
    }

    const { host, port, timeout }: PortCheckRequest = await req.json();

    if (!host || typeof host !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Host is required and must be a string' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    if (!port || typeof port !== 'number' || port < 1 || port > 65535) {
      return new Response(
        JSON.stringify({ error: 'Port must be a number between 1 and 65535' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const sanitizedHost = host.trim();
    if (sanitizedHost.length > 253) {
      return new Response(
        JSON.stringify({ error: 'Hostname too long' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    console.log(`Port check requested for ${sanitizedHost}:${port} from IP ${clientIP}`);

    const result = await checkPort(sanitizedHost, port, timeout || 5000);

    return new Response(
      JSON.stringify(result),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'X-RateLimit-Limit': String(RATE_LIMIT_MAX),
          'X-RateLimit-Remaining': String(rateLimit.remaining),
        },
      }
    );
  } catch (err) {
    console.error('Error in check-port function:', err);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
