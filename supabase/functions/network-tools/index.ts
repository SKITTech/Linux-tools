import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { tool, ...params } = await req.json();

    switch (tool) {
      case 'whats-my-ip':
        return handleWhatsMyIP(req);
      case 'http-headers':
        return handleHttpHeaders(params);
      case 'reverse-dns':
        return handleReverseDns(params);
      case 'website-to-ip':
        return handleWebsiteToIP(params);
      case 'whois':
        return handleWhois(params);
      case 'ssl-check':
        return handleSSLCheck(params);
      case 'ip-geolocation':
        return handleIPGeolocation(params);
      default:
        return json({ error: `Unknown tool: ${tool}` }, 400);
    }
  } catch (err) {
    console.error('network-tools error:', err);
    return json({ error: 'Request failed' }, 500);
  }
});

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/* ─── What's My IP ─── */
async function handleWhatsMyIP(req: Request) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown';

  // Get geolocation info via ip-api.com (free, no key needed)
  let geo: any = {};
  try {
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,timezone`);
    const data = await resp.json();
    if (data.status === 'success') geo = data;
  } catch { /* ignore */ }

  return json({
    ip,
    country: geo.country || 'Unknown',
    region: geo.regionName || 'Unknown',
    city: geo.city || 'Unknown',
    isp: geo.isp || 'Unknown',
    org: geo.org || 'Unknown',
    as: geo.as || 'Unknown',
    timezone: geo.timezone || 'Unknown',
  });
}

/* ─── HTTP Headers ─── */
async function handleHttpHeaders(params: any) {
  const { url } = params;
  if (!url) return json({ error: 'URL is required' }, 400);

  const target = url.includes('://') ? url : `https://${url}`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const resp = await fetch(target, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeout);
    const elapsed = Date.now() - start;

    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });

    // Consume body to prevent leak
    await resp.text();

    return json({
      url: target,
      status: resp.status,
      statusText: resp.statusText,
      responseTime: elapsed,
      headers,
      redirected: resp.redirected,
      finalUrl: resp.url,
    });
  } catch (err: any) {
    return json({ error: err.message || 'Failed to fetch headers' }, 500);
  }
}

/* ─── Reverse DNS ─── */
async function handleReverseDns(params: any) {
  const { ip } = params;
  if (!ip) return json({ error: 'IP address is required' }, 400);

  // Use Google DNS-over-HTTPS for PTR lookup
  // Convert IP to reverse format
  const parts = ip.split('.');
  if (parts.length === 4) {
    const reversed = parts.reverse().join('.') + '.in-addr.arpa';
    try {
      const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(reversed)}&type=PTR`);
      const data = await resp.json();
      const hostnames = (data.Answer || [])
        .filter((a: any) => a.type === 12)
        .map((a: any) => a.data.replace(/\.$/, ''));

      return json({
        ip,
        hostnames,
        query: reversed,
        status: data.Status === 0 ? 'NOERROR' : `ERROR (${data.Status})`,
      });
    } catch (err: any) {
      return json({ error: 'Reverse DNS lookup failed' }, 500);
    }
  }

  return json({ error: 'Only IPv4 addresses are supported for reverse DNS' }, 400);
}

/* ─── Website to IP ─── */
async function handleWebsiteToIP(params: any) {
  const { domain } = params;
  if (!domain) return json({ error: 'Domain is required' }, 400);

  const sanitized = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  try {
    // Get A records (IPv4)
    const respA = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sanitized)}&type=A`);
    const dataA = await respA.json();
    const ipv4 = (dataA.Answer || []).filter((a: any) => a.type === 1).map((a: any) => a.data);

    // Get AAAA records (IPv6)
    const respAAAA = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sanitized)}&type=AAAA`);
    const dataAAAA = await respAAAA.json();
    const ipv6 = (dataAAAA.Answer || []).filter((a: any) => a.type === 28).map((a: any) => a.data);

    return json({
      domain: sanitized,
      ipv4,
      ipv6,
      hasIPv6: ipv6.length > 0,
    });
  } catch (err: any) {
    return json({ error: 'Domain resolution failed' }, 500);
  }
}

/* ─── WHOIS (basic via RDAP) ─── */
async function handleWhois(params: any) {
  const { query } = params;
  if (!query) return json({ error: 'Domain or IP is required' }, 400);

  const sanitized = query.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  try {
    // Try RDAP for domain info
    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(sanitized)}`);
    if (!resp.ok) {
      await resp.text();
      return json({
        query: sanitized,
        error: 'WHOIS data not available via RDAP',
        raw: null,
      });
    }

    const data = await resp.json();

    const registrar = data.entities?.find((e: any) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'Unknown';
    
    const events: Record<string, string> = {};
    (data.events || []).forEach((e: any) => {
      events[e.eventAction] = e.eventDate;
    });

    const nameservers = (data.nameservers || []).map((ns: any) => ns.ldhName || ns.objectClassName);

    return json({
      query: sanitized,
      name: data.ldhName || sanitized,
      status: data.status || [],
      registrar,
      created: events.registration || 'Unknown',
      updated: events.lastChanged || 'Unknown',
      expires: events.expiration || 'Unknown',
      nameservers,
      rdapUrl: data.links?.[0]?.href || null,
    });
  } catch (err: any) {
    return json({ error: 'WHOIS lookup failed' }, 500);
  }
}

/* ─── IP Geolocation ─── */
async function handleIPGeolocation(params: any) {
  const { ip } = params;
  if (!ip) return json({ error: 'IP address is required' }, 400);

  const sanitized = ip.trim();

  try {
    // Primary: ip-api.com (free, no key)
    const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(sanitized)}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query`);
    const data = await resp.json();

    if (data.status === 'fail') {
      return json({ error: data.message || 'Geolocation lookup failed', ip: sanitized });
    }

    return json({
      ip: data.query || sanitized,
      continent: data.continent || 'Unknown',
      country: data.country || 'Unknown',
      countryCode: data.countryCode || '',
      region: data.regionName || 'Unknown',
      regionCode: data.region || '',
      city: data.city || 'Unknown',
      zip: data.zip || 'Unknown',
      lat: data.lat,
      lon: data.lon,
      timezone: data.timezone || 'Unknown',
      utcOffset: data.offset,
      currency: data.currency || 'Unknown',
      isp: data.isp || 'Unknown',
      org: data.org || 'Unknown',
      as: data.as || 'Unknown',
      asName: data.asname || 'Unknown',
      reverse: data.reverse || '',
      mobile: data.mobile || false,
      proxy: data.proxy || false,
      hosting: data.hosting || false,
    });
  } catch (err: any) {
    return json({ error: 'IP geolocation lookup failed' }, 500);
  }
}

/* ─── SSL Certificate Check ─── */
async function handleSSLCheck(params: any) {
  const { domain } = params;
  if (!domain) return json({ error: 'Domain is required' }, 400);

  const sanitized = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const url = `https://${sanitized}`;

  try {
    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const resp = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeout);
    const elapsed = Date.now() - start;
    await resp.text();

    // We can't access TLS details directly in Deno fetch, but we can confirm HTTPS works
    return json({
      domain: sanitized,
      sslValid: resp.ok || resp.status < 500,
      statusCode: resp.status,
      responseTime: elapsed,
      redirected: resp.redirected,
      finalUrl: resp.url,
      protocol: 'TLS',
    });
  } catch (err: any) {
    return json({
      domain: sanitized,
      sslValid: false,
      error: err.message || 'SSL check failed',
    });
  }
}
