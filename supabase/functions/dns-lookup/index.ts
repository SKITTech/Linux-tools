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
    const { domain, type } = await req.json();

    if (!domain || typeof domain !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Domain is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const sanitized = domain.trim().replace(/\/+$/, '');
    if (sanitized.length > 253) {
      return new Response(
        JSON.stringify({ error: 'Domain too long' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const recordType = (type || 'A').toUpperCase();
    const validTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA', 'PTR'];
    if (!validTypes.includes(recordType)) {
      return new Response(
        JSON.stringify({ error: `Invalid record type. Supported: ${validTypes.join(', ')}` }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const startTime = Date.now();

    // Use Google's DNS-over-HTTPS API for real lookups
    const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(sanitized)}&type=${recordType}`;
    const dnsResp = await fetch(dnsUrl, {
      headers: { 'Accept': 'application/dns-json' },
    });

    const dnsData = await dnsResp.json();
    const queryTime = Date.now() - startTime;

    const records = (dnsData.Answer || []).map((answer: any) => ({
      name: answer.name,
      type: getTypeName(answer.type),
      ttl: answer.TTL,
      data: answer.data,
    }));

    const authority = (dnsData.Authority || []).map((auth: any) => ({
      name: auth.name,
      type: getTypeName(auth.type),
      ttl: auth.TTL,
      data: auth.data,
    }));

    return new Response(
      JSON.stringify({
        domain: sanitized,
        queryType: recordType,
        status: dnsData.Status === 0 ? 'NOERROR' : `ERROR (${dnsData.Status})`,
        records,
        authority,
        queryTime,
        server: 'dns.google',
        truncated: dnsData.TC || false,
        recursionAvailable: dnsData.RA || false,
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    console.error('DNS lookup error:', err);
    return new Response(
      JSON.stringify({ error: 'DNS lookup failed' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

function getTypeName(typeNum: number): string {
  const types: Record<number, string> = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 43: 'DS', 46: 'RRSIG', 47: 'NSEC',
    48: 'DNSKEY', 50: 'NSEC3', 257: 'CAA', 12: 'PTR',
  };
  return types[typeNum] || `TYPE${typeNum}`;
}
