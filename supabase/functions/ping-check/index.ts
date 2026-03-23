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
    const { host, count } = await req.json();

    if (!host || typeof host !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Host is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const sanitized = host.trim();
    if (sanitized.length > 253) {
      return new Response(
        JSON.stringify({ error: 'Hostname too long' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Block private/internal addresses
    const blocked = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
    if (blocked.includes(sanitized.toLowerCase())) {
      return new Response(
        JSON.stringify({ error: 'Scanning internal addresses is not allowed' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const pingCount = Math.min(count || 4, 10);
    const results: Array<{ seq: number; time: number; status: string }> = [];

    // Perform real HTTP-based connectivity checks
    for (let i = 0; i < pingCount; i++) {
      const startTime = performance.now();
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        // Use HEAD request to minimize data transfer
        const url = sanitized.includes('://') ? sanitized : `https://${sanitized}`;
        await fetch(url, {
          method: 'HEAD',
          signal: controller.signal,
          redirect: 'follow',
        });

        clearTimeout(timeout);
        const elapsed = Math.round(performance.now() - startTime);
        results.push({ seq: i + 1, time: elapsed, status: 'ok' });
      } catch (err) {
        const elapsed = Math.round(performance.now() - startTime);
        const error = err as Error;
        if (error.name === 'AbortError') {
          results.push({ seq: i + 1, time: elapsed, status: 'timeout' });
        } else {
          results.push({ seq: i + 1, time: elapsed, status: 'error' });
        }
      }

      // Small delay between pings
      if (i < pingCount - 1) {
        await new Promise(r => setTimeout(r, 200));
      }
    }

    const successful = results.filter(r => r.status === 'ok');
    const times = successful.map(r => r.time);
    const stats = times.length > 0
      ? {
          min: Math.min(...times),
          max: Math.max(...times),
          avg: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
        }
      : null;

    return new Response(
      JSON.stringify({
        host: sanitized,
        results,
        summary: {
          sent: results.length,
          received: successful.length,
          lost: results.length - successful.length,
          lossPercent: Math.round(((results.length - successful.length) / results.length) * 100),
          stats,
        },
      }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    console.error('Ping error:', err);
    return new Response(
      JSON.stringify({ error: 'Ping check failed' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
