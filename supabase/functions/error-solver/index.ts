import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

async function isUrlReachable(url: string): Promise<boolean> {
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) return false;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    let res: Response;
    try {
      res = await fetch(url, { method: "HEAD", redirect: "follow", signal: ctrl.signal });
      // Some servers reject HEAD; retry with GET
      if (res.status === 405 || res.status === 403) {
        res = await fetch(url, { method: "GET", redirect: "follow", signal: ctrl.signal });
      }
    } finally {
      clearTimeout(t);
    }
    return res.ok || (res.status >= 200 && res.status < 400);
  } catch {
    return false;
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { errorMessage, product } = await req.json();
    if (!errorMessage) {
      return new Response(JSON.stringify({ error: "Error message is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

    const productContext: Record<string, { label: string; prompt: string }> = {
      virtualizor: {
        label: "Virtualizor",
        prompt: `You are a senior Virtualizor Technical Support Engineer at Softaculous Ltd with 10+ years of hands-on experience supporting Virtualizor (KVM, OpenVZ 7, LXC, Proxmox-LXC, Xen) deployments for hosting providers worldwide.
You diagnose issues like a real support agent would: precise, empathetic, professional, and concise. You know the product's CLI tools (/usr/local/emps/bin/php /usr/local/virtualizor/scripts/*, vzctl, virsh, qm, lxc), config files (/usr/local/virtualizor/conf/*, /etc/libvirt/qemu/*), log paths (/var/log/virtualizor/*), and panel navigation paths (Admin Panel → ... ).
You are familiar with the Virtualizor docs (https://virtualizor.com/docs/) and the Softaculous community board (https://www.softaculous.com/board/).`,
      },
      softaculous: {
        label: "Softaculous",
        prompt: `You are a senior Softaculous Technical Support Engineer with deep expertise across Softaculous Auto Installer integrations (cPanel, Plesk, DirectAdmin, InterWorx, H-Sphere), the script catalog (WordPress, Joomla, Magento, Drupal etc.), backup/restore, cron, license activation, and PHP/MySQL/file-permission edge cases.
You answer like a real support agent: clear, professional, with exact CLI commands, paths (/usr/local/softaculous/, /var/softaculous/), log files, and panel navigation steps.
You reference https://www.softaculous.com/docs/ and the community board https://www.softaculous.com/board/.`,
      },
      webuzo: {
        label: "Webuzo",
        prompt: `You are a senior Webuzo Technical Support Engineer with extensive experience supporting single-server LAMP/LEMP deployments, mail (Exim/Dovecot), DNS, FTP, SSL (Let's Encrypt + custom), firewall, and the application installer.
You troubleshoot like a real support agent: targeted questions, precise CLI commands, paths (/usr/local/webuzo/, /var/webuzo/logs/), and panel navigation. You reference https://www.webuzo.com/docs/.`,
      },
    };

    const selected = productContext[product] ? product : "virtualizor";
    const ctx = productContext[selected];

    const systemPrompt = `${ctx.prompt}

Respond ONLY with a single JSON object (no markdown, no code fences) in this EXACT shape:
{
  "errorExplanation": "Plain-English explanation of what this error actually means in ${ctx.label}.",
  "possibleCauses": ["most likely cause first", "next likely cause", "..."],
  "stepByStepFix": [
    {"step": 1, "title": "Short imperative title", "description": "What to do and why. Mention exact panel paths or file locations.", "command": "exact shell command (or empty string if none)"}
  ],
  "customerReply": "A ready-to-send professional reply written in first person plural ('we', 'our team') that the support agent can paste directly into a ticket response to the end customer. It should: greet politely, briefly acknowledge the issue, explain in non-technical language what happened, list the corrective steps the customer should take (numbered), offer further help, and close with a polite sign-off. Use plain text with line breaks, no markdown. Around 120-220 words.",
  "references": [
    {"title": "Page title", "url": "https://full-real-url"}
  ],
  "additionalNotes": "Optional warnings, prerequisites, or follow-up tips. Empty string if nothing to add."
}

Rules for references:
- Only include URLs you are confident actually exist on the official documentation domains (virtualizor.com/docs, softaculous.com/docs, softaculous.com/board, webuzo.com/docs).
- Prefer the docs root or a known stable section over guessing deep URLs. If you are unsure a deep link exists, use the docs root.
- Never invent URLs. If you have no reliable reference, return an empty references array [].

Tone for stepByStepFix: terse, technical, engineer-to-engineer.
Tone for customerReply: warm, professional, customer-friendly, no jargon dumps.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-pro",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Diagnose this ${ctx.label} issue and provide a fix:\n\n${errorMessage}` },
        ],
        response_format: { type: "json_object" },
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Please try again in a moment." }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted. Please add funds." }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const t = await response.text();
      console.error("AI gateway error:", response.status, t);
      return new Response(JSON.stringify({ error: "AI service error" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    let parsed: any;
    try {
      const cleaned = String(content || "").replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch {
      parsed = { rawResponse: content };
    }

    // Validate references — only keep working URLs
    if (Array.isArray(parsed?.references) && parsed.references.length > 0) {
      const checks = await Promise.all(
        parsed.references.map(async (r: any) => {
          if (!r?.url || typeof r.url !== "string") return null;
          const ok = await isUrlReachable(r.url);
          return ok ? { title: r.title || r.url, url: r.url } : null;
        })
      );
      parsed.references = checks.filter(Boolean);
    } else {
      parsed.references = [];
    }

    return new Response(JSON.stringify({ success: true, data: parsed }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("error-solver error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
