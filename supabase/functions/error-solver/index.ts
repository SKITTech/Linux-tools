import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { errorMessage } = await req.json();
    if (!errorMessage) {
      return new Response(JSON.stringify({ error: "Error message is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

    const systemPrompt = `You are an expert Virtualizor system administrator and troubleshooting specialist. 
Your job is to help users diagnose and fix Virtualizor-related errors.

When given an error message or error code, you must:
1. Search your knowledge of the official Virtualizor documentation (https://virtualizor.com/docs/) 
2. Consider common Virtualizor issues related to KVM, OpenVZ, LXC, Xen virtualization
3. Consider server configuration, networking, storage, and panel-related issues

Respond in this EXACT JSON format (no markdown wrapping, pure JSON):
{
  "errorExplanation": "Clear explanation of what this error means in the context of Virtualizor",
  "possibleCauses": ["cause 1", "cause 2", "cause 3"],
  "stepByStepFix": [
    {"step": 1, "title": "Step title", "description": "Detailed description", "command": "optional command to run"},
    {"step": 2, "title": "Step title", "description": "Detailed description", "command": ""}
  ],
  "references": [
    {"title": "Reference title", "url": "https://virtualizor.com/docs/relevant-page"}
  ],
  "additionalNotes": "Any extra tips or warnings"
}

Always prioritize official Virtualizor documentation references. Include relevant CLI commands, config file paths, and panel navigation steps. If the error is not Virtualizor-specific, still try to provide context about how it relates to a Virtualizor environment.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Diagnose and provide a fix for this Virtualizor error:\n\n${errorMessage}` },
        ],
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

    let parsed;
    try {
      // Strip markdown code fences if present
      const cleaned = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch {
      parsed = { rawResponse: content };
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
