import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { question, mode, history } = await req.json();
    if (!question) {
      return new Response(JSON.stringify({ error: "question is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

    const isBeginner = mode !== "advanced";
    const systemPrompt = `You are "Ask Git", a senior software engineer and Git trainer.
Audience mode: ${isBeginner ? "BEGINNER — explain clearly, define jargon, prefer safe defaults." : "ADVANCED — concise, use flags, mention best practices, avoid hand-holding."}.

Formatting rules:
- Use Markdown.
- Put every shell command in its own fenced code block tagged \`\`\`bash so the UI can render a copy button.
- When suggesting a DESTRUCTIVE command (reset --hard, clean -fd/-fx, push --force, rebase that rewrites public history, filter-branch/filter-repo, branch -D, update-ref -d), prefix the explanation with "⚠️ DESTRUCTIVE:" and include an UNDO/recovery section using \`git reflog\`, \`git revert\`, or \`git restore\` as appropriate.
- For force pushes, recommend --force-with-lease over --force.
- Keep answers focused. No filler.`;

    const messages: Array<{ role: string; content: string }> = [
      { role: "system", content: systemPrompt },
    ];
    if (Array.isArray(history)) {
      for (const m of history.slice(-10)) {
        if (m?.role && m?.content) messages.push({ role: m.role, content: String(m.content).slice(0, 4000) });
      }
    }
    messages.push({ role: "user", content: String(question).slice(0, 4000) });

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "google/gemini-2.5-flash", messages }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Please try again shortly." }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted. Please add funds." }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const t = await response.text();
      console.error("git-ask AI error:", response.status, t);
      return new Response(JSON.stringify({ error: "AI service error" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content ?? "";

    return new Response(JSON.stringify({ success: true, answer: content }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("git-ask error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
