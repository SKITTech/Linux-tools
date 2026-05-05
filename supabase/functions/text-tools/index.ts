import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

async function callAI(apiKey: string, systemPrompt: string, userText: string, model = "google/gemini-2.5-flash-lite") {
  const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userText }
      ],
      temperature: 0.3,
      response_format: { type: "json_object" },
    }),
  });

  if (!response.ok) {
    if (response.status === 429) throw { status: 429, message: "Rate limit exceeded. Please try again later." };
    if (response.status === 402) throw { status: 402, message: "Credits exhausted. Please add funds." };
    throw new Error("AI gateway error: " + response.status);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content || "";
  let cleaned = content.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();

  const jsonStart = cleaned.search(/[\{\[]/);
  const startChar = jsonStart !== -1 ? cleaned[jsonStart] : '{';
  const jsonEnd = cleaned.lastIndexOf(startChar === '[' ? ']' : '}');
  if (jsonStart !== -1 && jsonEnd !== -1) cleaned = cleaned.substring(jsonStart, jsonEnd + 1);

  try {
    return JSON.parse(cleaned);
  } catch {
    cleaned = cleaned
      .replace(/,\s*}/g, "}").replace(/,\s*]/g, "]")
      .replace(/[\x00-\x1F\x7F]/g, "");
    return JSON.parse(cleaned);
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { text, action, targetLanguage } = await req.json();
    if (!text) throw new Error("Text is required");
    if (!action) throw new Error("Action is required");

    const apiKey = Deno.env.get("LOVABLE_API_KEY");
    if (!apiKey) throw new Error("API key not configured");

    // Combined enhance action - single AI call returning all 3 variants for max speed
    if (action === "enhance") {
      const enhancePrompt = `You are an expert writing assistant. Analyze the user's text and produce three deliverables in ONE JSON response (no markdown, no code fences):
{
  "grammar": {
    "corrected": "the grammar/spelling-corrected text preserving original meaning and tone",
    "changes": [{"original":"wrong phrase","corrected":"fixed phrase","reason":"short reason"}],
    "score": 85,
    "summary": "one short sentence about overall quality"
  },
  "professional": {
    "rewritten": "polished professional rewrite suitable for business/formal contexts",
    "improvements": ["clarity","tone","conciseness"],
    "tip": "one actionable tip"
  },
  "casual": {
    "rewritten": "natural friendly conversational rewrite",
    "improvements": ["warmth","brevity"],
    "tip": "one actionable tip"
  }
}
Score 0-100 (100 = flawless). Keep changes array <= 8 items. Be concise.`;

      const parsed = await callAI(apiKey, enhancePrompt, text);
      return new Response(JSON.stringify(parsed), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Email suggestions - generates 3 email options
    if (action === "email-suggestions") {
      const emailPrompt = `You are an email writing expert. Based on the user's message, generate exactly 3 different email versions with varying tones (formal, semi-formal, friendly). Respond with JSON (no markdown, no code fences):
{
  "suggestions": [
    {"tone":"Formal","subject":"subject line","email":"full email body"},
    {"tone":"Semi-Formal","subject":"subject line","email":"full email body"},
    {"tone":"Friendly","subject":"subject line","email":"full email body"}
  ],
  "tip":"one email writing tip"
}`;
      const parsed = await callAI(apiKey, emailPrompt, text);
      return new Response(JSON.stringify(parsed), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    let systemPrompt = "";
    switch (action) {
      case "translate":
        systemPrompt = `You are a professional translator. Translate the text to ${targetLanguage || "English"}. Respond with JSON (no markdown, no code fences):
{"translated":"translated text","sourceLanguage":"detected language","targetLanguage":"${targetLanguage || "English"}","notes":"translation notes"}`;
        break;
      case "summarize":
        systemPrompt = `You are a summarization expert. Summarize the text concisely. Respond with JSON (no markdown, no code fences):
{"summary":"concise summary","keyPoints":["point 1","point 2"],"wordReduction":"e.g., 500 → 80 words"}`;
        break;
      case "expand":
        systemPrompt = `You are a writing assistant. Expand the text with detail. Respond with JSON (no markdown, no code fences):
{"expanded":"expanded text","addedDetails":["detail 1"],"wordIncrease":"e.g., 50 → 200 words"}`;
        break;
      default:
        throw new Error("Invalid action");
    }

    const parsed = await callAI(apiKey, systemPrompt, text);
    return new Response(JSON.stringify(parsed), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const status = error.status || 500;
    const message = error.message || "Unknown error";
    return new Response(JSON.stringify({ error: message }), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
