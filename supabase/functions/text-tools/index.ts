import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { text, action, targetLanguage } = await req.json();
    if (!text) throw new Error("Text is required");
    if (!action) throw new Error("Action is required");

    const apiKey = Deno.env.get("LOVABLE_API_KEY");
    if (!apiKey) throw new Error("API key not configured");

    let systemPrompt = "";
    switch (action) {
      case "grammar":
        systemPrompt = `You are a professional grammar and spelling checker. Analyze the text and respond with a JSON object (no markdown, no code fences):
{
  "corrected": "the corrected text",
  "changes": [{"original": "wrong text", "corrected": "correct text", "reason": "explanation"}],
  "score": 85,
  "summary": "brief summary of issues found"
}
Score is 0-100 (100 = perfect). Be thorough but preserve the original meaning and tone.`;
        break;
      case "professional":
        systemPrompt = `You are a professional writing assistant. Rewrite the text to sound more professional, polished, and business-appropriate. Respond with a JSON object (no markdown, no code fences):
{
  "rewritten": "the professional version",
  "tone": "formal/semi-formal/business-casual",
  "improvements": ["list of key improvements made"],
  "tip": "one writing tip based on the text"
}`;
        break;
      case "casual":
        systemPrompt = `You are a casual writing assistant. Rewrite the text to sound friendly, conversational, and approachable. Respond with a JSON object (no markdown, no code fences):
{
  "rewritten": "the casual version",
  "tone": "casual/friendly/conversational",
  "improvements": ["list of key changes made"],
  "tip": "one writing tip"
}`;
        break;
      case "translate":
        systemPrompt = `You are a professional translator. Translate the text to ${targetLanguage || "English"}. Respond with a JSON object (no markdown, no code fences):
{
  "translated": "the translated text",
  "sourceLanguage": "detected source language",
  "targetLanguage": "${targetLanguage || "English"}",
  "notes": "any translation notes or cultural context"
}`;
        break;
      case "summarize":
        systemPrompt = `You are a summarization expert. Summarize the text concisely. Respond with a JSON object (no markdown, no code fences):
{
  "summary": "concise summary",
  "keyPoints": ["key point 1", "key point 2"],
  "wordReduction": "e.g., 500 → 80 words"
}`;
        break;
      case "expand":
        systemPrompt = `You are a writing assistant. Expand and elaborate on the given text, adding detail and depth. Respond with a JSON object (no markdown, no code fences):
{
  "expanded": "the expanded text",
  "addedDetails": ["detail 1", "detail 2"],
  "wordIncrease": "e.g., 50 → 200 words"
}`;
        break;
      case "email":
        systemPrompt = `You are an email writing expert. Convert the text into a well-structured professional email. Respond with a JSON object (no markdown, no code fences):
{
  "subject": "suggested email subject",
  "email": "the full formatted email body",
  "tone": "the tone used",
  "tip": "one email writing tip"
}`;
        break;
      default:
        throw new Error("Invalid action");
    }

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: text }
        ],
        temperature: 0.3,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Please try again later." }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "Credits exhausted. Please add funds." }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      throw new Error("AI gateway error: " + response.status);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || "";

    let parsed;
    try {
      const cleaned = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch {
      parsed = { error: "Failed to parse response", raw: content };
    }

    return new Response(JSON.stringify(parsed), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
