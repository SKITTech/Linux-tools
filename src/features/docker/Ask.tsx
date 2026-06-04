import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Copy, Send, AlertTriangle, Sparkles, Search, X, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import type { AskMode, ChatMessage } from "./types";

const TOPICS = [
  "Dockerfile", "Compose", "Networking", "Volumes", "BuildKit",
  "Multi-stage", "Healthchecks", "Secrets", "Debugging", "Security", "Registry", "Swarm",
];

const TEMPLATES = [
  { label: "Dockerfile help", text: "Help me write a production-ready Dockerfile for a Node 20 TypeScript API." },
  { label: "Compose help", text: "Show me a docker compose.yaml for a Node API + Postgres with healthchecks." },
  { label: "Networking", text: "Explain Docker user-defined bridge networks and container DNS with examples." },
  { label: "Volumes", text: "Named volumes vs bind mounts — when to use which? Show commands." },
  { label: "Debug exit 137", text: "My container exits with code 137. How do I debug it?" },
];

const STORAGE_KEY = "docker.ask.history.v1";
const MODE_KEY = "docker.ask.mode.v1";

const DESTRUCTIVE = /\b(rm\s+-f|system\s+prune|volume\s+(rm|prune)|image\s+prune\s+-a|container\s+prune|network\s+prune|down\s+.*-v)\b/i;

function CodeBlock({ code }: { code: string }) {
  const destructive = DESTRUCTIVE.test(code);
  return (
    <div className="my-2 rounded-lg border border-border/60 bg-muted/40 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/60 bg-muted/60 text-xs">
        <span className="font-mono text-muted-foreground">bash</span>
        <div className="flex items-center gap-2">
          {destructive && (
            <Badge variant="destructive" className="gap-1"><AlertTriangle className="w-3 h-3" />destructive</Badge>
          )}
          <Button size="sm" variant="ghost" className="h-6 px-2"
            onClick={() => { navigator.clipboard.writeText(code); toast.success("Copied"); }}>
            <Copy className="w-3 h-3 mr-1" />Copy
          </Button>
        </div>
      </div>
      <pre className="px-3 py-2 text-xs font-mono overflow-x-auto whitespace-pre">{code}</pre>
    </div>
  );
}

function renderMarkdown(text: string) {
  const parts: React.ReactNode[] = [];
  const regex = /```(?:bash|sh|shell|dockerfile|yaml|yml)?\n([\s\S]*?)```/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = regex.exec(text)) !== null) {
    if (m.index > last) parts.push(<p key={`t${i}`} className="whitespace-pre-wrap text-sm leading-relaxed">{text.slice(last, m.index)}</p>);
    parts.push(<CodeBlock key={`c${i}`} code={m[1].trim()} />);
    last = m.index + m[0].length; i++;
  }
  if (last < text.length) parts.push(<p key={`t${i}`} className="whitespace-pre-wrap text-sm leading-relaxed">{text.slice(last)}</p>);
  return <div>{parts}</div>;
}

export default function Ask() {
  const [mode, setMode] = useState<AskMode>(() => (localStorage.getItem(MODE_KEY) as AskMode) || "beginner");
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); } catch { return []; }
  });
  const [input, setInput] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { localStorage.setItem(STORAGE_KEY, JSON.stringify(messages)); }, [messages]);
  useEffect(() => { localStorage.setItem(MODE_KEY, mode); }, [mode]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" }); }, [messages, loading]);
  useEffect(() => { taRef.current?.focus(); }, []);

  const visible = useMemo(() => {
    if (!search.trim()) return messages;
    const s = search.toLowerCase();
    return messages.filter((m) => m.content.toLowerCase().includes(s));
  }, [messages, search]);

  async function ask(question: string, history: ChatMessage[]) {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("docker-ask", {
        body: { question, mode, history: history.slice(-10).map(({ role, content }) => ({ role, content })) },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      return (data?.answer as string) || "(no response)";
    } finally {
      setLoading(false);
    }
  }

  async function send(question: string) {
    const q = question.trim();
    if (!q || loading) return;
    const userMsg: ChatMessage = { id: crypto.randomUUID(), role: "user", content: q, createdAt: Date.now() };
    const next = [...messages, userMsg];
    setMessages(next); setInput("");
    try {
      const answer = await ask(q, next);
      setMessages((m) => [...m, { id: crypto.randomUUID(), role: "assistant", content: answer, createdAt: Date.now() }]);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to ask");
    } finally {
      setTimeout(() => taRef.current?.focus(), 0);
    }
  }

  async function regenerate() {
    // remove trailing assistant message(s) and re-ask the last user message
    let trimmed = [...messages];
    while (trimmed.length && trimmed[trimmed.length - 1].role === "assistant") trimmed.pop();
    const last = trimmed[trimmed.length - 1];
    if (!last || last.role !== "user") { toast.error("Nothing to regenerate"); return; }
    setMessages(trimmed);
    try {
      const answer = await ask(last.content, trimmed);
      setMessages((m) => [...m, { id: crypto.randomUUID(), role: "assistant", content: answer, createdAt: Date.now() }]);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to regenerate");
    }
  }

  function deleteFrom(id: string) {
    const idx = messages.findIndex((m) => m.id === id);
    if (idx === -1) return;
    setMessages(messages.slice(0, idx));
  }

  return (
    <div className="flex flex-col h-[calc(100vh-180px)]">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Ask Docker</h2>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Mode:</span>
          <Button size="sm" variant={mode === "beginner" ? "default" : "outline"} onClick={() => setMode("beginner")}>Beginner</Button>
          <Button size="sm" variant={mode === "advanced" ? "default" : "outline"} onClick={() => setMode("advanced")}>Advanced</Button>
          {messages.some((m) => m.role === "assistant") && (
            <Button size="sm" variant="outline" onClick={regenerate} disabled={loading}>
              <RefreshCw className="w-3.5 h-3.5 mr-1" />Regenerate
            </Button>
          )}
          {messages.length > 0 && (
            <Button size="sm" variant="ghost" onClick={() => setMessages([])}>Clear</Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-2">
        {TEMPLATES.map((t) => (
          <Button key={t.label} size="sm" variant="outline" className="h-7 text-xs rounded-full" onClick={() => send(t.text)} disabled={loading}>
            {t.label}
          </Button>
        ))}
      </div>
      <div className="flex flex-wrap gap-1.5 mb-3">
        {TOPICS.map((t) => (
          <Badge key={t} variant="secondary" className="cursor-pointer hover:bg-primary/20 text-[11px]" onClick={() => send(`Explain Docker ${t} with practical examples and the most common commands.`)}>
            {t}
          </Badge>
        ))}
      </div>

      {messages.length > 3 && (
        <div className="relative mb-2">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search history…" className="h-8 pl-7 pr-7 text-xs" />
          {search && <button onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2"><X className="w-3 h-3 text-muted-foreground" /></button>}
        </div>
      )}

      <Card className="flex-1 overflow-hidden">
        <ScrollArea className="h-full">
          <div ref={scrollRef} className="p-4 space-y-4">
            {visible.length === 0 && (
              <div className="text-center text-sm text-muted-foreground py-12">
                Ask any Docker question. Tap a chip above to get started.
              </div>
            )}
            {visible.map((m) => (
              <div key={m.id} className={m.role === "user" ? "flex justify-end group" : "group"}>
                {m.role === "user" ? (
                  <div className="max-w-[80%] rounded-2xl bg-primary text-primary-foreground px-4 py-2 text-sm whitespace-pre-wrap relative">
                    {m.content}
                    <button onClick={() => deleteFrom(m.id)} title="Delete from here" className="absolute -left-7 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <div className="max-w-[90%]">
                    {renderMarkdown(m.content)}
                    <div className="mt-1 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => { navigator.clipboard.writeText(m.content); toast.success("Answer copied"); }}>
                        <Copy className="w-3 h-3 mr-1" />Copy answer
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {loading && <div className="text-xs text-muted-foreground animate-pulse">Thinking…</div>}
          </div>
        </ScrollArea>
      </Card>

      <div className="mt-3 flex gap-2 items-end">
        <Textarea
          ref={taRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask anything Docker — Enter to send, Shift+Enter for newline"
          className="min-h-[60px] resize-none font-mono text-sm"
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              send(input);
            }
          }}
        />
        <Button onClick={() => send(input)} disabled={loading || !input.trim()} className="h-[60px] px-5">
          <Send className="w-4 h-4 mr-2" />Ask
        </Button>
      </div>
    </div>
  );
}
