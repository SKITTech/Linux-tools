import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { AlertTriangle, RotateCcw, Terminal as TermIcon } from "lucide-react";
import { toast } from "sonner";
import { runCommand, isDestructive, DEFAULT_STATE, type SandboxState } from "./terminalEngine";

const HISTORY_KEY = "docker.term.history.v1";

export default function Terminal() {
  const [lines, setLines] = useState<{ kind: "prompt" | "out" | "err"; text: string }[]>([
    { kind: "out", text: "Docker Sandbox v1.0 — simulated environment (no host or real engine access).\nType 'help' to see available commands. Type 'reset' to reset state." },
  ]);
  const [input, setInput] = useState("");
  const [confirmDangerous, setConfirmDangerous] = useState(false);
  const [state, setState] = useState<SandboxState>(structuredClone(DEFAULT_STATE));
  const [history, setHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [histIdx, setHistIdx] = useState<number>(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-200))); }, [history]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [lines]);

  function submit() {
    const cmd = input.trim();
    if (!cmd) return;
    if (isDestructive(cmd) && !confirmDangerous) {
      toast.error("This command is destructive. Tick \"I understand\" to allow it.");
      return;
    }
    const next = [...lines, { kind: "prompt" as const, text: `$ ${cmd}` }];
    const result = runCommand(cmd, state);
    if (result.output === "__CLEAR__") {
      setLines([]); setInput(""); setHistory((h) => [...h, cmd]); setHistIdx(-1); return;
    }
    next.push({ kind: result.exitCode === 0 ? "out" : "err", text: result.output });
    setLines(next);
    setState(result.state);
    setHistory((h) => [...h, cmd]);
    setHistIdx(-1);
    setInput("");
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") { e.preventDefault(); submit(); return; }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const idx = histIdx === -1 ? history.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(idx); setInput(history[idx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx === -1) return;
      const idx = histIdx + 1;
      if (idx >= history.length) { setHistIdx(-1); setInput(""); } else { setHistIdx(idx); setInput(history[idx]); }
    }
  }

  function resetSandbox() {
    setState(structuredClone(DEFAULT_STATE));
    setLines([{ kind: "out", text: "Sandbox reset to defaults." }]);
    toast.success("Sandbox reset");
  }

  return (
    <div className="flex flex-col h-[calc(100vh-180px)]">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TermIcon className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Sandbox Terminal</h2>
          <Badge variant="outline" className="gap-1"><AlertTriangle className="w-3 h-3" />Simulated</Badge>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <Checkbox checked={confirmDangerous} onCheckedChange={(v) => setConfirmDangerous(!!v)} />
            I understand — allow destructive commands
          </label>
          <Button size="sm" variant="outline" onClick={resetSandbox}><RotateCcw className="w-3.5 h-3.5 mr-1" />Reset</Button>
        </div>
      </div>

      <Card className="p-3 mb-3 bg-amber-500/5 border-amber-500/30">
        <div className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <p>
            This terminal is a <strong>safe simulator</strong>. Only <code className="font-mono">docker</code> and{" "}
            <code className="font-mono">docker compose</code> are accepted (allowlist), no host commands ever execute, and no
            network is touched. Use it to practice flags and pipelines without risk.
          </p>
        </div>
      </Card>

      <Card className="flex-1 overflow-hidden bg-black text-green-400 font-mono text-xs">
        <div className="h-full overflow-y-auto p-4 space-y-1">
          {lines.map((l, i) => (
            <pre key={i} className={`whitespace-pre-wrap break-words ${l.kind === "err" ? "text-red-400" : l.kind === "prompt" ? "text-cyan-300" : "text-green-300"}`}>{l.text}</pre>
          ))}
          <div className="flex items-center gap-2 pt-1">
            <span className="text-cyan-300">$</span>
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              autoFocus
              spellCheck={false}
              className="flex-1 bg-transparent outline-none text-green-100 font-mono text-xs"
              placeholder="docker ps"
            />
          </div>
          <div ref={endRef} />
        </div>
      </Card>
    </div>
  );
}
