import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertTriangle, RotateCcw, Terminal as TermIcon, GitBranch, Sparkles, Wrench } from "lucide-react";
import { toast } from "sonner";
import { runGit, isDestructive, EMPTY_STATE, type RepoState } from "./gitEngine";

const HISTORY_KEY = "git.term.history.v1";
const STATE_KEY = "git.term.state.v1";

export default function Terminal() {
  const [lines, setLines] = useState<{ kind: "prompt" | "out" | "err"; text: string }[]>([
    { kind: "out", text: "Git Sandbox v1.0 — simulated environment (allowlisted commands only, no host access).\nType 'help' to list commands. 'load-sample' to start with a toy repo. 'load-conflict' for a conflict exercise." },
  ]);
  const [input, setInput] = useState("");
  const [confirmDangerous, setConfirmDangerous] = useState(false);
  const [readOnly, setReadOnly] = useState(false);
  const [state, setState] = useState<RepoState>(() => {
    try { return JSON.parse(localStorage.getItem(STATE_KEY) || "null") || structuredClone(EMPTY_STATE); } catch { return structuredClone(EMPTY_STATE); }
  });
  const [history, setHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [histIdx, setHistIdx] = useState<number>(-1);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [b, setB] = useState({ commitMsg: "", branch: "", mergeTarget: "" });
  const inputRef = useRef<HTMLInputElement>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-200))); }, [history]);
  useEffect(() => { localStorage.setItem(STATE_KEY, JSON.stringify(state)); }, [state]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [lines]);

  function run(cmd: string) {
    if (!cmd.trim()) return;
    if (isDestructive(cmd) && !confirmDangerous) {
      toast.error('Destructive command — tick "I understand" to allow it.');
    }
    const next = [...lines, { kind: "prompt" as const, text: `$ ${cmd}` }];
    const result = runGit(cmd, state, { readOnly, confirmedDestructive: confirmDangerous });
    if (result.output === "__CLEAR__") { setLines([]); setInput(""); setHistory((h) => [...h, cmd]); setHistIdx(-1); return; }
    next.push({ kind: result.exitCode === 0 ? "out" : "err", text: result.output });
    setLines(next); setState(result.state);
    setHistory((h) => [...h, cmd]); setHistIdx(-1); setInput("");
  }

  function submit() { run(input.trim()); }

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
    setState(structuredClone(EMPTY_STATE));
    setLines([{ kind: "out", text: "Sandbox reset to empty repo state." }]);
    toast.success("Sandbox reset");
  }

  const branchName = state.head.startsWith("DETACHED:") ? `(detached ${state.head.slice(9)})` : state.head;

  return (
    <div className="flex flex-col h-[calc(100vh-180px)]">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TermIcon className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Sandbox Terminal</h2>
          <Badge variant="outline" className="gap-1"><AlertTriangle className="w-3 h-3" />Simulated</Badge>
          <Badge variant="secondary" className="gap-1"><GitBranch className="w-3 h-3" />{branchName}</Badge>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <Switch checked={readOnly} onCheckedChange={setReadOnly} />
            Read-only
          </label>
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <Checkbox checked={confirmDangerous} onCheckedChange={(v) => setConfirmDangerous(!!v)} />
            I understand — allow destructive ops
          </label>
          <Button size="sm" variant="outline" onClick={resetSandbox}><RotateCcw className="w-3.5 h-3.5 mr-1" />Reset</Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-3">
        <Button size="sm" variant="outline" onClick={() => run("load-sample")}><Sparkles className="w-3.5 h-3.5 mr-1" />Load sample repo</Button>
        <Button size="sm" variant="outline" onClick={() => run("load-conflict")}>Open conflict exercise</Button>
        <Button size="sm" variant="outline" onClick={() => run("git branch")}>Show branches</Button>
        <Button size="sm" variant="outline" onClick={() => run("git log --oneline")}>Show log</Button>
        <Button size="sm" variant={builderOpen ? "default" : "outline"} onClick={() => setBuilderOpen((v) => !v)}><Wrench className="w-3.5 h-3.5 mr-1" />Command builder</Button>
      </div>

      {builderOpen && (
        <Card className="p-3 mb-3 grid sm:grid-cols-3 gap-3">
          <div className="space-y-1">
            <Label className="text-[11px]">Commit message</Label>
            <div className="flex gap-1">
              <Input value={b.commitMsg} onChange={(e) => setB({ ...b, commitMsg: e.target.value })} className="h-8 text-xs" placeholder="feat: add login" />
              <Button size="sm" onClick={() => b.commitMsg && run(`git commit -m "${b.commitMsg.replace(/"/g, '\\"')}"`)}>Run</Button>
            </div>
          </div>
          <div className="space-y-1">
            <Label className="text-[11px]">New branch</Label>
            <div className="flex gap-1">
              <Input value={b.branch} onChange={(e) => setB({ ...b, branch: e.target.value })} className="h-8 text-xs" placeholder="feature/x" />
              <Button size="sm" onClick={() => b.branch && run(`git switch -c ${b.branch}`)}>Create</Button>
            </div>
          </div>
          <div className="space-y-1">
            <Label className="text-[11px]">Merge branch into HEAD</Label>
            <div className="flex gap-1">
              <Input value={b.mergeTarget} onChange={(e) => setB({ ...b, mergeTarget: e.target.value })} className="h-8 text-xs" placeholder="feature/x" />
              <Button size="sm" onClick={() => b.mergeTarget && run(`git merge --no-ff ${b.mergeTarget}`)}>Merge</Button>
            </div>
          </div>
        </Card>
      )}

      <Card className="p-3 mb-3 bg-amber-500/5 border-amber-500/30">
        <div className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <p>
            Safe simulator. Only <code className="font-mono">git ...</code> is accepted (allowlist).
            Destructive ops (<code>reset --hard</code>, <code>clean -fd</code>, <code>push --force</code>, <code>rebase</code>, <code>filter-*</code>, <code>branch -D</code>)
            require the checkbox above. A real-host mode is intentionally not shipped — see README for the tradeoff.
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
            <input ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKeyDown}
              autoFocus spellCheck={false} className="flex-1 bg-transparent outline-none text-green-100 font-mono text-xs"
              placeholder="git status" />
          </div>
          <div ref={endRef} />
        </div>
      </Card>
    </div>
  );
}
