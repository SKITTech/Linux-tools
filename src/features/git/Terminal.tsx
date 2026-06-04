import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { AlertTriangle, RotateCcw, Terminal as TermIcon, GitBranch, Sparkles, Wrench, FileText, Save, Maximize2, Minimize2 } from "lucide-react";
import { toast } from "sonner";
import { runGit, isDestructive, EMPTY_STATE, type RepoState } from "./gitEngine";

const HISTORY_KEY = "git.term.history.v1";
const STATE_KEY = "git.term.state.v1";

export default function Terminal() {
  const [lines, setLines] = useState<{ kind: "prompt" | "out" | "err"; text: string }[]>([
    { kind: "out", text: "Git Sandbox v1.1 — simulated environment (allowlisted git + safe file builtins, no host access).\nType 'help' for the full command list. Try 'load-sample' or 'load-conflict' to start." },
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
  const [editorOpen, setEditorOpen] = useState(false);
  const [editPath, setEditPath] = useState("");
  const [editContent, setEditContent] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
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
    next.push({ kind: result.exitCode === 0 ? "out" : "err", text: result.output || "(ok)" });
    setLines(next); setState(result.state);
    setHistory((h) => [...h, cmd]); setHistIdx(-1); setInput("");
    setTimeout(() => inputRef.current?.focus(), 0);
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
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault(); setLines([]);
    }
  }

  function resetSandbox() {
    setState(structuredClone(EMPTY_STATE));
    setLines([{ kind: "out", text: "Sandbox reset to empty repo state." }]);
    toast.success("Sandbox reset");
  }

  function openEditor(path: string) {
    const f = state.files.find((x) => x.path === path);
    setEditPath(path);
    setEditContent(f?.content || "");
    setEditorOpen(true);
  }

  function saveEditor() {
    if (!editPath.trim()) { toast.error("File path required"); return; }
    // Use the safe builtin to write
    const safe = editContent.replace(/\n/g, " \\n ");
    // Update state directly to preserve newlines (bypassing terminal tokenizer)
    setState((s) => {
      const ns = structuredClone(s);
      const f = ns.files.find((x) => x.path === editPath);
      if (f) { f.content = editContent; if (f.tracked) f.modified = true; }
      else ns.files.push({ path: editPath, content: editContent, tracked: false, staged: false, modified: true });
      return ns;
    });
    setLines((l) => [...l, { kind: "prompt", text: `$ edit ${editPath}` }, { kind: "out", text: `wrote ${editContent.length} bytes to ${editPath}` }]);
    toast.success("Saved");
    setEditorOpen(false);
    // suppress unused warning
    void safe;
  }

  const branchName = state.head.startsWith("DETACHED:") ? `(detached ${state.head.slice(9)})` : state.head;

  return (
    <div className={fullscreen ? "fixed inset-0 z-50 bg-background p-4 flex flex-col" : "flex flex-col h-[calc(100vh-180px)]"}>
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TermIcon className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Sandbox Terminal</h2>
          <Badge variant="outline" className="gap-1"><AlertTriangle className="w-3 h-3" />Simulated</Badge>
          <Badge variant="secondary" className="gap-1"><GitBranch className="w-3 h-3" />{branchName}</Badge>
          <Badge variant="outline" className="text-[10px]">{state.files.length} files · {state.commits.length} commits</Badge>
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
          <Button size="sm" variant="outline" onClick={() => setFullscreen((v) => !v)}>
            {fullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </Button>
          <Button size="sm" variant="outline" onClick={resetSandbox}><RotateCcw className="w-3.5 h-3.5 mr-1" />Reset</Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-3">
        <Button size="sm" variant="outline" onClick={() => run("load-sample")}><Sparkles className="w-3.5 h-3.5 mr-1" />Sample repo</Button>
        <Button size="sm" variant="outline" onClick={() => run("load-conflict")}>Conflict exercise</Button>
        <Button size="sm" variant="outline" onClick={() => run("git status")}>status</Button>
        <Button size="sm" variant="outline" onClick={() => run("git status -s")}>status -s</Button>
        <Button size="sm" variant="outline" onClick={() => run("git branch -a")}>branches</Button>
        <Button size="sm" variant="outline" onClick={() => run("git log --oneline --graph")}>log --graph</Button>
        <Button size="sm" variant="outline" onClick={() => run("git reflog")}>reflog</Button>
        <Button size="sm" variant="outline" onClick={() => run("ls")}>ls</Button>
        <Button size="sm" variant={builderOpen ? "default" : "outline"} onClick={() => setBuilderOpen((v) => !v)}><Wrench className="w-3.5 h-3.5 mr-1" />Builder</Button>
        <Button size="sm" variant={editorOpen ? "default" : "outline"} onClick={() => { setEditorOpen(true); if (!editPath) setEditPath("README.md"); }}><FileText className="w-3.5 h-3.5 mr-1" />Editor</Button>
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

      {editorOpen && (
        <Card className="p-3 mb-3 space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <Label className="text-[11px]">File</Label>
            <Input value={editPath} onChange={(e) => setEditPath(e.target.value)} className="h-8 text-xs flex-1 min-w-[180px]" placeholder="src/app.ts" />
            <select className="h-8 text-xs rounded-md border border-border bg-background px-2"
              value=""
              onChange={(e) => { if (e.target.value) openEditor(e.target.value); }}>
              <option value="">Open existing…</option>
              {state.files.map((f) => <option key={f.path} value={f.path}>{f.path}</option>)}
            </select>
            <Button size="sm" onClick={saveEditor}><Save className="w-3.5 h-3.5 mr-1" />Save</Button>
            <Button size="sm" variant="outline" onClick={() => { run(`git add ${editPath}`); }}>Stage</Button>
            <Button size="sm" variant="ghost" onClick={() => setEditorOpen(false)}>Close</Button>
          </div>
          <Textarea value={editContent} onChange={(e) => setEditContent(e.target.value)} className="min-h-[140px] font-mono text-xs" placeholder="// file content…" />
        </Card>
      )}

      <Card className="p-3 mb-3 bg-amber-500/5 border-amber-500/30">
        <div className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <p>
            Safe simulator: only <code className="font-mono">git&nbsp;…</code> and a few file builtins (<code>ls</code>, <code>cat</code>, <code>edit</code>, <code>touch</code>, <code>write</code>) are accepted (allowlist).
            Destructive ops (<code>reset --hard</code>, <code>clean -fd</code>, <code>push --force</code>, <code>rebase</code>, <code>filter-*</code>, <code>branch -D</code>) require the checkbox above. Tip: <kbd className="px-1 rounded border">↑</kbd>/<kbd className="px-1 rounded border">↓</kbd> for history, <kbd className="px-1 rounded border">Ctrl+L</kbd> to clear.
          </p>
        </div>
      </Card>

      <Card className="flex-1 overflow-hidden bg-black text-green-400 font-mono text-xs">
        <div className="h-full overflow-y-auto p-4 space-y-1" onClick={() => inputRef.current?.focus()}>
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
