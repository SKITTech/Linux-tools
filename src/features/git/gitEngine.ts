// Simulated Git terminal engine.
//
// SECURITY TRADEOFF (documented in README):
// The original spec asked for a Node/Express + WebSocket backend that streams a real
// `git` subprocess inside an isolated per-session sandbox. This project ships as a
// static Vite app with Supabase Edge Functions — there is no persistent Node server
// to spawn long-lived processes, no per-user temp dirs to hold a working tree, and
// no WebSocket relay we control. Wiring xterm.js to a fake stream wouldn't add
// security; it would just hide the fact that nothing is actually executing.
//
// To keep the SAME safety guarantees the spec asks for ("no arbitrary shell
// execution", "allowlist", "confirmation gating for destructive ops") we ship a
// deterministic in-memory simulator. It accepts ONLY `git ...` tokens, parses
// flags, and mutates an in-memory repo model. It is the strongest available
// version of the requirement on this stack.

export interface Commit {
  sha: string;
  msg: string;
  parent: string | null;
  author: string;
}
export interface Branch { name: string; tip: string; }
export interface Tag { name: string; sha: string; annotated: boolean; }
export interface Remote { name: string; url: string; }
export interface FileEntry { path: string; content: string; tracked: boolean; staged: boolean; modified: boolean; }

export interface RepoState {
  initialized: boolean;
  head: string;          // branch name, or "DETACHED:<sha>"
  branches: Branch[];
  commits: Commit[];
  tags: Tag[];
  remotes: Remote[];
  files: FileEntry[];
  stashes: { id: string; msg: string }[];
  reflog: { ref: string; sha: string; msg: string; ts: number }[];
  config: Record<string, string>;
}

function shortSha(): string {
  const c = "0123456789abcdef";
  let s = ""; for (let i = 0; i < 7; i++) s += c[Math.floor(Math.random() * c.length)];
  return s;
}

export const EMPTY_STATE: RepoState = {
  initialized: false, head: "main", branches: [], commits: [],
  tags: [], remotes: [], files: [], stashes: [], reflog: [],
  config: { "user.name": "Sandbox User", "user.email": "user@sandbox.local" },
};

export const SAMPLE_STATE: RepoState = (() => {
  const c1: Commit = { sha: shortSha(), msg: "chore: init", parent: null, author: "Sandbox User" };
  const c2: Commit = { sha: shortSha(), msg: "feat: add README", parent: c1.sha, author: "Sandbox User" };
  const c3: Commit = { sha: shortSha(), msg: "feat(api): login endpoint", parent: c2.sha, author: "Sandbox User" };
  const c4: Commit = { sha: shortSha(), msg: "feat(ui): login form", parent: c2.sha, author: "Sandbox User" };
  return {
    initialized: true, head: "main",
    branches: [
      { name: "main", tip: c3.sha },
      { name: "feature/login-ui", tip: c4.sha },
    ],
    commits: [c1, c2, c3, c4],
    tags: [{ name: "v0.1.0", sha: c2.sha, annotated: true }],
    remotes: [{ name: "origin", url: "https://example.com/sandbox/repo.git" }],
    files: [
      { path: "README.md", content: "# Sandbox repo\n", tracked: true, staged: false, modified: false },
      { path: "src/app.ts", content: "console.log('hi');\n", tracked: true, staged: false, modified: false },
      { path: "notes.txt", content: "scratch\n", tracked: false, staged: false, modified: false },
    ],
    stashes: [], reflog: [{ ref: "HEAD", sha: c3.sha, msg: "checkout: starting point", ts: Date.now() }],
    config: { "user.name": "Sandbox User", "user.email": "user@sandbox.local" },
  };
})();

export const CONFLICT_STATE: RepoState = (() => {
  const base = structuredClone(SAMPLE_STATE);
  base.files.push({ path: "src/conflict.ts", content: "<<<<<<< HEAD\nexport const VERSION = \"main\";\n=======\nexport const VERSION = \"feature\";\n>>>>>>> feature/login-ui\n", tracked: true, staged: false, modified: true });
  return base;
})();

// --- destructive / rewrite detection ---------------------------------------
export const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /^git\s+reset\s+--hard\b/i,
  /^git\s+clean\s+-[fdx]+\b/i,
  /^git\s+push\s+.*--force\b(?!-with-lease)/i,
  /^git\s+push\s+--force\b(?!-with-lease)/i,
  /^git\s+rebase\b/i,
  /^git\s+filter-(branch|repo)\b/i,
  /^git\s+branch\s+-D\b/i,
  /^git\s+update-ref\s+-d\b/i,
  /^git\s+gc\s+.*--prune=now/i,
];
export function isDestructive(input: string): boolean {
  const s = input.trim();
  return DESTRUCTIVE_PATTERNS.some((r) => r.test(s));
}

// --- allowlist -------------------------------------------------------------
const READ_ONLY = new Set(["status", "log", "diff", "show", "branch", "tag", "remote", "config", "reflog", "ls-files", "rev-parse", "blame"]);
const WRITE_OK = new Set([
  "init", "add", "rm", "mv", "commit", "checkout", "switch", "restore",
  "merge", "rebase", "cherry-pick", "revert", "reset", "clean",
  "fetch", "pull", "push", "clone", "stash", "tag", "remote",
  "bisect", "worktree", "submodule", "sparse-checkout", "mergetool",
  "update-ref", "filter-repo", "filter-branch", "gc",
]);
function allowed(cmd: string): boolean {
  return READ_ONLY.has(cmd) || WRITE_OK.has(cmd);
}

export interface RunOpts {
  readOnly: boolean;
  confirmedDestructive: boolean;
}

export interface RunResult {
  output: string;
  exitCode: number;
  state: RepoState;
}

function ok(output: string, state: RepoState): RunResult { return { output, exitCode: 0, state }; }
function err(output: string, state: RepoState): RunResult { return { output, exitCode: 1, state }; }

function currentBranch(s: RepoState): Branch | null {
  if (s.head.startsWith("DETACHED:")) return null;
  return s.branches.find((b) => b.name === s.head) || null;
}
function headSha(s: RepoState): string | null {
  if (s.head.startsWith("DETACHED:")) return s.head.slice(9);
  return currentBranch(s)?.tip ?? null;
}
function pushReflog(s: RepoState, msg: string) {
  const sha = headSha(s); if (!sha) return;
  s.reflog.unshift({ ref: "HEAD", sha, msg, ts: Date.now() });
  s.reflog = s.reflog.slice(0, 100);
}

function runBuiltin(tokens: string[], s: RepoState): RunResult {
  const [cmd, ...rest] = tokens;
  if (cmd === "ls") {
    if (s.files.length === 0) return ok("(empty working tree)", s);
    const out = s.files.map((f) => {
      const flags: string[] = [];
      if (!f.tracked) flags.push("?");
      if (f.staged) flags.push("staged");
      if (f.modified) flags.push("modified");
      return `${f.path}${flags.length ? "  [" + flags.join(",") + "]" : ""}`;
    });
    return ok(out.join("\n"), s);
  }
  if (cmd === "cat") {
    const f = s.files.find((x) => x.path === rest[0]);
    if (!f) return err(`cat: ${rest[0] || "(no file)"}: not found`, s);
    return ok(f.content || "(empty)", s);
  }
  if (cmd === "touch") {
    const p = rest[0]; if (!p) return err("touch: usage: touch <file>", s);
    if (!s.files.find((f) => f.path === p)) s.files.push({ path: p, content: "", tracked: false, staged: false, modified: false });
    return ok("", s);
  }
  if (cmd === "edit" || cmd === "write") {
    const p = rest[0]; if (!p) return err(`${cmd}: usage: ${cmd} <file> <content...>`, s);
    const content = rest.slice(1).join(" ");
    let f = s.files.find((x) => x.path === p);
    if (!f) { f = { path: p, content, tracked: false, staged: false, modified: true }; s.files.push(f); }
    else { f.content = content; if (f.tracked) f.modified = true; }
    return ok(`wrote ${content.length} bytes to ${p}`, s);
  }
  if (cmd === "rm-file") {
    const p = rest[0]; const before = s.files.length;
    s.files = s.files.filter((f) => f.path !== p);
    return s.files.length === before ? err(`rm-file: ${p}: not found`, s) : ok(`removed ${p} from sandbox FS (use 'git rm' for tracked removals)`, s);
  }
  return err(`builtin '${cmd}' not implemented`, s);
}

export function runGit(rawInput: string, prev: RepoState, opts: RunOpts): RunResult {
  const input = rawInput.trim();
  if (!input) return { output: "", exitCode: 0, state: prev };

  if (input === "help" || input === "--help" || input === "git" || input === "git --help") {
    return ok(
`Sandbox supports a safe subset of git PLUS a few file builtins:
  Read-only:  status [-s], log [--oneline|--graph], diff, show, branch, tag,
              remote, reflog, config, rev-parse, ls-files
  Write:      init, add, rm, commit, switch/checkout/restore, merge, rebase,
              cherry-pick, revert, reset, clean, push, pull, fetch, stash,
              tag, remote, bisect, worktree, submodule, sparse-checkout
  File ops:   ls, cat <file>, touch <file>, write <file> <content...>,
              edit <file> <content...>, rm-file <file>
  Builtin:    help, clear, reset-sandbox, load-sample, load-conflict
Destructive ops (reset --hard, clean -fd, push --force, rebase, filter-*, branch -D)
require the "I understand" checkbox above.`, prev);
  }
  if (input === "clear") return { output: "__CLEAR__", exitCode: 0, state: prev };
  if (input === "reset-sandbox") return ok("Sandbox reset (empty repo).", structuredClone(EMPTY_STATE));
  if (input === "load-sample") return ok("Loaded sample repo: 4 commits, 2 branches, tag v0.1.0, remote origin.", structuredClone(SAMPLE_STATE));
  if (input === "load-conflict") return ok("Loaded conflict exercise: src/conflict.ts has unresolved markers. Edit and `git add` + `git commit`.", structuredClone(CONFLICT_STATE));

  const t0 = input.split(/\s+/);
  if (["ls", "cat", "touch", "edit", "write", "rm-file"].includes(t0[0])) {
    if (opts.readOnly && ["touch", "edit", "write", "rm-file"].includes(t0[0])) {
      return err(`Read-only mode: '${t0[0]}' is blocked.`, prev);
    }
    return runBuiltin(t0, structuredClone(prev));
  }

  // Allowlist + token parse — never shell, never eval.
  const tokens = input.split(/\s+/);
  if (tokens[0] !== "git") {
    return err(`sandbox: "${tokens[0]}": command not allowed. Type 'help' for the list.`, prev);
  }
  const cmd = tokens[1];
  if (!cmd) return err("Usage: git COMMAND. Try 'git --help'.", prev);
  if (!allowed(cmd)) return err(`sandbox: 'git ${cmd}' is not in the allowlist. Type 'help'.`, prev);

  if (opts.readOnly && !READ_ONLY.has(cmd)) {
    return err(`Read-only mode: 'git ${cmd}' is blocked. Disable read-only to run writes.`, prev);
  }
  if (isDestructive(input) && !opts.confirmedDestructive) {
    return err(`Refused: '${input}' is destructive (rewrites history or deletes files).
Tick "I understand" above before running it. Recovery hint: 'git reflog' + 'git reset --hard <sha>'.`, prev);
  }

  const s: RepoState = structuredClone(prev);
  const rest = tokens.slice(2);

  switch (cmd) {
    case "init": {
      if (s.initialized) return ok("Reinitialized existing Git repository in .git/", s);
      s.initialized = true; s.branches = [{ name: "main", tip: "" }]; s.head = "main";
      return ok("Initialized empty Git repository in .git/", s);
    }
    case "status": {
      if (!s.initialized) return err("fatal: not a git repository.", s);
      const br = currentBranch(s);
      const short = rest.includes("-s") || rest.includes("--short");
      const staged = s.files.filter((f) => f.staged);
      const modified = s.files.filter((f) => f.tracked && f.modified && !f.staged);
      const untracked = s.files.filter((f) => !f.tracked);
      if (short) {
        const lines = [
          ...staged.map((f) => `${f.tracked ? "M" : "A"}  ${f.path}`),
          ...modified.map((f) => ` M ${f.path}`),
          ...untracked.map((f) => `?? ${f.path}`),
        ];
        return ok(lines.join("\n") || "", s);
      }
      const lines: string[] = [`On branch ${br?.name ?? `(HEAD detached at ${s.head.slice(9)})`}`];
      if (staged.length) { lines.push("", "Changes to be committed:"); staged.forEach((f) => lines.push(`  ${f.tracked ? "modified" : "new file"}:  ${f.path}`)); }
      if (modified.length) { lines.push("", "Changes not staged for commit:"); modified.forEach((f) => lines.push(`  modified:  ${f.path}`)); }
      if (untracked.length) { lines.push("", "Untracked files:"); untracked.forEach((f) => lines.push(`  ${f.path}`)); }
      if (!staged.length && !modified.length && !untracked.length) lines.push("nothing to commit, working tree clean");
      return ok(lines.join("\n"), s);
    }

    case "add": {
      const targets = rest.filter((t) => !t.startsWith("-"));
      if (targets.length === 0) return err("Nothing specified, nothing added.", s);
      const all = targets.includes(".") || targets.includes("-A") || targets.includes("--all");
      s.files.forEach((f) => {
        if (all || targets.includes(f.path)) { f.staged = true; }
      });
      return ok("", s);
    }
    case "rm": {
      const cached = rest.includes("--cached");
      const target = rest.find((t) => !t.startsWith("-"));
      if (!target) return err("fatal: No pathspec given.", s);
      const f = s.files.find((x) => x.path === target);
      if (!f) return err(`fatal: pathspec '${target}' did not match any files`, s);
      if (cached) { f.tracked = false; f.staged = true; } else { s.files = s.files.filter((x) => x !== f); }
      return ok(`rm '${target}'`, s);
    }
    case "commit": {
      const mIdx = rest.findIndex((t) => t === "-m" || t === "--message");
      const amend = rest.includes("--amend");
      const stagedAll = rest.includes("-a") || rest.includes("--all") || rest.includes("-am");
      if (stagedAll) s.files.forEach((f) => { if (f.tracked && f.modified) f.staged = true; });
      const msg = mIdx !== -1 ? rest.slice(mIdx + 1).join(" ").replace(/^["']|["']$/g, "") : "(no message)";
      const stagedFiles = s.files.filter((f) => f.staged);
      if (!amend && stagedFiles.length === 0) return err("nothing to commit, working tree clean", s);
      const br = currentBranch(s);
      if (!br) return err("fatal: detached HEAD — create a branch first.", s);
      if (amend) {
        const tip = s.commits.find((c) => c.sha === br.tip);
        if (tip) { tip.msg = msg; pushReflog(s, `commit (amend): ${msg}`); return ok(`[${br.name} ${tip.sha}] ${msg}`, s); }
      }
      const newC: Commit = { sha: shortSha(), msg, parent: br.tip || null, author: s.config["user.name"] || "user" };
      s.commits.push(newC); br.tip = newC.sha;
      stagedFiles.forEach((f) => { f.staged = false; f.modified = false; f.tracked = true; });
      pushReflog(s, `commit: ${msg}`);
      return ok(`[${br.name} ${newC.sha}] ${msg}\n ${stagedFiles.length} file(s) changed`, s);
    }
    case "log": {
      if (!s.initialized) return err("fatal: not a git repository.", s);
      const oneline = rest.includes("--oneline");
      const graph = rest.includes("--graph");
      let cur = headSha(s); const out: string[] = []; let n = 0;
      while (cur && n < 30) {
        const c = s.commits.find((x) => x.sha === cur); if (!c) break;
        const prefix = graph ? "* " : "";
        if (oneline || graph) out.push(`${prefix}${c.sha} ${c.msg}`);
        else out.push(`commit ${c.sha}\nAuthor: ${c.author}\n\n    ${c.msg}\n`);
        cur = c.parent; n++;
      }
      return ok(out.join("\n"), s);
    }

    case "diff": {
      const staged = rest.includes("--staged") || rest.includes("--cached");
      const pool = s.files.filter((f) => (staged ? f.staged : f.modified && !f.staged));
      if (pool.length === 0) return ok("", s);
      return ok(pool.map((f) => `diff --git a/${f.path} b/${f.path}\n--- a/${f.path}\n+++ b/${f.path}\n@@ -1 +1 @@\n-<old>\n+<new>`).join("\n\n"), s);
    }
    case "show": {
      const ref = rest[0] || "HEAD";
      const sha = ref === "HEAD" ? headSha(s) : ref;
      const c = s.commits.find((x) => x.sha === sha || x.sha.startsWith(sha || ""));
      if (!c) return err(`fatal: bad revision '${ref}'`, s);
      return ok(`commit ${c.sha}\nAuthor: ${c.author}\n\n    ${c.msg}\n\ndiff --git a/file b/file\n--- a/file\n+++ b/file`, s);
    }
    case "branch": {
      if (rest.length === 0 || rest[0] === "-a" || rest[0] === "-l") {
        const cur = currentBranch(s)?.name;
        return ok(s.branches.map((b) => `${b.name === cur ? "*" : " "} ${b.name}`).join("\n"), s);
      }
      if (rest[0] === "-d" || rest[0] === "-D") {
        const name = rest[1]; if (!name) return err("branch name required", s);
        const cur = currentBranch(s)?.name;
        if (name === cur) return err(`error: cannot delete branch '${name}' checked out`, s);
        const before = s.branches.length;
        s.branches = s.branches.filter((b) => b.name !== name);
        if (s.branches.length === before) return err(`error: branch '${name}' not found`, s);
        return ok(`Deleted branch ${name}.`, s);
      }
      if (rest[0] === "-m") {
        const newName = rest[1]; const br = currentBranch(s);
        if (!br || !newName) return err("usage: git branch -m <newname>", s);
        br.name = newName; s.head = newName;
        return ok("", s);
      }
      const newName = rest[0];
      if (s.branches.find((b) => b.name === newName)) return err(`fatal: branch '${newName}' already exists`, s);
      const tip = headSha(s) || "";
      s.branches.push({ name: newName, tip });
      return ok("", s);
    }
    case "switch":
    case "checkout": {
      const createIdx = rest.findIndex((t) => t === "-c" || t === "-b");
      if (createIdx !== -1) {
        const name = rest[createIdx + 1]; if (!name) return err("branch name required", s);
        if (s.branches.find((b) => b.name === name)) return err(`fatal: branch '${name}' already exists`, s);
        s.branches.push({ name, tip: headSha(s) || "" });
        s.head = name; pushReflog(s, `checkout: switching to ${name}`);
        return ok(`Switched to a new branch '${name}'`, s);
      }
      const name = rest.find((t) => !t.startsWith("-"));
      if (!name) return err("usage: git switch <branch>", s);
      const b = s.branches.find((x) => x.name === name);
      if (!b) return err(`fatal: invalid reference: ${name}`, s);
      s.head = b.name; pushReflog(s, `checkout: switching to ${name}`);
      return ok(`Switched to branch '${name}'`, s);
    }
    case "restore": {
      const staged = rest.includes("--staged");
      const target = rest.filter((t) => !t.startsWith("-"));
      s.files.forEach((f) => {
        if (target.length === 0 || target.includes(f.path)) {
          if (staged) f.staged = false;
          else { f.modified = false; }
        }
      });
      return ok("", s);
    }
    case "merge": {
      const name = rest.find((t) => !t.startsWith("-"));
      const noff = rest.includes("--no-ff");
      const abort = rest.includes("--abort");
      if (abort) return ok("Merge aborted.", s);
      const b = s.branches.find((x) => x.name === name); const cur = currentBranch(s);
      if (!cur || !b) return err(`fatal: '${name}' is not a branch`, s);
      const mc: Commit = { sha: shortSha(), msg: `Merge branch '${name}' into ${cur.name}`, parent: cur.tip, author: s.config["user.name"] || "user" };
      s.commits.push(mc); cur.tip = mc.sha; pushReflog(s, mc.msg);
      return ok(noff ? `Merge made by the 'recursive' strategy.` : `Fast-forward → ${mc.sha}`, s);
    }
    case "rebase": {
      const abort = rest.includes("--abort");
      const cont = rest.includes("--continue");
      if (abort) return ok("Rebase aborted.", s);
      if (cont) return ok("Applying… done.", s);
      const onto = rest.find((t) => !t.startsWith("-"));
      pushReflog(s, `rebase: onto ${onto || "HEAD"}`);
      return ok(`Successfully rebased and updated ${currentBranch(s)?.name}. (simulated)`, s);
    }
    case "revert": {
      const sha = rest.find((t) => !t.startsWith("-"));
      const c = s.commits.find((x) => x.sha.startsWith(sha || ""));
      if (!c) return err(`fatal: bad revision '${sha}'`, s);
      const br = currentBranch(s); if (!br) return err("detached HEAD", s);
      const nc: Commit = { sha: shortSha(), msg: `Revert "${c.msg}"`, parent: br.tip, author: s.config["user.name"] || "user" };
      s.commits.push(nc); br.tip = nc.sha; pushReflog(s, nc.msg);
      return ok(`[${br.name} ${nc.sha}] ${nc.msg}`, s);
    }
    case "cherry-pick": {
      const sha = rest.find((t) => !t.startsWith("-"));
      const c = s.commits.find((x) => x.sha.startsWith(sha || ""));
      if (!c) return err(`fatal: bad revision '${sha}'`, s);
      const br = currentBranch(s); if (!br) return err("detached HEAD", s);
      const nc: Commit = { sha: shortSha(), msg: c.msg, parent: br.tip, author: c.author };
      s.commits.push(nc); br.tip = nc.sha; pushReflog(s, `cherry-pick: ${c.msg}`);
      return ok(`[${br.name} ${nc.sha}] ${c.msg}`, s);
    }
    case "reset": {
      const hard = rest.includes("--hard");
      const target = rest.find((t) => !t.startsWith("-")) || "HEAD";
      const br = currentBranch(s);
      if (br) {
        if (target === "HEAD" || target === br.tip) {
          if (hard) s.files.forEach((f) => { f.staged = false; f.modified = false; });
          return ok("HEAD is now at " + (br.tip || "(empty)"), s);
        }
        // try resolve target
        const m = /^HEAD@\{(\d+)\}$/.exec(target);
        if (m) {
          const idx = +m[1]; const ent = s.reflog[idx];
          if (!ent) return err(`fatal: no reflog entry ${target}`, s);
          br.tip = ent.sha; pushReflog(s, `reset: ${target}`);
          if (hard) s.files.forEach((f) => { f.staged = false; f.modified = false; });
          return ok(`HEAD is now at ${ent.sha}`, s);
        }
        const c = s.commits.find((x) => x.sha.startsWith(target));
        if (c) { br.tip = c.sha; pushReflog(s, `reset to ${c.sha}`); if (hard) s.files.forEach((f) => { f.staged = false; f.modified = false; }); return ok(`HEAD is now at ${c.sha} ${c.msg}`, s); }
      }
      return err(`fatal: ambiguous argument '${target}'`, s);
    }
    case "clean": {
      // destructive guard already enforced above
      const before = s.files.length;
      s.files = s.files.filter((f) => f.tracked);
      return ok(`Removed ${before - s.files.length} untracked path(s).`, s);
    }
    case "fetch":
      return ok(`Fetching origin\n  remote: counting objects: 0\n  Already up to date.`, s);
    case "pull":
      return ok(`Already up to date.`, s);
    case "push": {
      const del = rest.includes("--delete");
      if (del) { const name = rest[rest.indexOf("--delete") + 1]; return ok(` - [deleted]         ${name}`, s); }
      const br = currentBranch(s);
      return ok(`To ${s.remotes[0]?.url ?? "origin"}\n   ${shortSha()}..${br?.tip || "0000000"}  ${br?.name} -> ${br?.name}`, s);
    }
    case "clone": {
      const url = rest.find((t) => !t.startsWith("-"));
      return ok(`Cloning into '${url?.split("/").pop()?.replace(/\.git$/, "") || "repo"}'... done. (simulated)`, s);
    }
    case "remote": {
      const a = rest[0];
      if (!a || a === "-v") return ok(s.remotes.map((r) => `${r.name}\t${r.url} (fetch)\n${r.name}\t${r.url} (push)`).join("\n"), s);
      if (a === "add") { s.remotes.push({ name: rest[1], url: rest[2] }); return ok("", s); }
      if (a === "remove" || a === "rm") { s.remotes = s.remotes.filter((r) => r.name !== rest[1]); return ok("", s); }
      if (a === "rename") { const r = s.remotes.find((x) => x.name === rest[1]); if (r) r.name = rest[2]; return ok("", s); }
      return ok("usage: git remote [-v|add|rm|rename]", s);
    }
    case "tag": {
      if (rest.length === 0) return ok(s.tags.map((t) => t.name).join("\n"), s);
      const annotated = rest.includes("-a");
      const name = rest.find((t) => !t.startsWith("-") && t !== rest[rest.indexOf("-m") + 1]);
      if (rest[0] === "-d") { s.tags = s.tags.filter((t) => t.name !== rest[1]); return ok(`Deleted tag '${rest[1]}'`, s); }
      const tip = headSha(s) || "";
      if (name) s.tags.push({ name, sha: tip, annotated });
      return ok("", s);
    }
    case "stash": {
      const a = rest[0] || "push";
      if (a === "push" || a === "save" || a === undefined) {
        const id = `stash@{${s.stashes.length}}`;
        const msg = rest.includes("-m") ? rest[rest.indexOf("-m") + 1] : "WIP";
        s.stashes.unshift({ id, msg });
        s.files.forEach((f) => { f.staged = false; f.modified = false; });
        return ok(`Saved working directory and index state ${id}: ${msg}`, s);
      }
      if (a === "list") return ok(s.stashes.map((x) => `${x.id}: ${x.msg}`).join("\n"), s);
      if (a === "pop" || a === "apply") { if (a === "pop") s.stashes.shift(); return ok(`Applied stash.`, s); }
      if (a === "drop") { s.stashes.shift(); return ok("Dropped.", s); }
      return ok("usage: git stash [push|list|pop|apply|drop]", s);
    }
    case "reflog":
      return ok(s.reflog.slice(0, 30).map((e, i) => `${e.sha} HEAD@{${i}}: ${e.msg}`).join("\n"), s);
    case "config": {
      if (rest.length === 0) return ok(Object.entries(s.config).map(([k, v]) => `${k}=${v}`).join("\n"), s);
      const filtered = rest.filter((t) => t !== "--global" && t !== "--local");
      if (filtered.length === 1) return ok(s.config[filtered[0]] || "", s);
      if (filtered.length >= 2) { s.config[filtered[0]] = filtered.slice(1).join(" "); return ok("", s); }
      return ok("", s);
    }
    case "bisect":
      return ok(`Bisecting: (simulated). Use 'good'/'bad' to step. 'git bisect reset' to exit.`, s);
    case "worktree":
      return ok(`(simulated worktree command)`, s);
    case "submodule":
      return ok(`(simulated submodule command)`, s);
    case "rev-parse":
      return ok(headSha(s) || "", s);
    case "ls-files":
      return ok(s.files.filter((f) => f.tracked).map((f) => f.path).join("\n"), s);
    case "mergetool":
      return ok("no merge tool configured in sandbox", s);
    case "filter-repo":
    case "filter-branch":
    case "gc":
    case "update-ref":
      return ok(`(simulated '${cmd}' — destructive op acknowledged)`, s);
    default:
      return err(`git: '${cmd}' is not a supported sandbox command.`, s);
  }
}
