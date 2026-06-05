import { useEffect, useMemo, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import {
  AlertTriangle,
  ExternalLink,
  Terminal as TermIcon,
  Play,
  RefreshCw,
  Maximize2,
  Minimize2,
  Copy,
  CheckCircle2,
  Circle,
  ChevronLeft,
  ChevronRight,
  BookOpen,
  ListChecks,
  Lightbulb,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

/**
 * Docker Playground — KodeKloud-style lab layout.
 * Left: lesson/task panel with step-by-step instructions and copyable commands.
 * Right: live in-browser Docker host (Play with Docker) for real `docker` execution.
 * Falls back to "Open in new tab" if the provider blocks the iframe.
 */

const PROVIDERS = [
  { id: "pwd", label: "Play with Docker", url: "https://labs.play-with-docker.com/", note: "Free Docker Hub login • 4h sessions" },
  { id: "killercoda", label: "Killercoda", url: "https://killercoda.com/playgrounds/scenario/docker", note: "No login • short sessions" },
] as const;

type ProviderId = (typeof PROVIDERS)[number]["id"];

type Step = { title: string; body: string; cmd?: string; hint?: string };
type Lab = {
  id: string;
  level: "Beginner" | "Intermediate" | "Advanced";
  title: string;
  objective: string;
  steps: Step[];
};

const LABS: Lab[] = [
  {
    id: "hello",
    level: "Beginner",
    title: "Hello Docker — your first container",
    objective: "Verify the engine, pull an image, and run a container.",
    steps: [
      { title: "Check the Docker version", body: "Confirm the Docker engine is reachable in your sandbox.", cmd: "docker version" },
      { title: "Run the hello-world image", body: "Docker pulls a tiny test image, runs it, and exits.", cmd: "docker run --rm hello-world" },
      { title: "List local images", body: "Inspect what's now cached on the host.", cmd: "docker images" },
    ],
  },
  {
    id: "nginx",
    level: "Beginner",
    title: "Serve a website with Nginx",
    objective: "Run a detached web server and reach it from the browser.",
    steps: [
      { title: "Start Nginx detached", body: "Map port 80 in the container to 8080 on the host.", cmd: "docker run -d --name web -p 8080:80 nginx:alpine" },
      { title: "List running containers", body: "Confirm the container is healthy.", cmd: "docker ps" },
      { title: "Curl the welcome page", body: "On Play with Docker, click the '8080' badge that appears next to the node.", cmd: "curl -I http://localhost:8080" },
      { title: "Tail the access log", body: "Watch requests as you reload the page.", cmd: "docker logs -f web", hint: "Press Ctrl+C to stop following." },
      { title: "Clean up", body: "Stop and remove the container.", cmd: "docker rm -f web" },
    ],
  },
  {
    id: "exec",
    level: "Intermediate",
    title: "Shell into a container & inspect it",
    objective: "Practise exec, inspect, stats, and copying files in/out.",
    steps: [
      { title: "Run an Alpine container", body: "Keep it alive so we can poke at it.", cmd: "docker run -d --name box alpine sleep 3600" },
      { title: "Open an interactive shell", body: "Use exec with -it to attach a TTY.", cmd: "docker exec -it box sh" },
      { title: "Inside the container", body: "Try `ls /`, `cat /etc/os-release`, then `exit`.", hint: "Type `exit` to return to the host." },
      { title: "Inspect the container", body: "See network, mounts, env, and state as JSON.", cmd: "docker inspect box | head -40" },
      { title: "Live resource stats", body: "Cgroup-backed live CPU/MEM.", cmd: "docker stats --no-stream box" },
      { title: "Copy a file out", body: "Pull /etc/hostname to the host.", cmd: "docker cp box:/etc/hostname ./hostname.txt" },
      { title: "Cleanup", body: "Remove the running container.", cmd: "docker rm -f box" },
    ],
  },
  {
    id: "build",
    level: "Intermediate",
    title: "Build a custom image with a Dockerfile",
    objective: "Author a Dockerfile, build, tag, and run your own image.",
    steps: [
      { title: "Make a workspace", body: "Create a folder and move in.", cmd: "mkdir myapp && cd myapp" },
      { title: "Write index.html", body: "Tiny static page to ship.", cmd: "echo '<h1>Hello from my image</h1>' > index.html" },
      { title: "Write the Dockerfile", body: "Base off nginx:alpine and copy the page in.", cmd: "printf 'FROM nginx:alpine\\nCOPY index.html /usr/share/nginx/html/index.html\\n' > Dockerfile" },
      { title: "Build the image", body: "Tag it so you can reference it later.", cmd: "docker build -t myapp:1.0 ." },
      { title: "Run it", body: "Expose on port 8080.", cmd: "docker run -d --name myapp -p 8080:80 myapp:1.0" },
      { title: "Verify", body: "Hit the page from inside the sandbox.", cmd: "curl -s http://localhost:8080" },
    ],
  },
  {
    id: "compose",
    level: "Advanced",
    title: "Multi-service stack with Compose",
    objective: "Spin up Nginx + Redis with docker compose, then tear it down.",
    steps: [
      { title: "Create the project", body: "Move into a fresh folder.", cmd: "mkdir stack && cd stack" },
      {
        title: "Write compose.yaml",
        body: "Two services, a shared network, and a named volume.",
        cmd: "cat > compose.yaml <<'YML'\nservices:\n  web:\n    image: nginx:alpine\n    ports: [\"8080:80\"]\n  cache:\n    image: redis:7-alpine\n    volumes: [\"data:/data\"]\nvolumes:\n  data:\nYML",
      },
      { title: "Start the stack", body: "Detached, with health logs.", cmd: "docker compose up -d" },
      { title: "List services", body: "Confirm both are running.", cmd: "docker compose ps" },
      { title: "Tail logs", body: "Follow combined output.", cmd: "docker compose logs -f" },
      { title: "Stop & remove", body: "Keep the named volume.", cmd: "docker compose down" },
    ],
  },
];

const PROGRESS_KEY = "docker.labs.progress.v1";

function loadProgress(): Record<string, number[]> {
  try {
    return JSON.parse(localStorage.getItem(PROGRESS_KEY) || "{}");
  } catch {
    return {};
  }
}
function saveProgress(p: Record<string, number[]>) {
  localStorage.setItem(PROGRESS_KEY, JSON.stringify(p));
}

export default function Terminal() {
  const [provider, setProvider] = useState<ProviderId>("pwd");
  const providerUrl = PROVIDERS.find((p) => p.id === provider)!.url;

  const [started, setStarted] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [blocked, setBlocked] = useState<null | boolean>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const [labId, setLabId] = useState<string>(LABS[0].id);
  const lab = useMemo(() => LABS.find((l) => l.id === labId)!, [labId]);
  const [progress, setProgressState] = useState<Record<string, number[]>>(() => loadProgress());
  const done = progress[lab.id] ?? [];
  const pct = Math.round((done.length / lab.steps.length) * 100);

  useEffect(() => {
    if (!started) {
      setBlocked(null);
      return;
    }
    setBlocked(null);
    const t = window.setTimeout(() => setBlocked((b) => (b === null ? true : b)), 8000);
    return () => window.clearTimeout(t);
  }, [started, reloadKey, provider]);

  // When provider changes after starting, force a clean iframe load.
  useEffect(() => {
    if (started) setReloadKey((k) => k + 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  function toggleStep(idx: number) {
    setProgressState((prev) => {
      const cur = new Set(prev[lab.id] ?? []);
      cur.has(idx) ? cur.delete(idx) : cur.add(idx);
      const next = { ...prev, [lab.id]: [...cur].sort((a, b) => a - b) };
      saveProgress(next);
      return next;
    });
  }

  function copyCmd(c: string) {
    navigator.clipboard.writeText(c);
    toast.success("Copied — paste in the Docker terminal");
  }

  function resetLab() {
    setProgressState((prev) => {
      const next = { ...prev, [lab.id]: [] };
      saveProgress(next);
      return next;
    });
    toast.success("Lab progress reset");
  }

  return (
    <div className={fullscreen ? "fixed inset-0 z-50 bg-background p-4 flex flex-col" : "flex flex-col h-[calc(100vh-180px)]"}>
      {/* Top toolbar */}
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <TermIcon className="w-4 h-4 text-primary shrink-0" />
          <h2 className="text-lg font-semibold truncate">Docker Lab</h2>
          <Badge variant="outline" className="gap-1">
            <ExternalLink className="w-3 h-3" />
            Live sandbox
          </Badge>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex rounded-md border border-border bg-muted/40 p-0.5">
            {PROVIDERS.map((p) => (
              <button
                key={p.id}
                onClick={() => setProvider(p.id)}
                className={cn(
                  "px-2.5 py-1 text-xs rounded transition-colors",
                  provider === p.id ? "bg-background shadow-sm font-medium" : "text-muted-foreground hover:text-foreground"
                )}
                title={p.note}
              >
                {p.label}
              </button>
            ))}
          </div>
          {started && (
            <>
              <Button size="sm" variant="outline" onClick={() => setReloadKey((k) => k + 1)}>
                <RefreshCw className="w-3.5 h-3.5 mr-1" />
                Reload
              </Button>
              <Button size="sm" variant="outline" onClick={() => setFullscreen((v) => !v)}>
                {fullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              </Button>
            </>
          )}
          <Button size="sm" variant="outline" asChild>
            <a href={providerUrl} target="_blank" rel="noopener noreferrer">
              Open in new tab <ExternalLink className="w-3.5 h-3.5 ml-1" />
            </a>
          </Button>
        </div>
      </div>

      {/* Split lab layout */}
      <div className="flex-1 grid grid-cols-12 gap-3 min-h-0">
        {/* LEFT — task panel */}
        <Card className="col-span-12 lg:col-span-4 xl:col-span-3 flex flex-col min-h-0 overflow-hidden">
          {/* Lab picker */}
          <div className="p-3 border-b border-border/60 space-y-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              <BookOpen className="w-3 h-3" />
              Choose a lab
            </div>
            <div className="flex flex-wrap gap-1.5">
              {LABS.map((l) => {
                const active = l.id === lab.id;
                const labDone = (progress[l.id]?.length ?? 0) === l.steps.length && l.steps.length > 0;
                return (
                  <button
                    key={l.id}
                    onClick={() => setLabId(l.id)}
                    className={cn(
                      "text-[11px] px-2 py-1 rounded border transition-colors flex items-center gap-1",
                      active
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-muted/40 border-border hover:bg-muted"
                    )}
                  >
                    {labDone && <CheckCircle2 className="w-3 h-3" />}
                    {l.title.split(" — ")[0]}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Objective */}
          <div className="p-3 border-b border-border/60 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <Badge variant="secondary" className="text-[10px]">{lab.level}</Badge>
              <span className="text-[11px] text-muted-foreground">
                {done.length}/{lab.steps.length} done
              </span>
            </div>
            <h3 className="text-sm font-semibold leading-snug">{lab.title}</h3>
            <p className="text-xs text-muted-foreground leading-relaxed flex gap-1.5">
              <ListChecks className="w-3.5 h-3.5 shrink-0 mt-0.5 text-primary" />
              {lab.objective}
            </p>
            <Progress value={pct} className="h-1.5" />
          </div>

          {/* Steps */}
          <ScrollArea className="flex-1">
            <ol className="p-3 space-y-2">
              {lab.steps.map((s, i) => {
                const isDone = done.includes(i);
                return (
                  <li
                    key={i}
                    className={cn(
                      "rounded-md border p-2.5 transition-colors",
                      isDone ? "bg-primary/5 border-primary/30" : "bg-muted/30 border-border"
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <button
                        onClick={() => toggleStep(i)}
                        className="mt-0.5 shrink-0 text-muted-foreground hover:text-primary transition-colors"
                        aria-label={isDone ? "Mark incomplete" : "Mark done"}
                      >
                        {isDone ? <CheckCircle2 className="w-4 h-4 text-primary" /> : <Circle className="w-4 h-4" />}
                      </button>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-semibold flex items-center gap-1.5">
                          <span className="text-muted-foreground">Step {i + 1}.</span> {s.title}
                        </div>
                        <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{s.body}</p>
                        {s.cmd && (
                          <button
                            onClick={() => copyCmd(s.cmd!)}
                            className="mt-1.5 w-full text-left rounded border border-border/60 bg-background hover:bg-muted/50 transition-colors px-2 py-1.5 group"
                          >
                            <div className="flex items-start justify-between gap-1">
                              <code className="text-[11px] font-mono whitespace-pre-wrap break-all">{s.cmd}</code>
                              <Copy className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 shrink-0 mt-0.5" />
                            </div>
                          </button>
                        )}
                        {s.hint && (
                          <div className="mt-1.5 flex gap-1 text-[10px] text-amber-700 dark:text-amber-300">
                            <Lightbulb className="w-3 h-3 shrink-0 mt-0.5" />
                            <span>{s.hint}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
          </ScrollArea>

          {/* Footer actions */}
          <div className="p-2 border-t border-border/60 flex items-center justify-between gap-2">
            <Button size="sm" variant="ghost" onClick={resetLab} className="text-xs">
              Reset
            </Button>
            <div className="flex gap-1">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  const i = LABS.findIndex((l) => l.id === lab.id);
                  setLabId(LABS[(i - 1 + LABS.length) % LABS.length].id);
                }}
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  const i = LABS.findIndex((l) => l.id === lab.id);
                  setLabId(LABS[(i + 1) % LABS.length].id);
                }}
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        </Card>

        {/* RIGHT — live terminal */}
        <div className="col-span-12 lg:col-span-8 xl:col-span-9 flex flex-col min-h-0 gap-2">
          <Card className="p-2.5 bg-amber-500/5 border-amber-500/30">
            <div className="flex gap-2 text-[11px] text-amber-700 dark:text-amber-300">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <p>
                You're using <strong>{PROVIDERS.find((p) => p.id === provider)!.label}</strong> — a real Docker host in your browser.
                Don't paste secrets or run untrusted images. If the embed appears blank, click <strong>Open in new tab</strong>.
              </p>
            </div>
          </Card>

          {!started ? (
            <Card className="flex-1 flex flex-col items-center justify-center p-8 text-center gap-4">
              <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center">
                <Play className="w-6 h-6 text-primary" />
              </div>
              <div className="space-y-1 max-w-md">
                <h3 className="text-lg font-semibold">Launch your Docker lab</h3>
                <p className="text-sm text-muted-foreground">
                  A real Docker engine boots in your browser. Follow the steps on the left — click any
                  command to copy it, then paste into the terminal.
                </p>
              </div>
              <Button onClick={() => setStarted(true)} size="lg">
                <Play className="w-4 h-4 mr-1" />
                Start session
              </Button>
              <p className="text-[11px] text-muted-foreground max-w-md">
                Sessions are managed by {PROVIDERS.find((p) => p.id === provider)!.label} and not stored by this app.
                {provider === "pwd" && " A free Docker Hub login is required."}
              </p>
            </Card>
          ) : (
            <Card className="flex-1 overflow-hidden p-0 relative min-h-[400px]">
              <iframe
                key={`${provider}-${reloadKey}`}
                ref={iframeRef}
                src={providerUrl}
                title={PROVIDERS.find((p) => p.id === provider)!.label}
                className="w-full h-full border-0 bg-black"
                onLoad={() => setBlocked(false)}
                allow="clipboard-read; clipboard-write; fullscreen"
              />
              {blocked && (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-background/95 backdrop-blur p-6 text-center">
                  <AlertTriangle className="w-8 h-8 text-amber-500" />
                  <div className="space-y-1 max-w-md">
                    <h3 className="font-semibold">Embed blocked by the provider</h3>
                    <p className="text-sm text-muted-foreground">
                      Some providers refuse to load inside an iframe (X-Frame-Options). Try the other provider
                      above, or open the session in a new tab — your lab steps still copy commands for you.
                    </p>
                  </div>
                  <div className="flex gap-2 flex-wrap justify-center">
                    <Button asChild>
                      <a href={providerUrl} target="_blank" rel="noopener noreferrer">
                        Open in new tab <ExternalLink className="w-3.5 h-3.5 ml-1" />
                      </a>
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => {
                        setBlocked(null);
                        setReloadKey((k) => k + 1);
                      }}
                    >
                      <RefreshCw className="w-3.5 h-3.5 mr-1" />
                      Retry
                    </Button>
                  </div>
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
