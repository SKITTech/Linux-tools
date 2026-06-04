import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ExternalLink, Terminal as TermIcon, Play, RefreshCw, Maximize2, Minimize2, Copy } from "lucide-react";
import { toast } from "sonner";

const PWD_URL = "https://labs.play-with-docker.com/";
const KATACODA_ALT = "https://training.play-with-docker.com/";

const CHEATSHEET: { group: string; cmds: { c: string; d: string }[] }[] = [
  {
    group: "Quick start",
    cmds: [
      { c: "docker run --rm -p 8080:80 nginx:alpine", d: "Run nginx, expose on :8080" },
      { c: "docker run -d --name api -p 3000:3000 node:20-alpine sleep infinity", d: "Detached container, named 'api'" },
      { c: "docker exec -it api sh", d: "Shell into running container" },
    ],
  },
  {
    group: "Images",
    cmds: [
      { c: "docker pull alpine:latest", d: "Pull an image" },
      { c: "docker images", d: "List local images" },
      { c: "docker image prune", d: "Remove dangling images (safe)" },
    ],
  },
  {
    group: "Compose",
    cmds: [
      { c: "docker compose up -d", d: "Start stack in background" },
      { c: "docker compose ps", d: "Status of services" },
      { c: "docker compose logs -f", d: "Follow logs" },
      { c: "docker compose down", d: "Stop & remove (keeps volumes)" },
    ],
  },
  {
    group: "Debug",
    cmds: [
      { c: "docker stats", d: "Live CPU/MEM per container" },
      { c: "docker inspect <name>", d: "Full JSON config" },
      { c: "docker logs --tail 200 -f <name>", d: "Recent + follow logs" },
    ],
  },
];

export default function Terminal() {
  const [started, setStarted] = useState(false);
  const [key, setKey] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [showCheatsheet, setShowCheatsheet] = useState(false);
  const [blocked, setBlocked] = useState<null | boolean>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Best-effort detection: if the iframe never fires 'load' within 8s after start, mark as likely blocked.
  useEffect(() => {
    if (!started) { setBlocked(null); return; }
    setBlocked(null);
    const t = window.setTimeout(() => setBlocked((b) => (b === null ? true : b)), 8000);
    return () => window.clearTimeout(t);
  }, [started, key]);

  function copyCmd(c: string) {
    navigator.clipboard.writeText(c);
    toast.success("Copied — paste in the Docker terminal");
  }

  return (
    <div className={fullscreen ? "fixed inset-0 z-50 bg-background p-4 flex flex-col" : "flex flex-col h-[calc(100vh-180px)]"}>
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TermIcon className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Docker Playground</h2>
          <Badge variant="outline" className="gap-1">
            <ExternalLink className="w-3 h-3" />
            Play with Docker
          </Badge>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button size="sm" variant={showCheatsheet ? "default" : "outline"} onClick={() => setShowCheatsheet((v) => !v)}>
            Cheatsheet
          </Button>
          {started && (
            <>
              <Button size="sm" variant="outline" onClick={() => setKey((k) => k + 1)}>
                <RefreshCw className="w-3.5 h-3.5 mr-1" />Reload
              </Button>
              <Button size="sm" variant="outline" onClick={() => setFullscreen((v) => !v)}>
                {fullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              </Button>
            </>
          )}
          <Button size="sm" variant="outline" asChild>
            <a href={PWD_URL} target="_blank" rel="noopener noreferrer">
              Open in new tab <ExternalLink className="w-3.5 h-3.5 ml-1" />
            </a>
          </Button>
        </div>
      </div>

      <Card className="p-3 mb-3 bg-amber-500/5 border-amber-500/30">
        <div className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <p>
            Embedded <strong>Play with Docker</strong> — a free live Docker host by Docker Inc. Sign in with a Docker Hub account; sessions last up to 4 hours.
            If the embed appears blank, use <strong>Open in new tab</strong> (some providers block iframes). Do not run untrusted images or expose secrets.
          </p>
        </div>
      </Card>

      {showCheatsheet && (
        <Card className="p-3 mb-3">
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {CHEATSHEET.map((g) => (
              <div key={g.group} className="space-y-1">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{g.group}</div>
                {g.cmds.map((c) => (
                  <button key={c.c} onClick={() => copyCmd(c.c)} className="w-full text-left rounded-md border border-border/60 bg-muted/30 hover:bg-muted/60 transition-colors px-2 py-1.5 group">
                    <div className="flex items-center justify-between gap-1">
                      <code className="text-[11px] font-mono truncate">{c.c}</code>
                      <Copy className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 shrink-0" />
                    </div>
                    <div className="text-[10px] text-muted-foreground">{c.d}</div>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </Card>
      )}

      {!started ? (
        <Card className="flex-1 flex flex-col items-center justify-center p-8 text-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center">
            <Play className="w-6 h-6 text-primary" />
          </div>
          <div className="space-y-1 max-w-md">
            <h3 className="text-lg font-semibold">Launch a live Docker terminal</h3>
            <p className="text-sm text-muted-foreground">
              Spin up a real Docker host in your browser via Play with Docker. Pull images, run containers, and try{" "}
              <code className="font-mono">docker compose</code> on a real engine — no install required.
            </p>
          </div>
          <div className="flex gap-2 flex-wrap justify-center">
            <Button onClick={() => setStarted(true)}>
              <Play className="w-4 h-4 mr-1" />
              Start session
            </Button>
            <Button variant="outline" asChild>
              <a href={KATACODA_ALT} target="_blank" rel="noopener noreferrer">
                Guided tutorials <ExternalLink className="w-3.5 h-3.5 ml-1" />
              </a>
            </Button>
          </div>
          <p className="text-[11px] text-muted-foreground max-w-md">
            Requires a free Docker Hub account. Sessions and data are managed by play-with-docker.com and are not stored by this app.
          </p>
        </Card>
      ) : (
        <Card className="flex-1 overflow-hidden p-0 relative">
          <iframe
            key={key}
            ref={iframeRef}
            src={PWD_URL}
            title="Play with Docker"
            className="w-full h-full border-0"
            onLoad={() => setBlocked(false)}
            allow="clipboard-read; clipboard-write; fullscreen"
          />
          {blocked && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-background/95 backdrop-blur p-6 text-center">
              <AlertTriangle className="w-8 h-8 text-amber-500" />
              <div className="space-y-1 max-w-md">
                <h3 className="font-semibold">Embed blocked by Play with Docker</h3>
                <p className="text-sm text-muted-foreground">Some providers refuse to load inside an iframe (X-Frame-Options). Open the session in a new tab to continue — your cheatsheet still copies commands for you.</p>
              </div>
              <div className="flex gap-2">
                <Button asChild>
                  <a href={PWD_URL} target="_blank" rel="noopener noreferrer">Open in new tab <ExternalLink className="w-3.5 h-3.5 ml-1" /></a>
                </Button>
                <Button variant="outline" onClick={() => { setBlocked(null); setKey((k) => k + 1); }}>
                  <RefreshCw className="w-3.5 h-3.5 mr-1" />Retry
                </Button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
