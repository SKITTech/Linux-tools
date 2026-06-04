import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ExternalLink, Terminal as TermIcon, Play, RefreshCw } from "lucide-react";

const PWD_URL = "https://labs.play-with-docker.com/";
const KATACODA_ALT = "https://training.play-with-docker.com/";

export default function Terminal() {
  const [started, setStarted] = useState(false);
  const [key, setKey] = useState(0);

  return (
    <div className="flex flex-col h-[calc(100vh-180px)]">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TermIcon className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Docker Playground</h2>
          <Badge variant="outline" className="gap-1">
            <ExternalLink className="w-3 h-3" />
            Play with Docker
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          {started && (
            <Button size="sm" variant="outline" onClick={() => setKey((k) => k + 1)}>
              <RefreshCw className="w-3.5 h-3.5 mr-1" />
              Reload
            </Button>
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
            This embeds <strong>Play with Docker</strong> — a free live Docker environment by Docker Inc. You'll need to sign in
            with a Docker Hub account. Each session lasts up to 4 hours. If the embed is blocked by the provider's frame policy,
            use <strong>Open in new tab</strong>. Do not run untrusted images or expose secrets.
          </p>
        </div>
      </Card>

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
            Requires a free Docker Hub account. Sessions and data are managed by play-with-docker.com and are not stored by this
            app.
          </p>
        </Card>
      ) : (
        <Card className="flex-1 overflow-hidden p-0">
          <iframe
            key={key}
            src={PWD_URL}
            title="Play with Docker"
            className="w-full h-full border-0"
            allow="clipboard-read; clipboard-write; fullscreen"
          />
        </Card>
      )}
    </div>
  );
}
