import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, RotateCcw, Maximize2, Minimize2, TerminalSquare, AlertTriangle } from "lucide-react";

const LAB_URL = "https://kodekloud.com/studio/labs/docker";

export default function Terminal() {
  const [fullscreen, setFullscreen] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [key, setKey] = useState(0);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    setBlocked(false);
    const t = setTimeout(() => {
      try {
        // If the iframe is blocked (X-Frame-Options/CSP), the contentWindow location read throws.
        // We can't reliably detect it, so we offer the fallback button always.
      } catch {
        setBlocked(true);
      }
    }, 4000);
    return () => clearTimeout(t);
  }, [key]);

  return (
    <div className={fullscreen ? "fixed inset-0 z-50 bg-background p-3 flex flex-col" : "flex flex-col h-[calc(100vh-180px)]"}>
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TerminalSquare className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Docker Labs — KodeKloud Studio</h2>
          <Badge variant="outline">Live environment</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => setKey((k) => k + 1)}>
            <RotateCcw className="w-3.5 h-3.5 mr-1" /> Reload
          </Button>
          <Button size="sm" variant="outline" asChild>
            <a href={LAB_URL} target="_blank" rel="noreferrer">
              <ExternalLink className="w-3.5 h-3.5 mr-1" /> Open in new tab
            </a>
          </Button>
          <Button size="sm" variant="outline" onClick={() => setFullscreen((v) => !v)}>
            {fullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </Button>
        </div>
      </div>

      <Card className="p-3 mb-3 bg-amber-500/5 border-amber-500/30">
        <div className="flex gap-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <p>
            KodeKloud Studio is embedded below. A free KodeKloud account may be required to launch labs. If the page does not load (some providers block iframes via X-Frame-Options/CSP), use <strong>Open in new tab</strong>.
          </p>
        </div>
      </Card>

      <Card className="flex-1 overflow-hidden p-0 relative">
        <iframe
          key={key}
          ref={iframeRef}
          src={LAB_URL}
          title="KodeKloud Docker Labs"
          className="w-full h-full border-0"
          allow="clipboard-read; clipboard-write; fullscreen"
          onError={() => setBlocked(true)}
        />
        {blocked && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/95">
            <div className="text-center space-y-3 max-w-md p-6">
              <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
              <h3 className="font-semibold">Embedding blocked</h3>
              <p className="text-sm text-muted-foreground">KodeKloud doesn't allow this page to be embedded. Open it in a new tab instead.</p>
              <Button asChild>
                <a href={LAB_URL} target="_blank" rel="noreferrer">
                  <ExternalLink className="w-4 h-4 mr-1" /> Launch KodeKloud Docker Labs
                </a>
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
