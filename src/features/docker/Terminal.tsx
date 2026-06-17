import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ExternalLink,
  TerminalSquare,
  BookOpen,
  CheckCircle2,
  Play,
} from "lucide-react";

const LAB_URL = "https://kodekloud.com/studio/labs/docker";

const LAB_STEPS = [
  "Hello Docker",
  "Docker Images",
  "Docker Containers",
  "Docker Volumes",
  "Docker Networking",
  "Docker Compose",
];

export default function Terminal() {
  const [loading, setLoading] = useState(false);

  const handleLaunch = () => {
    setLoading(true);
    // small delay so the user sees feedback before the tab opens
    setTimeout(() => {
      window.open(LAB_URL, "_blank", "noopener,noreferrer");
      setLoading(false);
    }, 300);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-180px)]">
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <div className="flex items-center gap-2">
          <TerminalSquare className="w-4 h-4 text-primary" />
          <h2 className="text-lg font-semibold">Docker Labs</h2>
          <Badge variant="outline">KodeKloud Studio</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            onClick={handleLaunch}
            disabled={loading}
            className="gap-1.5"
          >
            <Play className="w-3.5 h-3.5" />
            {loading ? "Opening…" : "Launch Lab"}
          </Button>
          <Button size="sm" variant="outline" asChild>
            <a href={LAB_URL} target="_blank" rel="noreferrer">
              <ExternalLink className="w-3.5 h-3.5 mr-1" /> Open in new tab
            </a>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 flex-1 min-h-0">
        {/* Left: Info card */}
        <Card className="p-5 flex flex-col gap-4 overflow-auto">
          <div className="flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-primary" />
            <h3 className="font-semibold">Hands-on Docker Labs</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            KodeKloud Studio provides a free, browser-based Docker playground
            with guided labs. A free KodeKloud account is required to start
            labs.
          </p>

          <div className="space-y-2">
            <p className="text-sm font-medium">Lab Curriculum</p>
            <ul className="space-y-1.5">
              {LAB_STEPS.map((step, i) => (
                <li
                  key={step}
                  className="flex items-center gap-2 text-sm text-muted-foreground"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                  <span>
                    Lab {i + 1}: {step}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-auto pt-4 border-t">
            <Button className="w-full gap-2" onClick={handleLaunch} disabled={loading}>
              <Play className="w-4 h-4" />
              {loading ? "Opening KodeKloud…" : "Launch KodeKloud Docker Labs"}
            </Button>
            <p className="text-xs text-muted-foreground text-center mt-2">
              Opens in a new browser tab
            </p>
          </div>
        </Card>

        {/* Right: Preview / embed area — iframe is intentionally omitted because
            KodeKloud sends X-Frame-Options / CSP headers that block embedding.
            We show a branded placeholder instead of a broken frame. */}
        <Card className="lg:col-span-2 flex flex-col items-center justify-center p-8 bg-muted/30 relative overflow-hidden">
          <div className="absolute inset-0 opacity-5 pointer-events-none bg-[radial-gradient(circle_at_center,var(--color-primary)_0,transparent_70%)]" />
          <TerminalSquare className="w-12 h-12 text-primary/40 mb-4" />
          <h3 className="text-xl font-semibold mb-2">KodeKloud Docker Studio</h3>
          <p className="text-sm text-muted-foreground text-center max-w-md mb-6">
            This provider does not allow embedded iframes for security reasons
            (X-Frame-Options / CSP). Click the button below to open the lab
            environment in a new tab.
          </p>
          <Button size="lg" onClick={handleLaunch} disabled={loading} className="gap-2">
            <ExternalLink className="w-4 h-4" />
            {loading ? "Opening…" : "Open KodeKloud Docker Labs"}
          </Button>
        </Card>
      </div>
    </div>
  );
}
