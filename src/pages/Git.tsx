import { useState } from "react";
import { SEO } from "@/components/SEO";
import { Sidebar } from "@/components/Sidebar";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { GitBranch, MessagesSquare, GraduationCap, TerminalSquare, Trophy } from "lucide-react";
import { cn } from "@/lib/utils";
import Ask from "@/features/git/Ask";
import Learn from "@/features/git/Learn";
import Terminal from "@/features/git/Terminal";
import Quiz from "@/features/git/Quiz";

type Tab = "ask" | "learn" | "terminal" | "quiz";

const TABS: { id: Tab; label: string; icon: typeof GitBranch; desc: string }[] = [
  { id: "ask", label: "Ask Git", icon: MessagesSquare, desc: "Q&A with copy-ready commands" },
  { id: "learn", label: "Learn", icon: GraduationCap, desc: "Curriculum & checkpoints" },
  { id: "terminal", label: "Terminal", icon: TerminalSquare, desc: "Safe simulated sandbox" },
  { id: "quiz", label: "Quiz", icon: Trophy, desc: "MCQ with spaced repetition" },
];

export default function Git() {
  const [tab, setTab] = useState<Tab>("ask");

  return (
    <Sidebar>
      <SEO
        title="Git Workspace — Learn, Ask, Practice"
        description="An interactive Git learning workspace: AI Q&A, structured curriculum, a safe terminal sandbox, and a spaced-repetition quiz."
        path="/git"
      />
      <div className="min-h-screen bg-background">
        <header className="border-b border-border/50 bg-gradient-to-br from-primary/5 via-background to-accent/5">
          <div className="container mx-auto px-6 py-6">
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                <GitBranch className="w-5 h-5 text-primary" />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">Git Workspace</h1>
            </div>
            <p className="text-sm text-muted-foreground ml-[52px]">Ask, learn, practise — all in one place.</p>
          </div>
        </header>

        <div className="container mx-auto px-6 py-6 grid grid-cols-12 gap-4">
          <aside className="col-span-12 md:col-span-3 lg:col-span-2">
            <Card className="p-2 space-y-1">
              {TABS.map((t) => {
                const Icon = t.icon;
                const active = tab === t.id;
                return (
                  <Button key={t.id} variant={active ? "default" : "ghost"} className={cn("w-full justify-start gap-2", !active && "text-muted-foreground")}
                    onClick={() => setTab(t.id)}>
                    <Icon className="w-4 h-4" />
                    <span>{t.label}</span>
                  </Button>
                );
              })}
            </Card>
            <p className="text-[11px] text-muted-foreground mt-2 px-1">{TABS.find((x) => x.id === tab)?.desc}</p>
          </aside>

          <section className="col-span-12 md:col-span-9 lg:col-span-10">
            {tab === "ask" && <Ask />}
            {tab === "learn" && <Learn />}
            {tab === "terminal" && <Terminal />}
            {tab === "quiz" && <Quiz />}
          </section>
        </div>
      </div>
    </Sidebar>
  );
}
