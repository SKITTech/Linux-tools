import { useMemo, useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Check, ChevronRight, BookOpen, Copy, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { LESSONS } from "./lessons";
import type { Level } from "./types";

const PROGRESS_KEY = "docker.learn.completed.v1";

const LEVEL_LABEL: Record<Level, string> = { beginner: "Beginner", intermediate: "Intermediate", advanced: "Advanced" };

export default function Learn() {
  const [activeId, setActiveId] = useState<string>(LESSONS[0].id);
  const [completed, setCompleted] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(PROGRESS_KEY) || "[]"); } catch { return []; }
  });
  const [checkpointAnswers, setCheckpointAnswers] = useState<Record<string, number>>({});

  useEffect(() => { localStorage.setItem(PROGRESS_KEY, JSON.stringify(completed)); }, [completed]);

  const lesson = LESSONS.find((l) => l.id === activeId)!;
  const groups = useMemo(() => {
    const g: Record<Level, typeof LESSONS> = { beginner: [], intermediate: [], advanced: [] };
    LESSONS.forEach((l) => g[l.level].push(l));
    return g;
  }, []);

  const toggleComplete = () => {
    setCompleted((c) => c.includes(lesson.id) ? c.filter((x) => x !== lesson.id) : [...c, lesson.id]);
  };

  const cpKey = (qi: number) => `${lesson.id}:${qi}`;

  return (
    <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
      <Card className="col-span-4 lg:col-span-3 overflow-hidden">
        <ScrollArea className="h-full">
          <div className="p-3 space-y-4">
            {(["beginner", "intermediate", "advanced"] as Level[]).map((lv) => (
              <div key={lv}>
                <div className="px-2 mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{LEVEL_LABEL[lv]}</div>
                <div className="space-y-1">
                  {groups[lv].map((l) => {
                    const done = completed.includes(l.id);
                    const active = l.id === activeId;
                    return (
                      <button key={l.id} onClick={() => setActiveId(l.id)}
                        className={`w-full text-left text-sm rounded-lg px-3 py-2 transition-colors flex items-start gap-2 ${active ? "bg-primary text-primary-foreground" : "hover:bg-muted/60"}`}>
                        <span className={`mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center shrink-0 ${done ? "bg-success border-success" : active ? "border-primary-foreground/60" : "border-border"}`}>
                          {done && <Check className="w-2.5 h-2.5 text-white" />}
                        </span>
                        <span className="flex-1">{l.title}</span>
                        <ChevronRight className="w-3 h-3 opacity-60 mt-1" />
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </Card>

      <Card className="col-span-8 lg:col-span-9 overflow-hidden">
        <ScrollArea className="h-full">
          <div className="p-6 space-y-5 max-w-3xl">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-primary" />
                <h2 className="text-xl font-bold">{lesson.title}</h2>
                <Badge variant="outline" className="capitalize">{lesson.level}</Badge>
              </div>
              <Button size="sm" variant={completed.includes(lesson.id) ? "default" : "outline"} onClick={toggleComplete}>
                <Check className="w-4 h-4 mr-1" /> {completed.includes(lesson.id) ? "Completed" : "Mark complete"}
              </Button>
            </div>

            <p className="text-sm text-muted-foreground italic">{lesson.summary}</p>

            <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap text-sm">{lesson.body}</div>

            <section>
              <h3 className="text-sm font-semibold mb-2">Try it</h3>
              <div className="space-y-2">
                {lesson.tryIt.map((cmd, i) => (
                  <div key={i} className="rounded-lg border border-border/60 bg-muted/40 flex items-center justify-between gap-2 px-3 py-2">
                    <code className="text-xs font-mono flex-1 overflow-x-auto">{cmd}</code>
                    <Button size="sm" variant="ghost" className="h-7 px-2 shrink-0" onClick={() => { navigator.clipboard.writeText(cmd); toast.success("Copied"); }}>
                      <Copy className="w-3 h-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-sm font-semibold mb-2 flex items-center gap-2"><AlertCircle className="w-4 h-4 text-destructive" />Common mistakes</h3>
              <ul className="list-disc list-inside text-sm space-y-1 text-muted-foreground">
                {lesson.mistakes.map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            </section>

            <section>
              <h3 className="text-sm font-semibold mb-2">Checkpoint</h3>
              <div className="space-y-3">
                {lesson.checkpoints.map((cp, qi) => {
                  const picked = checkpointAnswers[cpKey(qi)];
                  const answered = picked !== undefined;
                  return (
                    <Card key={qi} className="p-3 space-y-2">
                      <div className="text-sm font-medium">{qi + 1}. {cp.q}</div>
                      <div className="grid gap-1.5">
                        {cp.choices.map((c, ci) => {
                          const isCorrect = ci === cp.answer;
                          const isPicked = picked === ci;
                          return (
                            <button key={ci}
                              disabled={answered}
                              onClick={() => setCheckpointAnswers((a) => ({ ...a, [cpKey(qi)]: ci }))}
                              className={`text-left text-sm rounded-md px-3 py-1.5 border transition-colors ${
                                !answered ? "hover:bg-muted/50 border-border" :
                                isCorrect ? "bg-success/20 border-success text-foreground" :
                                isPicked ? "bg-destructive/15 border-destructive" : "border-border opacity-60"
                              }`}>
                              {c}
                            </button>
                          );
                        })}
                      </div>
                      {answered && <p className="text-xs text-muted-foreground">{cp.explain}</p>}
                    </Card>
                  );
                })}
              </div>
            </section>
          </div>
        </ScrollArea>
      </Card>
    </div>
  );
}
