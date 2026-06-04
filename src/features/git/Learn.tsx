import { useMemo, useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Check, ChevronRight, ChevronLeft, BookOpen, Copy, AlertCircle, LifeBuoy, Search, X, ListChecks } from "lucide-react";
import { toast } from "sonner";
import { LESSONS } from "./lessons";
import type { Level } from "./types";

const PROGRESS_KEY = "git.learn.completed.v1";
const ACTIVE_KEY = "git.learn.active.v1";
const LEVEL_LABEL: Record<Level, string> = { beginner: "Beginner", intermediate: "Intermediate", advanced: "Advanced" };

export default function Learn() {
  const [activeId, setActiveId] = useState<string>(() => localStorage.getItem(ACTIVE_KEY) || LESSONS[0].id);
  const [completed, setCompleted] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(PROGRESS_KEY) || "[]"); } catch { return []; }
  });
  const [checkpointAnswers, setCheckpointAnswers] = useState<Record<string, number>>({});
  const [search, setSearch] = useState("");

  useEffect(() => { localStorage.setItem(PROGRESS_KEY, JSON.stringify(completed)); }, [completed]);
  useEffect(() => { localStorage.setItem(ACTIVE_KEY, activeId); }, [activeId]);

  const lesson = LESSONS.find((l) => l.id === activeId) || LESSONS[0];
  const lessonIdx = LESSONS.findIndex((l) => l.id === lesson.id);
  const prev = lessonIdx > 0 ? LESSONS[lessonIdx - 1] : null;
  const next = lessonIdx < LESSONS.length - 1 ? LESSONS[lessonIdx + 1] : null;

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return LESSONS;
    return LESSONS.filter((l) => (l.title + " " + l.summary + " " + l.body).toLowerCase().includes(q));
  }, [search]);

  const groups = useMemo(() => {
    const g: Record<Level, typeof LESSONS> = { beginner: [], intermediate: [], advanced: [] };
    filtered.forEach((l) => g[l.level].push(l));
    return g;
  }, [filtered]);

  const toggleComplete = () => {
    setCompleted((c) => c.includes(lesson.id) ? c.filter((x) => x !== lesson.id) : [...c, lesson.id]);
  };
  const cpKey = (qi: number) => `${lesson.id}:${qi}`;

  return (
    <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
      <Card className="col-span-4 lg:col-span-3 overflow-hidden flex flex-col">
        <div className="p-3 border-b border-border/60 space-y-2">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search lessons…" className="h-8 pl-7 pr-7 text-xs" />
            {search && <button onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2"><X className="w-3 h-3 text-muted-foreground" /></button>}
          </div>
          <div className="flex items-center justify-between text-[11px] text-muted-foreground">
            <span>{completed.length} / {LESSONS.length} done</span>
            <span>{Math.round((completed.length / LESSONS.length) * 100)}%</span>
          </div>
          <Progress value={(completed.length / LESSONS.length) * 100} className="h-1" />
        </div>
        <ScrollArea className="flex-1">
          <div className="p-3 space-y-4">
            {(["beginner", "intermediate", "advanced"] as Level[]).map((lv) => groups[lv].length > 0 && (
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
            {filtered.length === 0 && <p className="text-xs text-muted-foreground px-2">No matches.</p>}
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
                <span className="text-[11px] text-muted-foreground">{lessonIdx + 1} / {LESSONS.length}</span>
              </div>
              <Button size="sm" variant={completed.includes(lesson.id) ? "default" : "outline"} onClick={toggleComplete}>
                <Check className="w-4 h-4 mr-1" /> {completed.includes(lesson.id) ? "Completed" : "Mark complete"}
              </Button>
            </div>

            <p className="text-sm text-muted-foreground italic">{lesson.summary}</p>
            <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap text-sm">{lesson.body}</div>

            <section>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold">Try it</h3>
                <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => { navigator.clipboard.writeText(lesson.tryIt.join("\n")); toast.success("All commands copied"); }}>
                  <ListChecks className="w-3.5 h-3.5 mr-1" />Copy all
                </Button>
              </div>
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

            {lesson.recovery && lesson.recovery.length > 0 && (
              <section>
                <h3 className="text-sm font-semibold mb-2 flex items-center gap-2"><LifeBuoy className="w-4 h-4 text-primary" />Recovery</h3>
                <ul className="list-disc list-inside text-sm space-y-1 text-muted-foreground">
                  {lesson.recovery.map((m, i) => <li key={i}>{m}</li>)}
                </ul>
              </section>
            )}

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
                            <button key={ci} disabled={answered}
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

            <div className="flex items-center justify-between pt-4 border-t border-border/60">
              <Button variant="outline" disabled={!prev} onClick={() => prev && setActiveId(prev.id)}>
                <ChevronLeft className="w-4 h-4 mr-1" />{prev ? prev.title : "Previous"}
              </Button>
              <Button variant="outline" disabled={!next} onClick={() => next && setActiveId(next.id)}>
                {next ? next.title : "Next"}<ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </div>
          </div>
        </ScrollArea>
      </Card>
    </div>
  );
}
