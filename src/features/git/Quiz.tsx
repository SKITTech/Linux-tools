import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Check, X, Flame, Trophy, RotateCcw, Eye, Filter } from "lucide-react";
import { QUESTIONS } from "./questions";
import type { Level, QuizProgress, QuizQuestion } from "./types";

const PROG_KEY = "git.quiz.progress.v1";
const DEFAULT_PROG: QuizProgress = { scoreById: {}, streak: 0, totalCorrect: 0, totalAnswered: 0 };

function nextDue(correct: boolean, prevCorrect: number, prevWrong: number) {
  if (!correct) return Date.now() + 30_000;
  const steps = [60_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000, 24 * 60 * 60_000];
  const idx = Math.min(steps.length - 1, Math.max(0, prevCorrect - prevWrong));
  return Date.now() + steps[idx];
}
function arrayEq(a: number[], b: number[]) {
  if (a.length !== b.length) return false;
  const sa = [...a].sort(); const sb = [...b].sort();
  return sa.every((v, i) => v === sb[i]);
}
export function isAnswerCorrect(q: QuizQuestion, picked: number[]): boolean {
  if (q.type === "multi") return Array.isArray(q.answer) && arrayEq(q.answer as number[], picked);
  return picked.length === 1 && picked[0] === q.answer;
}
function fmtDue(ts: number): string {
  const d = ts - Date.now();
  if (d <= 0) return "due now";
  const m = Math.round(d / 60000);
  if (m < 60) return `in ${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `in ${h}h`;
  return `in ${Math.round(h / 24)}d`;
}
const ALL_TOPICS = Array.from(new Set(QUESTIONS.map((q) => q.topic))).sort();

export default function Quiz() {
  const [level, setLevel] = useState<Level | "all">("all");
  const [topic, setTopic] = useState<string>("all");
  const [reviewMissed, setReviewMissed] = useState(false);
  const [prog, setProg] = useState<QuizProgress>(() => {
    try { return { ...DEFAULT_PROG, ...JSON.parse(localStorage.getItem(PROG_KEY) || "{}") }; } catch { return DEFAULT_PROG; }
  });
  const [picked, setPicked] = useState<number[]>([]);
  const [submitted, setSubmitted] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [currentId, setCurrentId] = useState<string | null>(null);

  useEffect(() => { localStorage.setItem(PROG_KEY, JSON.stringify(prog)); }, [prog]);

  const pool = useMemo(() => QUESTIONS.filter((q) => {
    if (level !== "all" && q.level !== level) return false;
    if (topic !== "all" && q.topic !== topic) return false;
    if (reviewMissed) {
      const s = prog.scoreById[q.id];
      if (!s || s.wrong === 0) return false;
    }
    return true;
  }), [level, topic, reviewMissed, prog]);

  function pickNext(): string | null {
    if (pool.length === 0) return null;
    const now = Date.now();
    const due = pool.filter((q) => { const s = prog.scoreById[q.id]; return s && s.nextDue <= now; });
    const unseen = pool.filter((q) => !prog.scoreById[q.id]);
    const bucket = due.length ? due : unseen.length ? unseen : pool;
    return bucket[Math.floor(Math.random() * bucket.length)].id;
  }

  useEffect(() => { setCurrentId(pickNext()); setPicked([]); setSubmitted(false); setRevealed(false); /* eslint-disable-next-line */ }, [level, topic, reviewMissed]);

  const q = currentId ? QUESTIONS.find((x) => x.id === currentId) : null;
  const stat = q ? prog.scoreById[q.id] : null;

  function toggle(ci: number) {
    if (submitted || !q) return;
    if (q.type === "multi") setPicked((p) => p.includes(ci) ? p.filter((x) => x !== ci) : [...p, ci]);
    else setPicked([ci]);
  }
  function submit() {
    if (!q || picked.length === 0) return;
    const correct = isAnswerCorrect(q, picked);
    setSubmitted(true);
    setProg((p) => {
      const prev = p.scoreById[q.id] || { correct: 0, wrong: 0, lastSeen: 0, nextDue: 0 };
      const nc = correct ? prev.correct + 1 : prev.correct;
      const nw = correct ? prev.wrong : prev.wrong + 1;
      return {
        scoreById: { ...p.scoreById, [q.id]: { correct: nc, wrong: nw, lastSeen: Date.now(), nextDue: nextDue(correct, nc, nw) } },
        streak: correct ? p.streak + 1 : 0,
        totalCorrect: p.totalCorrect + (correct ? 1 : 0),
        totalAnswered: p.totalAnswered + 1,
      };
    });
  }
  function nextQ() { setCurrentId(pickNext()); setPicked([]); setSubmitted(false); setRevealed(false); }
  function reset() { setProg(DEFAULT_PROG); setCurrentId(pickNext()); setPicked([]); setSubmitted(false); setRevealed(false); }
  function reveal() { setRevealed(true); }

  const seen = Object.keys(prog.scoreById).length;
  const accuracy = prog.totalAnswered ? Math.round((prog.totalCorrect / prog.totalAnswered) * 100) : 0;

  const topicStats = useMemo(() => {
    const m: Record<string, { c: number; t: number }> = {};
    QUESTIONS.forEach((q) => {
      const s = prog.scoreById[q.id]; if (!s) return;
      m[q.topic] ||= { c: 0, t: 0 };
      m[q.topic].c += s.correct; m[q.topic].t += s.correct + s.wrong;
    });
    return m;
  }, [prog]);

  return (
    <div className="space-y-4">
      <div className="grid sm:grid-cols-4 gap-3">
        <Card className="p-3"><div className="text-[11px] text-muted-foreground uppercase">Streak</div><div className="text-2xl font-bold flex items-center gap-1"><Flame className="w-5 h-5 text-orange-500" />{prog.streak}</div></Card>
        <Card className="p-3"><div className="text-[11px] text-muted-foreground uppercase">Accuracy</div><div className="text-2xl font-bold">{accuracy}%</div></Card>
        <Card className="p-3"><div className="text-[11px] text-muted-foreground uppercase">Answered</div><div className="text-2xl font-bold">{prog.totalAnswered}</div></Card>
        <Card className="p-3"><div className="text-[11px] text-muted-foreground uppercase">Coverage</div><div className="text-2xl font-bold">{seen}/{QUESTIONS.length}</div><Progress className="mt-1 h-1" value={(seen / QUESTIONS.length) * 100} /></Card>
      </div>

      <Card className="p-3 space-y-2">
        <div className="flex items-center gap-2 text-xs flex-wrap">
          <span className="text-muted-foreground">Difficulty:</span>
          {(["all", "beginner", "intermediate", "advanced"] as const).map((lv) => (
            <Button key={lv} size="sm" variant={level === lv ? "default" : "outline"} className="capitalize h-7" onClick={() => setLevel(lv)}>{lv}</Button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-xs flex-wrap">
          <span className="text-muted-foreground flex items-center gap-1"><Filter className="w-3 h-3" />Topic:</span>
          <Button size="sm" variant={topic === "all" ? "default" : "outline"} className="h-7" onClick={() => setTopic("all")}>all</Button>
          {ALL_TOPICS.map((t) => (
            <Button key={t} size="sm" variant={topic === t ? "default" : "outline"} className="capitalize h-7" onClick={() => setTopic(t)}>{t}</Button>
          ))}
        </div>
        <div className="flex items-center justify-between gap-2 flex-wrap pt-1">
          <Button size="sm" variant={reviewMissed ? "default" : "outline"} onClick={() => setReviewMissed((v) => !v)} className="h-7">
            <RotateCcw className="w-3.5 h-3.5 mr-1" />{reviewMissed ? "Reviewing missed" : "Review missed only"}
          </Button>
          <Button size="sm" variant="ghost" onClick={reset}><RotateCcw className="w-3.5 h-3.5 mr-1" />Reset progress</Button>
        </div>
      </Card>

      {q ? (
        <Card className="p-5 space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="capitalize">{q.level}</Badge>
            <Badge variant="secondary" className="capitalize">{q.topic}</Badge>
            {q.type === "multi" && <Badge>multi-select</Badge>}
            {q.type === "command" && <Badge>what command?</Badge>}
            {stat && (
              <span className="text-[11px] text-muted-foreground ml-auto">
                seen {stat.correct + stat.wrong}× • {stat.correct}✓ / {stat.wrong}✗ • next {fmtDue(stat.nextDue)}
              </span>
            )}
          </div>
          <div className="text-base font-medium">{q.q}</div>
          <div className="grid gap-2">
            {q.choices.map((c, ci) => {
              const isPicked = picked.includes(ci);
              const isCorrect = q.type === "multi" ? (q.answer as number[]).includes(ci) : ci === q.answer;
              const showAnswers = submitted || revealed;
              const stateClass = !showAnswers
                ? isPicked ? "border-primary bg-primary/5" : "border-border hover:bg-muted/40"
                : isCorrect ? "border-success bg-success/15"
                  : isPicked ? "border-destructive bg-destructive/10" : "border-border opacity-60";
              return (
                <button key={ci} onClick={() => toggle(ci)} disabled={showAnswers}
                  className={`text-left text-sm rounded-md px-3 py-2 border transition-colors ${stateClass}`}>
                  <span className="font-mono text-xs text-muted-foreground mr-2">{String.fromCharCode(65 + ci)}.</span>{c}
                </button>
              );
            })}
          </div>
          {submitted ? (
            <div className="space-y-3">
              <div className={`flex items-center gap-2 text-sm font-medium ${isAnswerCorrect(q, picked) ? "text-success" : "text-destructive"}`}>
                {isAnswerCorrect(q, picked) ? <><Check className="w-4 h-4" />Correct</> : <><X className="w-4 h-4" />Not quite</>}
              </div>
              <p className="text-sm text-muted-foreground">{q.explain}</p>
              <Button onClick={nextQ}>Next question</Button>
            </div>
          ) : revealed ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground"><span className="font-medium text-foreground">Answer: </span>{q.explain}</p>
              <div className="flex gap-2"><Button onClick={nextQ}>Next question</Button></div>
            </div>
          ) : (
            <div className="flex gap-2">
              <Button onClick={submit} disabled={picked.length === 0}>Submit</Button>
              <Button variant="outline" onClick={reveal}><Eye className="w-4 h-4 mr-1" />Reveal answer</Button>
              <Button variant="ghost" onClick={nextQ}>Skip</Button>
            </div>
          )}
        </Card>
      ) : (
        <Card className="p-8 text-center text-muted-foreground">
          <Trophy className="w-8 h-8 mx-auto mb-2 text-primary" />
          {reviewMissed ? "Nothing to review — you haven't missed any questions in this filter yet." : "No questions for this filter."}
        </Card>
      )}

      {Object.keys(topicStats).length > 0 && (
        <Card className="p-4">
          <div className="text-sm font-semibold mb-3">Topic mastery</div>
          <div className="grid sm:grid-cols-2 gap-3">
            {Object.entries(topicStats).sort().map(([t, s]) => (
              <div key={t} className="space-y-1">
                <div className="flex justify-between text-xs"><span className="capitalize">{t}</span><span className="text-muted-foreground">{s.c}/{s.t}</span></div>
                <Progress value={s.t ? (s.c / s.t) * 100 : 0} className="h-1.5" />
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
