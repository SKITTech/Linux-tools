import { useState, useMemo, useRef, useCallback } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "@/hooks/use-toast";
import {
  FileText, Upload, Copy, Download, Trash2, ArrowLeftRight,
  Plus, Minus, Equal, Eye, Code, AlignLeft
} from "lucide-react";

interface DiffLine {
  type: "added" | "removed" | "unchanged" | "modified";
  leftLine: string;
  rightLine: string;
  leftNum: number | null;
  rightNum: number | null;
}

interface DiffStats {
  added: number;
  removed: number;
  modified: number;
  unchanged: number;
}

function computeDiff(
  textA: string,
  textB: string,
  ignoreCase: boolean,
  ignoreWhitespace: boolean,
  trimLines: boolean
): { lines: DiffLine[]; stats: DiffStats } {
  let linesA = textA.split("\n");
  let linesB = textB.split("\n");

  const normalize = (line: string) => {
    let l = line;
    if (trimLines) l = l.trim();
    if (ignoreWhitespace) l = l.replace(/\s+/g, " ");
    if (ignoreCase) l = l.toLowerCase();
    return l;
  };

  const n = linesA.length;
  const m = linesB.length;

  // LCS via DP
  const dp: number[][] = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      if (normalize(linesA[i - 1]) === normalize(linesB[j - 1])) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack
  const result: DiffLine[] = [];
  let i = n, j = m;
  const temp: DiffLine[] = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && normalize(linesA[i - 1]) === normalize(linesB[j - 1])) {
      temp.push({ type: "unchanged", leftLine: linesA[i - 1], rightLine: linesB[j - 1], leftNum: i, rightNum: j });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      temp.push({ type: "added", leftLine: "", rightLine: linesB[j - 1], leftNum: null, rightNum: j });
      j--;
    } else {
      temp.push({ type: "removed", leftLine: linesA[i - 1], rightLine: "", leftNum: i, rightNum: null });
      i--;
    }
  }

  temp.reverse();

  const stats: DiffStats = { added: 0, removed: 0, modified: 0, unchanged: 0 };
  for (const line of temp) {
    stats[line.type === "modified" ? "modified" : line.type]++;
    result.push(line);
  }

  return { lines: result, stats };
}

function getWordDiff(a: string, b: string): { aWords: { text: string; changed: boolean }[]; bWords: { text: string; changed: boolean }[] } {
  const wordsA = a.split(/(\s+)/);
  const wordsB = b.split(/(\s+)/);

  const n = wordsA.length, m = wordsB.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));
  for (let i = 1; i <= n; i++)
    for (let j = 1; j <= m; j++)
      dp[i][j] = wordsA[i - 1] === wordsB[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);

  let i = n, j = m;
  const aTemp: { text: string; changed: boolean }[] = [];
  const bTemp: { text: string; changed: boolean }[] = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && wordsA[i - 1] === wordsB[j - 1]) {
      aTemp.push({ text: wordsA[i - 1], changed: false });
      bTemp.push({ text: wordsB[j - 1], changed: false });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      bTemp.push({ text: wordsB[j - 1], changed: true });
      j--;
    } else {
      aTemp.push({ text: wordsA[i - 1], changed: true });
      i--;
    }
  }

  aTemp.reverse();
  bTemp.reverse();
  return { aWords: aTemp, bWords: bTemp };
}

const TextCompare = () => {
  const [textA, setTextA] = useState("");
  const [textB, setTextB] = useState("");
  const [ignoreCase, setIgnoreCase] = useState(false);
  const [ignoreWhitespace, setIgnoreWhitespace] = useState(false);
  const [trimLines, setTrimLines] = useState(false);
  const [showOnlyDiffs, setShowOnlyDiffs] = useState(false);
  const [viewMode, setViewMode] = useState<"side-by-side" | "inline" | "unified">("side-by-side");
  const [wordLevel, setWordLevel] = useState(true);
  const fileRefA = useRef<HTMLInputElement>(null);
  const fileRefB = useRef<HTMLInputElement>(null);

  const { lines, stats } = useMemo(() => {
    if (!textA && !textB) return { lines: [], stats: { added: 0, removed: 0, modified: 0, unchanged: 0 } };
    return computeDiff(textA, textB, ignoreCase, ignoreWhitespace, trimLines);
  }, [textA, textB, ignoreCase, ignoreWhitespace, trimLines]);

  const displayLines = useMemo(() => {
    if (showOnlyDiffs) return lines.filter(l => l.type !== "unchanged");
    return lines;
  }, [lines, showOnlyDiffs]);

  const handleFileUpload = useCallback((side: "a" | "b") => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast({ title: "File too large", description: "Max 5MB", variant: "destructive" });
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      if (side === "a") setTextA(text); else setTextB(text);
      toast({ title: "File loaded", description: `${file.name} loaded successfully` });
    };
    reader.readAsText(file);
  }, []);

  const swapTexts = () => { setTextA(textB); setTextB(textA); };
  const clearAll = () => { setTextA(""); setTextB(""); };

  const exportDiff = () => {
    const output = displayLines.map(l => {
      if (l.type === "added") return `+ ${l.rightLine}`;
      if (l.type === "removed") return `- ${l.leftLine}`;
      return `  ${l.leftLine}`;
    }).join("\n");
    const blob = new Blob([output], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "diff-output.txt"; a.click();
    URL.revokeObjectURL(url);
    toast({ title: "Exported", description: "Diff exported as text file" });
  };

  const copyDiff = () => {
    const output = displayLines.map(l => {
      if (l.type === "added") return `+ ${l.rightLine}`;
      if (l.type === "removed") return `- ${l.leftLine}`;
      return `  ${l.leftLine}`;
    }).join("\n");
    navigator.clipboard.writeText(output);
    toast({ title: "Copied", description: "Diff copied to clipboard" });
  };

  const hasContent = textA || textB;
  const hasDiffs = stats.added + stats.removed > 0;

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        <div className="p-4 md:p-6 max-w-[1600px] mx-auto space-y-4">
          {/* Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
                <FileText className="w-6 h-6 text-primary" />
                Advanced Text Compare
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Compare texts with word-level diffs, multiple view modes, and flexible options
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={swapTexts} disabled={!hasContent}>
                <ArrowLeftRight className="w-4 h-4 mr-1" /> Swap
              </Button>
              <Button variant="outline" size="sm" onClick={copyDiff} disabled={!hasDiffs}>
                <Copy className="w-4 h-4 mr-1" /> Copy
              </Button>
              <Button variant="outline" size="sm" onClick={exportDiff} disabled={!hasDiffs}>
                <Download className="w-4 h-4 mr-1" /> Export
              </Button>
              <Button variant="outline" size="sm" onClick={clearAll} disabled={!hasContent}>
                <Trash2 className="w-4 h-4 mr-1" /> Clear
              </Button>
            </div>
          </div>

          {/* Options Bar */}
          <Card>
            <CardContent className="p-3">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
                <div className="flex items-center gap-2">
                  <Switch id="ignoreCase" checked={ignoreCase} onCheckedChange={setIgnoreCase} />
                  <Label htmlFor="ignoreCase" className="text-xs cursor-pointer">Ignore Case</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch id="ignoreWS" checked={ignoreWhitespace} onCheckedChange={setIgnoreWhitespace} />
                  <Label htmlFor="ignoreWS" className="text-xs cursor-pointer">Ignore Whitespace</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch id="trimLines" checked={trimLines} onCheckedChange={setTrimLines} />
                  <Label htmlFor="trimLines" className="text-xs cursor-pointer">Trim Lines</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch id="wordLevel" checked={wordLevel} onCheckedChange={setWordLevel} />
                  <Label htmlFor="wordLevel" className="text-xs cursor-pointer">Word-Level Diff</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch id="onlyDiffs" checked={showOnlyDiffs} onCheckedChange={setShowOnlyDiffs} />
                  <Label htmlFor="onlyDiffs" className="text-xs cursor-pointer">Only Differences</Label>
                </div>
                <div className="ml-auto flex items-center gap-1">
                  <Button variant={viewMode === "side-by-side" ? "default" : "ghost"} size="sm" className="h-7 text-xs" onClick={() => setViewMode("side-by-side")}>
                    <Code className="w-3 h-3 mr-1" /> Side-by-Side
                  </Button>
                  <Button variant={viewMode === "inline" ? "default" : "ghost"} size="sm" className="h-7 text-xs" onClick={() => setViewMode("inline")}>
                    <AlignLeft className="w-3 h-3 mr-1" /> Inline
                  </Button>
                  <Button variant={viewMode === "unified" ? "default" : "ghost"} size="sm" className="h-7 text-xs" onClick={() => setViewMode("unified")}>
                    <Eye className="w-3 h-3 mr-1" /> Unified
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Input Areas */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left */}
            <Card>
              <CardHeader className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold">Original Text</CardTitle>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-[10px]">{textA.split("\n").filter(Boolean).length} lines</Badge>
                    <input ref={fileRefA} type="file" accept=".txt,.csv,.json,.xml,.html,.css,.js,.ts,.py,.sql,.log,.md,.yaml,.yml,.ini,.conf,.cfg" className="hidden" onChange={handleFileUpload("a")} />
                    <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => fileRefA.current?.click()}>
                      <Upload className="w-3 h-3 mr-1" /> Upload
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-4 pt-0">
                <Textarea
                  value={textA}
                  onChange={(e) => setTextA(e.target.value)}
                  placeholder="Paste or upload original text here..."
                  className="min-h-[200px] font-mono text-xs leading-relaxed resize-y bg-muted/30"
                />
              </CardContent>
            </Card>

            {/* Right */}
            <Card>
              <CardHeader className="py-3 px-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold">Modified Text</CardTitle>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-[10px]">{textB.split("\n").filter(Boolean).length} lines</Badge>
                    <input ref={fileRefB} type="file" accept=".txt,.csv,.json,.xml,.html,.css,.js,.ts,.py,.sql,.log,.md,.yaml,.yml,.ini,.conf,.cfg" className="hidden" onChange={handleFileUpload("b")} />
                    <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => fileRefB.current?.click()}>
                      <Upload className="w-3 h-3 mr-1" /> Upload
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-4 pt-0">
                <Textarea
                  value={textB}
                  onChange={(e) => setTextB(e.target.value)}
                  placeholder="Paste or upload modified text here..."
                  className="min-h-[200px] font-mono text-xs leading-relaxed resize-y bg-muted/30"
                />
              </CardContent>
            </Card>
          </div>

          {/* Stats */}
          {hasContent && (
            <div className="flex items-center gap-3 flex-wrap">
              <Badge variant="outline" className="gap-1.5 text-xs py-1 border-green-500/30 text-green-600 dark:text-green-400">
                <Plus className="w-3 h-3" /> {stats.added} Added
              </Badge>
              <Badge variant="outline" className="gap-1.5 text-xs py-1 border-red-500/30 text-red-600 dark:text-red-400">
                <Minus className="w-3 h-3" /> {stats.removed} Removed
              </Badge>
              <Badge variant="outline" className="gap-1.5 text-xs py-1 border-muted-foreground/30 text-muted-foreground">
                <Equal className="w-3 h-3" /> {stats.unchanged} Unchanged
              </Badge>
              <span className="text-xs text-muted-foreground ml-auto">
                {displayLines.length} lines shown
              </span>
            </div>
          )}

          {/* Diff Output */}
          {hasContent && (
            <Card>
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-sm font-semibold">Comparison Result</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <ScrollArea className="max-h-[500px]">
                  {viewMode === "side-by-side" && (
                    <div className="grid grid-cols-2 divide-x divide-border">
                      <div className="font-mono text-xs">
                        {displayLines.map((line, idx) => {
                          const isRemoved = line.type === "removed";
                          const isUnchanged = line.type === "unchanged";
                          const wordDiff = wordLevel && !isUnchanged && line.leftLine && line.rightLine
                            ? getWordDiff(line.leftLine, line.rightLine) : null;

                          return (
                            <div
                              key={`l-${idx}`}
                              className={`flex items-stretch border-b border-border/30 ${
                                isRemoved ? "bg-red-500/10" : line.type === "added" ? "bg-transparent" : ""
                              }`}
                            >
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">
                                {line.leftNum ?? ""}
                              </span>
                              <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1">
                                {isRemoved && <Minus className="w-3 h-3 inline mr-1 text-red-500" />}
                                {wordDiff
                                  ? wordDiff.aWords.map((w, i) => (
                                      <span key={i} className={w.changed ? "bg-red-500/25 rounded px-0.5" : ""}>{w.text}</span>
                                    ))
                                  : line.leftLine}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                      <div className="font-mono text-xs">
                        {displayLines.map((line, idx) => {
                          const isAdded = line.type === "added";
                          const isUnchanged = line.type === "unchanged";
                          const wordDiff = wordLevel && !isUnchanged && line.leftLine && line.rightLine
                            ? getWordDiff(line.leftLine, line.rightLine) : null;

                          return (
                            <div
                              key={`r-${idx}`}
                              className={`flex items-stretch border-b border-border/30 ${
                                isAdded ? "bg-green-500/10" : line.type === "removed" ? "bg-transparent" : ""
                              }`}
                            >
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">
                                {line.rightNum ?? ""}
                              </span>
                              <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1">
                                {isAdded && <Plus className="w-3 h-3 inline mr-1 text-green-500" />}
                                {wordDiff
                                  ? wordDiff.bWords.map((w, i) => (
                                      <span key={i} className={w.changed ? "bg-green-500/25 rounded px-0.5" : ""}>{w.text}</span>
                                    ))
                                  : line.rightLine}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {viewMode === "inline" && (
                    <div className="font-mono text-xs">
                      {displayLines.map((line, idx) => (
                        <div
                          key={idx}
                          className={`flex items-stretch border-b border-border/30 ${
                            line.type === "added" ? "bg-green-500/10" :
                            line.type === "removed" ? "bg-red-500/10" : ""
                          }`}
                        >
                          <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">
                            {line.leftNum ?? line.rightNum ?? ""}
                          </span>
                          <span className="w-6 shrink-0 text-center py-1 select-none font-bold">
                            {line.type === "added" ? <span className="text-green-500">+</span> :
                             line.type === "removed" ? <span className="text-red-500">−</span> : " "}
                          </span>
                          <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1">
                            {line.type === "removed" ? line.leftLine : line.rightLine || line.leftLine}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {viewMode === "unified" && (
                    <div className="font-mono text-xs">
                      {displayLines.map((line, idx) => {
                        if (line.type === "unchanged") {
                          return (
                            <div key={idx} className="flex items-stretch border-b border-border/30">
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">{line.leftNum}</span>
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">{line.rightNum}</span>
                              <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1">{line.leftLine}</span>
                            </div>
                          );
                        }
                        const rows = [];
                        if (line.type === "removed" || (line.leftLine && line.type !== "added")) {
                          rows.push(
                            <div key={`${idx}-r`} className="flex items-stretch border-b border-border/30 bg-red-500/10">
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">{line.leftNum}</span>
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30"></span>
                              <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1"><span className="text-red-500 font-bold mr-1">−</span>{line.leftLine}</span>
                            </div>
                          );
                        }
                        if (line.type === "added" || (line.rightLine && line.type !== "removed")) {
                          rows.push(
                            <div key={`${idx}-a`} className="flex items-stretch border-b border-border/30 bg-green-500/10">
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30"></span>
                              <span className="w-10 shrink-0 text-right pr-2 py-1 text-muted-foreground/60 select-none border-r border-border/30">{line.rightNum}</span>
                              <span className="px-2 py-1 whitespace-pre-wrap break-all flex-1"><span className="text-green-500 font-bold mr-1">+</span>{line.rightLine}</span>
                            </div>
                          );
                        }
                        return rows;
                      })}
                    </div>
                  )}

                  {displayLines.length === 0 && hasContent && (
                    <div className="p-8 text-center text-muted-foreground">
                      <Equal className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm font-medium">Texts are identical</p>
                      <p className="text-xs mt-1">No differences found with current settings</p>
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          )}

          {!hasContent && (
            <Card>
              <CardContent className="p-12 text-center">
                <FileText className="w-12 h-12 mx-auto mb-3 text-muted-foreground/30" />
                <p className="text-sm font-medium text-muted-foreground">Paste or upload text in both panels to compare</p>
                <p className="text-xs text-muted-foreground/60 mt-1">Supports side-by-side, inline, and unified diff views with word-level highlighting</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </Sidebar>
  );
};

export default TextCompare;
