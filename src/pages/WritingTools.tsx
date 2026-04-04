import { useState } from "react";
import {
  CheckCircle, Copy, Check, Loader2, Sparkles, Languages, FileText,
  Mail, AlignLeft, Maximize2, PenTool, ArrowRight, Lightbulb, AlertCircle
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sidebar } from "@/components/Sidebar";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

const tools = [
  { id: "enhance", label: "Text Enhancer", icon: Sparkles, description: "Grammar check + Professional + Casual tone — all at once", color: "text-emerald-500" },
  { id: "translate", label: "Translator", icon: Languages, description: "Translate to any language", color: "text-purple-500" },
  { id: "summarize", label: "Summarize", icon: FileText, description: "Condense text to key points", color: "text-cyan-500" },
  { id: "expand", label: "Expand", icon: Maximize2, description: "Add detail and depth", color: "text-orange-500" },
  { id: "email-suggestions", label: "Email Writer", icon: Mail, description: "Get 3 email options from your message", color: "text-rose-500" },
];

const languages = [
  "English", "Spanish", "French", "German", "Italian", "Portuguese", "Chinese", "Japanese",
  "Korean", "Arabic", "Hindi", "Russian", "Dutch", "Swedish", "Turkish", "Polish", "Thai",
  "Vietnamese", "Indonesian", "Greek", "Czech", "Romanian", "Hungarian", "Finnish", "Danish",
];

const WritingTools = () => {
  const [inputText, setInputText] = useState("");
  const [selectedTool, setSelectedTool] = useState("enhance");
  const [targetLanguage, setTargetLanguage] = useState("English");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    toast.success("Copied!");
    setTimeout(() => setCopied(null), 2000);
  };

  const handleProcess = async () => {
    if (!inputText.trim()) {
      toast.error("Please enter some text first");
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const { data, error } = await supabase.functions.invoke("text-tools", {
        body: {
          text: inputText,
          action: selectedTool,
          targetLanguage: selectedTool === "translate" ? targetLanguage : undefined,
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setResult(data);
    } catch (err: any) {
      toast.error(err.message || "Processing failed");
    } finally {
      setLoading(false);
    }
  };

  const currentTool = tools.find(t => t.id === selectedTool)!;
  const Icon = currentTool.icon;

  const renderEnhanceResult = () => {
    if (!result) return null;
    const { grammar, professional, casual } = result;
    return (
      <div className="space-y-5">
        {/* Grammar Check */}
        {grammar && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-500" />
                <h3 className="font-semibold text-foreground text-sm">Grammar Check</h3>
                {grammar.score !== undefined && (
                  <Badge variant="outline" className={grammar.score >= 90 ? "text-emerald-500 border-emerald-500/30" : grammar.score >= 70 ? "text-amber-500 border-amber-500/30" : "text-red-500 border-red-500/30"}>
                    {grammar.score}/100
                  </Badge>
                )}
              </div>
              <Button size="sm" variant="ghost" className="h-7 gap-1" onClick={() => copyToClipboard(grammar.corrected || "", "grammar")}>
                {copied === "grammar" ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              </Button>
            </div>
            <div className="bg-muted/20 rounded-lg p-3 text-sm text-foreground whitespace-pre-wrap">{grammar.corrected}</div>
            {grammar.changes?.length > 0 && (
              <div className="space-y-1.5">
                {grammar.changes.map((c: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-xs bg-muted/10 rounded p-2">
                    <span className="line-through text-red-400">{c.original}</span>
                    <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0" />
                    <span className="text-emerald-500 font-medium">{c.corrected}</span>
                    <span className="text-muted-foreground ml-auto">— {c.reason}</span>
                  </div>
                ))}
              </div>
            )}
            {grammar.summary && <p className="text-xs text-muted-foreground">{grammar.summary}</p>}
          </div>
        )}

        <div className="border-t border-border/30" />

        {/* Professional Tone */}
        {professional && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <PenTool className="w-4 h-4 text-blue-500" />
                <h3 className="font-semibold text-foreground text-sm">Professional Tone</h3>
              </div>
              <Button size="sm" variant="ghost" className="h-7 gap-1" onClick={() => copyToClipboard(professional.rewritten || "", "pro")}>
                {copied === "pro" ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              </Button>
            </div>
            <div className="bg-muted/20 rounded-lg p-3 text-sm text-foreground whitespace-pre-wrap">{professional.rewritten}</div>
            {professional.improvements?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {professional.improvements.map((imp: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-xs bg-blue-500/5 text-blue-400 border-blue-500/20">{imp}</Badge>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="border-t border-border/30" />

        {/* Casual Tone */}
        {casual && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlignLeft className="w-4 h-4 text-amber-500" />
                <h3 className="font-semibold text-foreground text-sm">Casual Tone</h3>
              </div>
              <Button size="sm" variant="ghost" className="h-7 gap-1" onClick={() => copyToClipboard(casual.rewritten || "", "casual")}>
                {copied === "casual" ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              </Button>
            </div>
            <div className="bg-muted/20 rounded-lg p-3 text-sm text-foreground whitespace-pre-wrap">{casual.rewritten}</div>
            {casual.improvements?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {casual.improvements.map((imp: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-xs bg-amber-500/5 text-amber-400 border-amber-500/20">{imp}</Badge>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tips */}
        {(professional?.tip || casual?.tip) && (
          <>
            <div className="border-t border-border/30" />
            <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-lg p-3 text-sm text-muted-foreground">
              <Lightbulb className="w-4 h-4 text-primary mt-0.5 shrink-0" />
              <span><strong className="text-foreground">Tip:</strong> {professional?.tip || casual?.tip}</span>
            </div>
          </>
        )}
      </div>
    );
  };

  const renderEmailSuggestions = () => {
    if (!result?.suggestions) return null;
    return (
      <div className="space-y-4">
        {result.suggestions.map((s: any, i: number) => (
          <div key={i} className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Mail className="w-4 h-4 text-rose-500" />
                <h3 className="font-semibold text-foreground text-sm">Option {i + 1}: {s.tone}</h3>
              </div>
              <Button size="sm" variant="ghost" className="h-7 gap-1" onClick={() => copyToClipboard(`Subject: ${s.subject}\n\n${s.email}`, `email-${i}`)}>
                {copied === `email-${i}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
              </Button>
            </div>
            <div className="bg-primary/5 rounded-lg p-2 px-3">
              <span className="text-xs text-muted-foreground">Subject: </span>
              <span className="text-sm font-medium text-foreground">{s.subject}</span>
            </div>
            <div className="bg-muted/20 rounded-lg p-3 text-sm text-foreground whitespace-pre-wrap">{s.email}</div>
            {i < result.suggestions.length - 1 && <div className="border-t border-border/30" />}
          </div>
        ))}
        {result.tip && (
          <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-lg p-3 text-sm text-muted-foreground">
            <Lightbulb className="w-4 h-4 text-primary mt-0.5 shrink-0" />
            <span><strong className="text-foreground">Tip:</strong> {result.tip}</span>
          </div>
        )}
      </div>
    );
  };

  const renderStandardResult = () => {
    if (!result) return null;
    const outputText = result.translated || result.summary || result.expanded || "";
    return (
      <div className="space-y-4">
        <div className="flex justify-end">
          <Button size="sm" variant="ghost" className="h-7 gap-1" onClick={() => copyToClipboard(outputText, "std")}>
            {copied === "std" ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
          </Button>
        </div>
        <div className="bg-muted/20 rounded-lg p-4 min-h-[200px]">
          <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">{outputText}</p>
        </div>
        {result.keyPoints?.length > 0 && (
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Key Points</h4>
            {result.keyPoints.map((kp: string, i: number) => (
              <div key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                <Lightbulb className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
                {kp}
              </div>
            ))}
          </div>
        )}
        {result.notes && (
          <div className="flex items-start gap-2 bg-muted/20 rounded-lg p-3 text-sm text-muted-foreground">
            <AlertCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
            {result.notes}
          </div>
        )}
        {(result.wordReduction || result.wordIncrease) && (
          <Badge variant="outline" className="bg-muted/30">{result.wordReduction || result.wordIncrease}</Badge>
        )}
        {outputText && (
          <Button variant="outline" size="sm" onClick={() => { setInputText(outputText); setResult(null); }} className="gap-2">
            <ArrowRight className="w-3.5 h-3.5" /> Use as Input
          </Button>
        )}
      </div>
    );
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border/50 bg-gradient-to-br from-primary/5 via-background to-accent/5">
          <div className="container mx-auto px-6 py-8">
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                <Sparkles className="w-5 h-5 text-primary" />
              </div>
              <h1 className="text-3xl font-bold text-foreground tracking-tight">Writing Tools</h1>
            </div>
            <p className="text-muted-foreground ml-[52px]">
              AI-powered grammar check, tone adjustment, translation & more
            </p>
          </div>
        </header>

        <main className="container mx-auto px-6 py-6 space-y-6">
          {/* Tool Selector */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            {tools.map(tool => {
              const TIcon = tool.icon;
              const isActive = selectedTool === tool.id;
              return (
                <button
                  key={tool.id}
                  onClick={() => { setSelectedTool(tool.id); setResult(null); }}
                  className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border transition-all duration-200 ${
                    isActive
                      ? "bg-primary/10 border-primary/30 shadow-sm"
                      : "bg-card/80 border-border/50 hover:border-primary/20 hover:bg-muted/40"
                  }`}
                >
                  <TIcon className={`w-5 h-5 ${isActive ? "text-primary" : tool.color}`} />
                  <span className={`text-xs font-medium ${isActive ? "text-primary" : "text-muted-foreground"}`}>{tool.label}</span>
                </button>
              );
            })}
          </div>

          <div className={`grid ${selectedTool === "enhance" || selectedTool === "email-suggestions" ? "lg:grid-cols-[1fr_1.5fr]" : "lg:grid-cols-2"} gap-6`}>
            {/* Input */}
            <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${currentTool.color}`} />
                  <h2 className="font-semibold text-foreground">{currentTool.label}</h2>
                </div>
                <Badge variant="outline" className="text-xs hidden sm:inline-flex">{currentTool.description}</Badge>
              </div>

              {selectedTool === "translate" && (
                <div className="mb-4">
                  <label className="text-xs text-muted-foreground mb-1.5 block">Translate to:</label>
                  <Select value={targetLanguage} onValueChange={setTargetLanguage}>
                    <SelectTrigger className="bg-muted/20 border-border/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {languages.map(l => (
                        <SelectItem key={l} value={l}>{l}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <Textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={
                  selectedTool === "enhance" ? "Paste your text to get grammar check, professional & casual versions..."
                    : selectedTool === "translate" ? "Enter text to translate..."
                    : selectedTool === "email-suggestions" ? "Write your message idea and get 3 polished email options..."
                    : "Enter your text here..."
                }
                className="min-h-[250px] bg-muted/10 border-border/50 text-sm mb-4"
              />

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {inputText.length} chars · {inputText.trim().split(/\s+/).filter(Boolean).length} words
                </span>
                <Button onClick={handleProcess} disabled={loading || !inputText.trim()} className="gap-2">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                  {loading ? "Processing..." : "Process"}
                </Button>
              </div>
            </Card>

            {/* Output */}
            <Card className="p-6 bg-card/80 backdrop-blur border-border/50 overflow-auto max-h-[80vh]">
              <div className="flex items-center mb-4">
                <h2 className="font-semibold text-foreground flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-primary" /> Result
                </h2>
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <Loader2 className="w-8 h-8 animate-spin mb-3 text-primary" />
                  <p className="text-sm">
                    {selectedTool === "enhance" ? "Running 3 analyses in parallel..." : "Analyzing your text..."}
                  </p>
                </div>
              ) : result ? (
                selectedTool === "enhance" ? renderEnhanceResult()
                  : selectedTool === "email-suggestions" ? renderEmailSuggestions()
                  : renderStandardResult()
              ) : (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <Icon className={`w-12 h-12 mb-3 opacity-20 ${currentTool.color}`} />
                  <p className="text-sm">Enter text and click Process to see results</p>
                  <p className="text-xs mt-1 text-muted-foreground/60">Powered by AI</p>
                </div>
              )}
            </Card>
          </div>
        </main>
      </div>
    </Sidebar>
  );
};

export default WritingTools;
