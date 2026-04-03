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
  { id: "grammar", label: "Grammar Check", icon: CheckCircle, description: "Fix grammar, spelling & punctuation", color: "text-emerald-500" },
  { id: "professional", label: "Professional Tone", icon: PenTool, description: "Rewrite for business & formal context", color: "text-blue-500" },
  { id: "casual", label: "Casual Tone", icon: AlignLeft, description: "Make it friendly & conversational", color: "text-amber-500" },
  { id: "translate", label: "Translator", icon: Languages, description: "Translate to any language", color: "text-purple-500" },
  { id: "summarize", label: "Summarize", icon: FileText, description: "Condense text to key points", color: "text-cyan-500" },
  { id: "expand", label: "Expand", icon: Maximize2, description: "Add detail and depth", color: "text-orange-500" },
  { id: "email", label: "Email Writer", icon: Mail, description: "Convert text to professional email", color: "text-rose-500" },
];

const languages = [
  "English", "Spanish", "French", "German", "Italian", "Portuguese", "Chinese", "Japanese",
  "Korean", "Arabic", "Hindi", "Russian", "Dutch", "Swedish", "Turkish", "Polish", "Thai",
  "Vietnamese", "Indonesian", "Greek", "Czech", "Romanian", "Hungarian", "Finnish", "Danish",
];

const WritingTools = () => {
  const [inputText, setInputText] = useState("");
  const [selectedTool, setSelectedTool] = useState("grammar");
  const [targetLanguage, setTargetLanguage] = useState("Spanish");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Copied!");
    setTimeout(() => setCopied(false), 2000);
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
        body: { text: inputText, action: selectedTool, targetLanguage: selectedTool === "translate" ? targetLanguage : undefined },
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

  const getOutputText = () => {
    if (!result) return "";
    return result.corrected || result.rewritten || result.translated || result.summary || result.expanded || result.email || "";
  };

  const currentTool = tools.find(t => t.id === selectedTool)!;
  const Icon = currentTool.icon;

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
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2">
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

          <div className="grid lg:grid-cols-2 gap-6">
            {/* Input */}
            <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${currentTool.color}`} />
                  <h2 className="font-semibold text-foreground">{currentTool.label}</h2>
                </div>
                <Badge variant="outline" className="text-xs">{currentTool.description}</Badge>
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
                  selectedTool === "grammar" ? "Paste your text here to check grammar and spelling..."
                    : selectedTool === "translate" ? "Enter text to translate..."
                    : selectedTool === "email" ? "Describe what you want to communicate in the email..."
                    : "Enter your text here..."
                }
                className="min-h-[250px] bg-muted/10 border-border/50 text-sm mb-4"
              />

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  {inputText.length} characters · {inputText.trim().split(/\s+/).filter(Boolean).length} words
                </span>
                <Button onClick={handleProcess} disabled={loading || !inputText.trim()} className="gap-2">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                  {loading ? "Processing..." : "Process"}
                </Button>
              </div>
            </Card>

            {/* Output */}
            <Card className="p-6 bg-card/80 backdrop-blur border-border/50">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-semibold text-foreground flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-primary" /> Result
                </h2>
                {getOutputText() && (
                  <Button size="sm" variant="outline" onClick={() => copyToClipboard(getOutputText())} className="gap-1.5 h-8">
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? "Copied" : "Copy"}
                  </Button>
                )}
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <Loader2 className="w-8 h-8 animate-spin mb-3 text-primary" />
                  <p className="text-sm">Analyzing your text...</p>
                </div>
              ) : result ? (
                <div className="space-y-4">
                  {/* Main output text */}
                  <div className="bg-muted/20 rounded-lg p-4 min-h-[200px]">
                    <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">{getOutputText()}</p>
                  </div>

                  {/* Grammar-specific: score + changes */}
                  {selectedTool === "grammar" && result.score !== undefined && (
                    <>
                      <div className="flex items-center gap-3">
                        <div className={`text-2xl font-bold ${result.score >= 90 ? "text-emerald-500" : result.score >= 70 ? "text-amber-500" : "text-red-500"}`}>
                          {result.score}/100
                        </div>
                        <div className="text-sm text-muted-foreground">{result.summary}</div>
                      </div>
                      {result.changes?.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Changes Made</h4>
                          {result.changes.map((c: any, i: number) => (
                            <div key={i} className="bg-muted/20 rounded-lg p-3 text-sm">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="line-through text-red-400">{c.original}</span>
                                <ArrowRight className="w-3 h-3 text-muted-foreground" />
                                <span className="text-emerald-500 font-medium">{c.corrected}</span>
                              </div>
                              <p className="text-xs text-muted-foreground">{c.reason}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}

                  {/* Improvements list */}
                  {result.improvements?.length > 0 && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Improvements</h4>
                      {result.improvements.map((imp: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" />
                          {imp}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Key points (summarize) */}
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

                  {/* Email subject */}
                  {result.subject && (
                    <div className="bg-primary/5 rounded-lg p-3">
                      <span className="text-xs text-muted-foreground">Suggested Subject: </span>
                      <span className="text-sm font-medium text-foreground">{result.subject}</span>
                    </div>
                  )}

                  {/* Translation notes */}
                  {result.notes && (
                    <div className="flex items-start gap-2 bg-muted/20 rounded-lg p-3 text-sm text-muted-foreground">
                      <AlertCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                      {result.notes}
                    </div>
                  )}

                  {/* Tip */}
                  {result.tip && (
                    <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-lg p-3 text-sm text-muted-foreground">
                      <Lightbulb className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                      <span><strong className="text-foreground">Tip:</strong> {result.tip}</span>
                    </div>
                  )}

                  {/* Word stats */}
                  {(result.wordReduction || result.wordIncrease) && (
                    <Badge variant="outline" className="bg-muted/30">{result.wordReduction || result.wordIncrease}</Badge>
                  )}

                  {/* Use result button */}
                  {getOutputText() && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => { setInputText(getOutputText()); setResult(null); }}
                      className="gap-2"
                    >
                      <ArrowRight className="w-3.5 h-3.5" /> Use as Input
                    </Button>
                  )}
                </div>
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
