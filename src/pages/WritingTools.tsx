import { useState } from "react";
import {
  CheckCircle, Copy, Check, Loader2, Sparkles, Languages, FileText,
  Mail, AlignLeft, Maximize2, PenTool, ArrowRight, Lightbulb, AlertCircle,
  Wand2, RotateCcw, Type, Zap
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Sidebar } from "@/components/Sidebar";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

const tools = [
  { id: "enhance", label: "Text Enhancer", icon: Wand2, description: "Improve grammar, tone & style instantly", color: "text-emerald-500" },
  { id: "translate", label: "Translator", icon: Languages, description: "Translate to 25+ languages", color: "text-purple-500" },
  { id: "summarize", label: "Summarizer", icon: FileText, description: "Extract key points concisely", color: "text-cyan-500" },
  { id: "expand", label: "Expander", icon: Maximize2, description: "Enrich with detail & depth", color: "text-orange-500" },
  { id: "email-suggestions", label: "Email Writer", icon: Mail, description: "Generate polished email drafts", color: "text-rose-500" },
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
    toast.success("Copied to clipboard");
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
      if (err.message?.includes("429") || err.message?.includes("Rate limit")) {
        toast.error("Rate limit reached. Please wait a moment and try again.");
      } else if (err.message?.includes("402") || err.message?.includes("Credits")) {
        toast.error("Credits exhausted. Please add funds in Settings → Workspace → Usage.");
      } else {
        toast.error(err.message || "Processing failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const currentTool = tools.find(t => t.id === selectedTool)!;
  const Icon = currentTool.icon;

  const wordCount = inputText.trim().split(/\s+/).filter(Boolean).length;
  const charCount = inputText.length;

  const CopyBtn = ({ text, id, label }: { text: string; id: string; label?: string }) => (
    <Button
      size="sm"
      variant="outline"
      className="h-7 gap-1.5 text-xs"
      onClick={() => copyToClipboard(text, id)}
    >
      {copied === id ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
      {label || "Copy"}
    </Button>
  );

  const renderEnhanceResult = () => {
    if (!result) return null;
    const { grammar, professional, casual } = result;
    return (
      <Tabs defaultValue="grammar" className="w-full">
        <TabsList className="w-full grid grid-cols-3 mb-4">
          <TabsTrigger value="grammar" className="gap-1.5 text-xs">
            <CheckCircle className="w-3.5 h-3.5" /> Grammar
            {grammar?.score !== undefined && (
              <Badge variant="secondary" className={`ml-1 text-[10px] px-1.5 py-0 ${grammar.score >= 90 ? "bg-emerald-500/10 text-emerald-500" : grammar.score >= 70 ? "bg-amber-500/10 text-amber-500" : "bg-red-500/10 text-red-500"}`}>
                {grammar.score}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="professional" className="gap-1.5 text-xs">
            <PenTool className="w-3.5 h-3.5" /> Professional
          </TabsTrigger>
          <TabsTrigger value="casual" className="gap-1.5 text-xs">
            <AlignLeft className="w-3.5 h-3.5" /> Casual
          </TabsTrigger>
        </TabsList>

        <TabsContent value="grammar" className="space-y-4 mt-0">
          {grammar && (
            <>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="font-semibold text-foreground text-sm">Corrected Text</h3>
                  {grammar.score !== undefined && (
                    <Badge variant="outline" className={`${grammar.score >= 90 ? "text-emerald-500 border-emerald-500/30 bg-emerald-500/5" : grammar.score >= 70 ? "text-amber-500 border-amber-500/30 bg-amber-500/5" : "text-red-500 border-red-500/30 bg-red-500/5"}`}>
                      Score: {grammar.score}/100
                    </Badge>
                  )}
                </div>
                <CopyBtn text={grammar.corrected || ""} id="grammar" />
              </div>
              <div className="bg-muted/30 rounded-xl p-4 text-sm text-foreground whitespace-pre-wrap leading-relaxed border border-border/30">
                {grammar.corrected}
              </div>
              {grammar.changes?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Changes Made</h4>
                  <div className="space-y-1.5">
                    {grammar.changes.map((c: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 text-xs bg-muted/20 rounded-lg p-2.5 border border-border/20">
                        <span className="line-through text-red-400 shrink-0">{c.original}</span>
                        <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0" />
                        <span className="text-emerald-500 font-medium shrink-0">{c.corrected}</span>
                        <span className="text-muted-foreground ml-auto text-right">{c.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {grammar.summary && (
                <p className="text-xs text-muted-foreground bg-muted/10 rounded-lg p-3 border border-border/20">{grammar.summary}</p>
              )}
            </>
          )}
        </TabsContent>

        <TabsContent value="professional" className="space-y-4 mt-0">
          {professional && (
            <>
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-foreground text-sm">Professional Version</h3>
                <CopyBtn text={professional.rewritten || ""} id="pro" />
              </div>
              <div className="bg-blue-500/5 rounded-xl p-4 text-sm text-foreground whitespace-pre-wrap leading-relaxed border border-blue-500/10">
                {professional.rewritten}
              </div>
              {professional.improvements?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Improvements</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {professional.improvements.map((imp: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs bg-blue-500/5 text-blue-400 border-blue-500/20">{imp}</Badge>
                    ))}
                  </div>
                </div>
              )}
              {professional.tip && (
                <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-xl p-3 text-sm text-muted-foreground">
                  <Lightbulb className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span><strong className="text-foreground">Pro Tip:</strong> {professional.tip}</span>
                </div>
              )}
            </>
          )}
        </TabsContent>

        <TabsContent value="casual" className="space-y-4 mt-0">
          {casual && (
            <>
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-foreground text-sm">Casual Version</h3>
                <CopyBtn text={casual.rewritten || ""} id="casual" />
              </div>
              <div className="bg-amber-500/5 rounded-xl p-4 text-sm text-foreground whitespace-pre-wrap leading-relaxed border border-amber-500/10">
                {casual.rewritten}
              </div>
              {casual.improvements?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Changes</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {casual.improvements.map((imp: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs bg-amber-500/5 text-amber-400 border-amber-500/20">{imp}</Badge>
                    ))}
                  </div>
                </div>
              )}
              {casual.tip && (
                <div className="flex items-start gap-2 bg-amber-500/5 border border-amber-500/10 rounded-xl p-3 text-sm text-muted-foreground">
                  <Lightbulb className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                  <span><strong className="text-foreground">Tip:</strong> {casual.tip}</span>
                </div>
              )}
            </>
          )}
        </TabsContent>
      </Tabs>
    );
  };

  const renderEmailSuggestions = () => {
    if (!result?.suggestions) return null;
    return (
      <Tabs defaultValue="0" className="w-full">
        <TabsList className="w-full grid grid-cols-3 mb-4">
          {result.suggestions.map((s: any, i: number) => (
            <TabsTrigger key={i} value={String(i)} className="gap-1.5 text-xs">
              <Mail className="w-3.5 h-3.5" /> {s.tone}
            </TabsTrigger>
          ))}
        </TabsList>
        {result.suggestions.map((s: any, i: number) => (
          <TabsContent key={i} value={String(i)} className="space-y-4 mt-0">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-foreground text-sm">{s.tone} Email</h3>
              <CopyBtn text={`Subject: ${s.subject}\n\n${s.email}`} id={`email-${i}`} />
            </div>
            <div className="bg-primary/5 rounded-xl p-3 border border-primary/10">
              <span className="text-xs text-muted-foreground font-medium">Subject: </span>
              <span className="text-sm font-semibold text-foreground">{s.subject}</span>
            </div>
            <div className="bg-muted/30 rounded-xl p-4 text-sm text-foreground whitespace-pre-wrap leading-relaxed border border-border/30">
              {s.email}
            </div>
          </TabsContent>
        ))}
        {result.tip && (
          <div className="flex items-start gap-2 bg-primary/5 border border-primary/10 rounded-xl p-3 text-sm text-muted-foreground mt-4">
            <Lightbulb className="w-4 h-4 text-primary mt-0.5 shrink-0" />
            <span><strong className="text-foreground">Tip:</strong> {result.tip}</span>
          </div>
        )}
      </Tabs>
    );
  };

  const renderStandardResult = () => {
    if (!result) return null;
    const outputText = result.translated || result.summary || result.expanded || "";
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-foreground text-sm flex items-center gap-2">
            <Zap className="w-4 h-4 text-primary" />
            {selectedTool === "translate" ? "Translation" : selectedTool === "summarize" ? "Summary" : "Expanded Text"}
          </h3>
          <div className="flex items-center gap-2">
            {(result.wordReduction || result.wordIncrease) && (
              <Badge variant="outline" className="text-xs bg-muted/30">{result.wordReduction || result.wordIncrease}</Badge>
            )}
            <CopyBtn text={outputText} id="std" />
          </div>
        </div>

        {result.sourceLanguage && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Badge variant="outline" className="bg-purple-500/5 text-purple-400 border-purple-500/20">
              {result.sourceLanguage} → {result.targetLanguage}
            </Badge>
          </div>
        )}

        <div className="bg-muted/30 rounded-xl p-4 min-h-[180px] border border-border/30">
          <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">{outputText}</p>
        </div>

        {result.keyPoints?.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Key Points</h4>
            <div className="space-y-1.5">
              {result.keyPoints.map((kp: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm text-muted-foreground bg-muted/10 rounded-lg p-2 border border-border/20">
                  <Lightbulb className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
                  {kp}
                </div>
              ))}
            </div>
          </div>
        )}

        {result.notes && (
          <div className="flex items-start gap-2 bg-muted/20 rounded-xl p-3 text-sm text-muted-foreground border border-border/20">
            <AlertCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
            {result.notes}
          </div>
        )}

        {result.addedDetails?.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Added Details</h4>
            <div className="flex flex-wrap gap-1.5">
              {result.addedDetails.map((d: string, i: number) => (
                <Badge key={i} variant="outline" className="text-xs bg-orange-500/5 text-orange-400 border-orange-500/20">{d}</Badge>
              ))}
            </div>
          </div>
        )}

        {outputText && (
          <Button variant="outline" size="sm" onClick={() => { setInputText(outputText); setResult(null); }} className="gap-2">
            <RotateCcw className="w-3.5 h-3.5" /> Use as Input
          </Button>
        )}
      </div>
    );
  };

  const placeholders: Record<string, string> = {
    enhance: "Paste your text here to check grammar, get professional & casual rewrites...",
    translate: "Enter text to translate into another language...",
    summarize: "Paste a long article, email, or document to get a concise summary...",
    expand: "Enter a short text or outline to expand with more detail...",
    "email-suggestions": "Describe your email intent (e.g., 'Follow up with client about project deadline')...",
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Header */}
        <header className="border-b border-border/50 bg-gradient-to-br from-primary/5 via-background to-accent/5">
          <div className="container mx-auto px-6 py-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center border border-primary/10">
                <Type className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground tracking-tight">Writing Tools</h1>
                <p className="text-sm text-muted-foreground">AI-powered writing assistant for grammar, tone, translation & email</p>
              </div>
            </div>
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
                  className={`group relative flex flex-col items-center gap-2 p-4 rounded-xl border transition-all duration-200 ${
                    isActive
                      ? "bg-primary/10 border-primary/30 shadow-md shadow-primary/5"
                      : "bg-card/80 border-border/50 hover:border-primary/20 hover:bg-muted/30 hover:shadow-sm"
                  }`}
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center transition-colors ${
                    isActive ? "bg-primary/20" : "bg-muted/30 group-hover:bg-muted/50"
                  }`}>
                    <TIcon className={`w-4.5 h-4.5 ${isActive ? "text-primary" : tool.color}`} />
                  </div>
                  <span className={`text-xs font-medium ${isActive ? "text-primary" : "text-muted-foreground"}`}>{tool.label}</span>
                  <span className="text-[10px] text-muted-foreground/60 text-center leading-tight hidden sm:block">{tool.description}</span>
                </button>
              );
            })}
          </div>

          {/* Main Content */}
          <div className={`grid ${selectedTool === "enhance" || selectedTool === "email-suggestions" ? "lg:grid-cols-[1fr_1.5fr]" : "lg:grid-cols-2"} gap-6`}>
            {/* Input Panel */}
            <Card className="p-5 bg-card/80 backdrop-blur border-border/50 shadow-sm">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${currentTool.color}`} />
                  <h2 className="font-semibold text-foreground text-sm">{currentTool.label}</h2>
                </div>
              </div>

              {selectedTool === "translate" && (
                <div className="mb-3">
                  <label className="text-xs text-muted-foreground mb-1.5 block font-medium">Translate to</label>
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
                placeholder={placeholders[selectedTool]}
                className="min-h-[280px] bg-muted/10 border-border/50 text-sm mb-3 resize-none focus:ring-1 focus:ring-primary/20"
              />

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground">
                    {charCount} chars · {wordCount} words
                  </span>
                  {inputText.length > 0 && (
                    <button
                      onClick={() => { setInputText(""); setResult(null); }}
                      className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <Button onClick={handleProcess} disabled={loading || !inputText.trim()} className="gap-2 shadow-sm">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                  {loading ? "Analyzing..." : "Analyze"}
                </Button>
              </div>
            </Card>

            {/* Output Panel */}
            <Card className="p-5 bg-card/80 backdrop-blur border-border/50 shadow-sm overflow-auto max-h-[80vh]">
              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
                  </div>
                  <p className="text-sm mt-4 font-medium">Analyzing your text...</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    {selectedTool === "enhance" ? "Running grammar, professional & casual analysis" : "This usually takes a few seconds"}
                  </p>
                </div>
              ) : result ? (
                selectedTool === "enhance" ? renderEnhanceResult()
                  : selectedTool === "email-suggestions" ? renderEmailSuggestions()
                  : renderStandardResult()
              ) : (
                <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                  <div className="w-16 h-16 rounded-2xl bg-muted/20 flex items-center justify-center mb-4">
                    <Icon className={`w-8 h-8 opacity-30 ${currentTool.color}`} />
                  </div>
                  <p className="text-sm font-medium">Ready to analyze</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">Enter your text and click Analyze</p>
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
