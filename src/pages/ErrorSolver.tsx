import { useState } from "react";
import { SEO } from "@/components/SEO";
import { Sidebar } from "@/components/Sidebar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, Copy, ExternalLink, Loader2, Terminal, Search, BookOpen, Lightbulb, MessageSquare } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sparkles } from "lucide-react";

const aiModels = [
  { id: "google/gemini-2.5-flash", label: "Gemini 2.5 Flash", description: "Fast & balanced (default)" },
  { id: "google/gemini-2.5-pro", label: "Gemini 2.5 Pro", description: "Deep reasoning, best quality" },
  { id: "google/gemini-3-flash-preview", label: "Gemini 3 Flash", description: "Next-gen, fast" },
  { id: "openai/gpt-5", label: "GPT-5", description: "OpenAI flagship, nuanced" },
  { id: "openai/gpt-5-mini", label: "GPT-5 Mini", description: "Faster GPT-5, lower cost" },
];

interface SolutionStep {
  step: number;
  title: string;
  description: string;
  command?: string;
}

interface Reference {
  title: string;
  url: string;
}

interface SolutionData {
  errorExplanation: string;
  possibleCauses: string[];
  stepByStepFix: SolutionStep[];
  references: Reference[];
  customerReply?: string;
  additionalNotes?: string;
  rawResponse?: string;
}

const products = [
  { id: "virtualizor", label: "Virtualizor", description: "KVM/OpenVZ/LXC virtualization panel" },
  { id: "softaculous", label: "Softaculous", description: "Auto-installer for web apps" },
  { id: "webuzo", label: "Webuzo", description: "Single server hosting panel" },
];

const ErrorSolver = () => {
  const [errorInput, setErrorInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [solution, setSolution] = useState<SolutionData | null>(null);
  const [selectedProduct, setSelectedProduct] = useState("virtualizor");
  const [selectedModel, setSelectedModel] = useState("google/gemini-2.5-flash");
  const { toast } = useToast();

  const handleSubmit = async () => {
    if (!errorInput.trim()) {
      toast({ title: "Error", description: "Please enter an error message", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    setSolution(null);

    try {
      const { data, error } = await supabase.functions.invoke("error-solver", {
        body: { errorMessage: errorInput.trim(), product: selectedProduct, model: selectedModel },
      });

      if (error) throw error;

      if (data?.success && data.data) {
        setSolution(data.data);
      } else {
        throw new Error(data?.error || "Failed to get solution");
      }
    } catch (err: any) {
      toast({ title: "Error", description: err.message || "Failed to analyze error", variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const copyText = (text: string, label = "Copied") => {
    navigator.clipboard.writeText(text);
    toast({ title: label, description: "Copied to clipboard" });
  };
  const copyCommand = (cmd: string) => copyText(cmd, "Command copied");

  return (
    <Sidebar>
      <SEO title="Error Solver — Virtualizor, Softaculous, Webuzo" description="AI-powered diagnosis and solutions for Virtualizor, Softaculous, and Webuzo errors." path="/#/error-solver" />
      <div className="p-6 max-w-5xl mx-auto space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-destructive/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-destructive" />
            </div>
            Error Solver
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered error diagnosis for Virtualizor, Softaculous & Webuzo
          </p>
        </div>

        {/* Product Tabs */}
        <Tabs value={selectedProduct} onValueChange={setSelectedProduct}>
          <TabsList className="w-full sm:w-auto">
            {products.map((p) => (
              <TabsTrigger key={p.id} value={p.id} className="text-xs sm:text-sm">
                {p.label}
              </TabsTrigger>
            ))}
          </TabsList>
          <p className="text-xs text-muted-foreground mt-1.5">
            {products.find((p) => p.id === selectedProduct)?.description}
          </p>
        </Tabs>

        {/* Input */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <Search className="w-4 h-4" />
              Describe Your Error
            </CardTitle>
            <CardDescription>
              Paste the error message, error code, or describe the issue you're facing with {products.find((p) => p.id === selectedProduct)?.label}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              value={errorInput}
              onChange={(e) => setErrorInput(e.target.value)}
              placeholder={
                selectedProduct === "virtualizor"
                  ? "e.g. 'Failed to create VPS: Could not find the storage' or 'KVM VPS not starting after migration'"
                  : selectedProduct === "softaculous"
                  ? "e.g. 'WordPress installation failed' or 'Backup creation error' or 'License activation failed'"
                  : "e.g. 'Apache not starting' or 'SSL certificate error' or 'DNS zone not loading'"
              }
              className="min-h-[120px] font-mono text-sm"
            />
            <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
              <div className="flex items-center gap-2 flex-1">
                <Sparkles className="w-4 h-4 text-primary shrink-0" />
                <Select value={selectedModel} onValueChange={setSelectedModel}>
                  <SelectTrigger className="w-full sm:w-[280px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {aiModels.map((m) => (
                      <SelectItem key={m.id} value={m.id}>
                        <div className="flex flex-col">
                          <span className="font-medium">{m.label}</span>
                          <span className="text-xs text-muted-foreground">{m.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button onClick={handleSubmit} disabled={isLoading || !errorInput.trim()} className="w-full sm:w-auto">
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Lightbulb className="w-4 h-4 mr-2" />
                    Find Solution
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Raw fallback */}
        {solution?.rawResponse && !solution.errorExplanation && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Analysis Result</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="whitespace-pre-wrap text-sm text-foreground bg-muted p-4 rounded-lg">{solution.rawResponse}</pre>
            </CardContent>
          </Card>
        )}

        {/* Structured solution */}
        {solution?.errorExplanation && (
          <div className="space-y-4">
            {/* Error Explanation */}
            <Card className="border-destructive/30">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2 text-destructive">
                  <AlertTriangle className="w-4 h-4" />
                  Error Explanation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-foreground leading-relaxed">{solution.errorExplanation}</p>
              </CardContent>
            </Card>

            {/* Possible Causes */}
            {solution.possibleCauses?.length > 0 && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Possible Causes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {solution.possibleCauses.map((cause, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-foreground">
                        <Badge variant="outline" className="shrink-0 mt-0.5 text-[10px] px-1.5">{i + 1}</Badge>
                        {cause}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            {/* Step-by-Step Fix */}
            {solution.stepByStepFix?.length > 0 && (
              <Card className="border-primary/30">
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg flex items-center gap-2 text-primary">
                    <CheckCircle className="w-4 h-4" />
                    Step-by-Step Fix
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {solution.stepByStepFix.map((step) => (
                    <div key={step.step} className="flex gap-3">
                      <div className="w-7 h-7 rounded-full bg-primary/10 text-primary flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                        {step.step}
                      </div>
                      <div className="flex-1 space-y-1.5">
                        <p className="text-sm font-semibold text-foreground">{step.title}</p>
                        <p className="text-sm text-muted-foreground">{step.description}</p>
                        {step.command && (
                          <div className="flex items-center gap-2 bg-muted rounded-lg p-2.5 mt-2">
                            <Terminal className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                            <code className="text-xs font-mono text-foreground flex-1 break-all">{step.command}</code>
                            <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0" onClick={() => copyCommand(step.command!)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Customer Reply */}
            {solution.customerReply && (
              <Card className="border-primary/30 bg-primary/5">
                <CardHeader className="pb-3 flex flex-row items-start justify-between space-y-0">
                  <div>
                    <CardTitle className="text-lg flex items-center gap-2 text-primary">
                      <MessageSquare className="w-4 h-4" />
                      Reply to Customer
                    </CardTitle>
                    <CardDescription>Ready-to-send response you can paste into the ticket</CardDescription>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => copyText(solution.customerReply!, "Reply copied")}>
                    <Copy className="w-3.5 h-3.5 mr-1.5" /> Copy
                  </Button>
                </CardHeader>
                <CardContent>
                  <pre className="whitespace-pre-wrap text-sm text-foreground bg-background border border-border/50 p-4 rounded-lg font-sans leading-relaxed">
                    {solution.customerReply}
                  </pre>
                </CardContent>
              </Card>
            )}

            {/* Additional Notes */}
            {solution.additionalNotes && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Lightbulb className="w-4 h-4" />
                    Additional Notes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground leading-relaxed">{solution.additionalNotes}</p>
                </CardContent>
              </Card>
            )}

            {/* References */}
            {solution.references?.length > 0 && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <BookOpen className="w-4 h-4" />
                    References
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {solution.references.map((ref, i) => (
                      <li key={i}>
                        <a
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-primary hover:underline flex items-center gap-1.5"
                        >
                          <ExternalLink className="w-3 h-3 shrink-0" />
                          {ref.title}
                        </a>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </div>
    </Sidebar>
  );
};

export default ErrorSolver;
