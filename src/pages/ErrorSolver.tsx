import { useState } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, Copy, ExternalLink, Loader2, Terminal, Search, BookOpen, Lightbulb } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

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
  additionalNotes?: string;
  rawResponse?: string;
}

const ErrorSolver = () => {
  const [errorInput, setErrorInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [solution, setSolution] = useState<SolutionData | null>(null);
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
        body: { errorMessage: errorInput.trim() },
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

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    toast({ title: "Copied", description: "Command copied to clipboard" });
  };

  return (
    <Sidebar>
      <div className="p-6 max-w-5xl mx-auto space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-destructive/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-destructive" />
            </div>
            Error Solver
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered Virtualizor error diagnosis and troubleshooting
          </p>
        </div>

        {/* Input */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <Search className="w-4 h-4" />
              Describe Your Error
            </CardTitle>
            <CardDescription>
              Paste the error message, error code, or describe the issue you're facing with Virtualizor
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              value={errorInput}
              onChange={(e) => setErrorInput(e.target.value)}
              placeholder="e.g. 'Failed to create VPS: Could not find the storage' or 'Error Code 1024' or 'KVM VPS not starting after migration'"
              className="min-h-[120px] font-mono text-sm"
            />
            <Button onClick={handleSubmit} disabled={isLoading || !errorInput.trim()} className="w-full sm:w-auto">
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing Error...
                </>
              ) : (
                <>
                  <Lightbulb className="w-4 h-4 mr-2" />
                  Find Solution
                </>
              )}
            </Button>
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
