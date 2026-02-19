import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileText, Search, AlertTriangle, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";

interface LogAnalysisResult {
  totalLines: number;
  errorCount: number;
  warningCount: number;
  infoCount: number;
  topIPs: { ip: string; count: number }[];
  topErrors: { error: string; count: number }[];
  timeRange: { start: string; end: string };
}

const LogAnalyzer = () => {
  const [logInput, setLogInput] = useState("");
  const [logType, setLogType] = useState("syslog");
  const [searchTerm, setSearchTerm] = useState("");
  const [analysis, setAnalysis] = useState<LogAnalysisResult | null>(null);
  const [filteredLogs, setFilteredLogs] = useState("");

  const analyzeLogs = () => {
    if (!logInput.trim()) {
      toast.error("Please paste log content to analyze");
      return;
    }

    const lines = logInput.split("\n").filter(line => line.trim());
    
    // Count log levels
    let errorCount = 0;
    let warningCount = 0;
    let infoCount = 0;

    // Extract IPs
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ipMap = new Map<string, number>();
    
    // Extract errors
    const errorMap = new Map<string, number>();

    lines.forEach(line => {
      const lowerLine = line.toLowerCase();
      
      if (lowerLine.includes("error") || lowerLine.includes("fatal") || lowerLine.includes("critical")) {
        errorCount++;
        const errorMatch = line.match(/error|fatal|critical.*$/i);
        if (errorMatch) {
          const errorMsg = errorMatch[0].substring(0, 100);
          errorMap.set(errorMsg, (errorMap.get(errorMsg) || 0) + 1);
        }
      } else if (lowerLine.includes("warn") || lowerLine.includes("warning")) {
        warningCount++;
      } else if (lowerLine.includes("info") || lowerLine.includes("notice")) {
        infoCount++;
      }

      const ips = line.match(ipRegex);
      if (ips) {
        ips.forEach(ip => {
          ipMap.set(ip, (ipMap.get(ip) || 0) + 1);
        });
      }
    });

    // Get top IPs
    const topIPs = Array.from(ipMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    // Get top errors
    const topErrors = Array.from(errorMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([error, count]) => ({ error, count }));

    // Extract time range (simplified)
    const firstLine = lines[0] || "";
    const lastLine = lines[lines.length - 1] || "";
    
    setAnalysis({
      totalLines: lines.length,
      errorCount,
      warningCount,
      infoCount,
      topIPs,
      topErrors,
      timeRange: {
        start: firstLine.substring(0, 20) || "N/A",
        end: lastLine.substring(0, 20) || "N/A",
      },
    });

    toast.success("Log analysis completed!");
  };

  // Detect potentially dangerous regex patterns (ReDoS)
  const isSafeRegex = (pattern: string): boolean => {
    // Block nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
    if (/(\+|\*|\{)\s*\)\s*(\+|\*|\{)/.test(pattern)) return false;
    // Block excessive alternation with quantifiers like (a|a)*
    if (/\(([^)]*\|){5,}[^)]*\)[\+\*]/.test(pattern)) return false;
    return true;
  };

  const searchLogs = () => {
    if (!searchTerm.trim() || !logInput.trim()) {
      toast.error("Please enter both log content and search term");
      return;
    }

    if (searchTerm.length > 100) {
      toast.error("Search pattern too long (max 100 characters)");
      return;
    }

    if (!isSafeRegex(searchTerm)) {
      toast.error("This regex pattern is not allowed due to potential performance issues");
      return;
    }

    let regex: RegExp;
    try {
      regex = new RegExp(searchTerm, "gi");
    } catch {
      toast.error("Invalid regex pattern");
      return;
    }

    const lines = logInput.split("\n");
    const matches: string[] = [];
    for (const line of lines) {
      try {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          matches.push(line);
        }
      } catch {
        break;
      }
    }

    setFilteredLogs(matches.join("\n") || "No matches found");
    toast.success(`Found ${matches.length} matching lines`);
  };

  const loadSampleLog = () => {
    const sample = `2025-01-20 10:15:32 INFO [system] Server started successfully
2025-01-20 10:15:45 INFO [auth] User admin logged in from 192.168.1.100
2025-01-20 10:16:12 ERROR [database] Connection timeout to 10.0.0.5:3306
2025-01-20 10:16:15 WARNING [disk] Disk usage above 85% on /var/log
2025-01-20 10:17:23 INFO [api] GET /api/users - 200 OK - 192.168.1.100
2025-01-20 10:18:45 ERROR [network] Failed to reach external service at 203.0.113.42
2025-01-20 10:19:12 INFO [cache] Cache cleared successfully
2025-01-20 10:20:33 ERROR [auth] Failed login attempt from 192.168.1.150
2025-01-20 10:21:45 WARNING [memory] Memory usage at 92%
2025-01-20 10:22:18 CRITICAL [database] Database connection lost
2025-01-20 10:23:50 INFO [backup] Daily backup completed
2025-01-20 10:24:12 ERROR [api] POST /api/upload - 500 Internal Server Error
2025-01-20 10:25:33 WARNING [ssl] Certificate expires in 7 days
2025-01-20 10:26:45 INFO [scheduler] Cron job executed successfully
2025-01-20 10:27:12 ERROR [auth] Failed login attempt from 192.168.1.150`;

    setLogInput(sample);
    toast.success("Sample log loaded!");
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-8">
          <div className="text-center my-8">
            <div className="flex items-center justify-center gap-3 mb-4">
              <FileText className="w-10 h-10 text-primary" />
              <h1 className="text-4xl font-bold text-foreground">Log Analyzer</h1>
            </div>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Parse and analyze system logs, web server logs, and application logs
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            <div className="space-y-6">
              <Card className="border-border/40 shadow-lg">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="w-5 h-5" />
                    Log Input
                  </CardTitle>
                  <CardDescription>Paste your log content for analysis</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label className="text-foreground mb-2 block">Log Type</Label>
                  <Select value={logType} onValueChange={setLogType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="syslog">Syslog</SelectItem>
                      <SelectItem value="nginx">Nginx</SelectItem>
                      <SelectItem value="apache">Apache</SelectItem>
                      <SelectItem value="application">Application</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="logInput" className="text-foreground mb-2 block">
                    Log Content <span className="text-destructive">*</span>
                  </Label>
                  <Textarea
                    id="logInput"
                    placeholder="Paste your log content here..."
                    value={logInput}
                    onChange={(e) => setLogInput(e.target.value)}
                    className="font-mono text-sm h-64"
                  />
                </div>

                <div className="flex gap-2">
                  <Button onClick={analyzeLogs} className="flex-1">
                    Analyze Logs
                  </Button>
                  <Button onClick={loadSampleLog} variant="outline">
                    Load Sample
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/40 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="w-5 h-5" />
                  Search Logs
                </CardTitle>
                <CardDescription>Find specific entries using regex patterns</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="searchTerm" className="text-foreground mb-2 block">
                    Search Pattern (Regex)
                  </Label>
                  <Input
                    id="searchTerm"
                    placeholder="ERROR|CRITICAL or 192.168.*.* or timeout"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>

                <Button onClick={searchLogs} className="w-full">
                  <Search className="w-4 h-4 mr-2" />
                  Search
                </Button>

                {filteredLogs && (
                  <div>
                    <Label className="text-foreground mb-2 block">Search Results</Label>
                    <Textarea
                      value={filteredLogs}
                      readOnly
                      className="font-mono text-sm h-48 bg-muted"
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5" />
                Analysis Results
              </CardTitle>
              <CardDescription>Statistical breakdown of log content</CardDescription>
            </CardHeader>
            <CardContent>
              {!analysis ? (
                <div className="text-center py-12 text-muted-foreground">
                  <FileText className="w-16 h-16 mx-auto mb-4 opacity-20" />
                  <p>Paste logs and click analyze to see results</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-muted/30 p-4 rounded-lg">
                      <div className="text-sm text-muted-foreground mb-1">Total Lines</div>
                      <div className="text-2xl font-bold text-foreground">{analysis.totalLines}</div>
                    </div>
                    <div className="bg-destructive/10 p-4 rounded-lg">
                      <div className="text-sm text-muted-foreground mb-1">Errors</div>
                      <div className="text-2xl font-bold text-destructive">{analysis.errorCount}</div>
                    </div>
                    <div className="bg-yellow-500/10 p-4 rounded-lg">
                      <div className="text-sm text-muted-foreground mb-1">Warnings</div>
                      <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-500">{analysis.warningCount}</div>
                    </div>
                    <div className="bg-primary/10 p-4 rounded-lg">
                      <div className="text-sm text-muted-foreground mb-1">Info</div>
                      <div className="text-2xl font-bold text-primary">{analysis.infoCount}</div>
                    </div>
                  </div>

                  {analysis.topIPs.length > 0 && (
                    <div>
                      <Label className="text-sm font-semibold mb-3 block">Top IP Addresses</Label>
                      <div className="space-y-2">
                        {analysis.topIPs.map((item, index) => (
                          <div key={index} className="flex justify-between items-center bg-muted/30 p-2 rounded">
                            <span className="font-mono text-sm">{item.ip}</span>
                            <span className="text-sm font-semibold text-primary">{item.count} requests</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {analysis.topErrors.length > 0 && (
                    <div>
                      <Label className="text-sm font-semibold mb-3 block flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-destructive" />
                        Top Errors
                      </Label>
                      <div className="space-y-2">
                        {analysis.topErrors.map((item, index) => (
                          <div key={index} className="bg-destructive/5 p-3 rounded border border-destructive/20">
                            <div className="text-xs font-mono text-muted-foreground mb-1 truncate">
                              {item.error}
                            </div>
                            <div className="text-sm font-semibold text-destructive">
                              {item.count} occurrences
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="bg-muted/30 p-4 rounded-lg">
                    <Label className="text-sm font-semibold mb-2 block">Time Range</Label>
                    <div className="text-xs font-mono space-y-1">
                      <div><span className="text-muted-foreground">Start:</span> {analysis.timeRange.start}</div>
                      <div><span className="text-muted-foreground">End:</span> {analysis.timeRange.end}</div>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
          </div>
        </div>
      </div>
    </Sidebar>
  );
};

export default LogAnalyzer;
