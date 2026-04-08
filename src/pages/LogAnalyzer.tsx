import { useState, useMemo, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  FileText, Search, AlertTriangle, CheckCircle2, Download, Trash2, Upload, BarChart3,
  Activity, Shield, Eye, Filter, TrendingUp, Zap, Terminal, XCircle, Info, AlertCircle,
  Bug, ChevronDown, ChevronUp, Copy, RefreshCw, Link2, Brain, Loader2, ShieldAlert,
  Gauge, ArrowRight, Network, Server, Globe,
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
import {
  parseLogs, computeStats, filterEntries, exportToCSV, exportToJSON,
  getSeverityColor, getSeverityBadgeColor, correlateEvents, detectSecurityFindings, computeHealthScore,
  type ParsedLogEntry, type LogFormat,
} from "@/utils/logParser";
import { supabase } from "@/integrations/supabase/client";

const SEVERITY_OPTIONS: ParsedLogEntry["severity"][] = [
  "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
];

const SEVERITY_ICONS: Record<string, React.ReactNode> = {
  emergency: <XCircle className="w-3 h-3" />,
  alert: <AlertTriangle className="w-3 h-3" />,
  critical: <AlertCircle className="w-3 h-3" />,
  error: <Bug className="w-3 h-3" />,
  warning: <AlertTriangle className="w-3 h-3" />,
  notice: <Info className="w-3 h-3" />,
  info: <Info className="w-3 h-3" />,
  debug: <Terminal className="w-3 h-3" />,
};

const SAMPLE_LOGS: Record<string, string> = {
  syslog: `Jan 20 10:15:32 webserver01 nginx[1234]: 192.168.1.100 - - [20/Jan/2025:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 1542
Jan 20 10:15:45 webserver01 sshd[5678]: Accepted publickey for admin from 192.168.1.50 port 22
Jan 20 10:16:12 dbserver01 mysql[9012]: ERROR 2003 (HY000): Can't connect to MySQL server on '10.0.0.5' (111)
Jan 20 10:16:15 webserver01 systemd[1]: disk-check.service: Disk usage above 85% on /var/log
Jan 20 10:17:23 webserver01 nginx[1234]: 192.168.1.100 - - [20/Jan/2025:10:17:23 +0000] "GET /api/health HTTP/1.1" 200 15
Jan 20 10:18:45 webserver01 nginx[1234]: 203.0.113.42 - - [20/Jan/2025:10:18:45 +0000] "POST /api/login HTTP/1.1" 401 89
Jan 20 10:19:12 cacheserver01 redis[3456]: WARNING: Memory usage at 92%
Jan 20 10:20:33 webserver01 nginx[1234]: 192.168.1.150 - - [20/Jan/2025:10:20:33 +0000] "GET /admin HTTP/1.1" 403 0
Jan 20 10:21:45 dbserver01 mysql[9012]: CRITICAL: Replication lag exceeds 300 seconds
Jan 20 10:22:18 webserver01 crond[7890]: Daily backup completed successfully
Jan 20 10:23:50 webserver01 nginx[1234]: 10.0.0.100 - - [20/Jan/2025:10:23:50 +0000] "POST /api/upload HTTP/1.1" 500 0
Jan 20 10:24:12 webserver01 certbot[2345]: WARNING: Certificate for example.com expires in 7 days
Jan 20 10:25:33 webserver01 sshd[5678]: Failed password for root from 203.0.113.99 port 22
Jan 20 10:26:45 webserver01 sshd[5678]: Failed password for root from 203.0.113.99 port 22
Jan 20 10:27:12 webserver01 fail2ban[4567]: WARNING: Banning IP 203.0.113.99 for repeated failures`,

  json: `{"timestamp":"2025-01-20T10:15:32Z","level":"info","service":"api-gateway","host":"prod-01","message":"Request processed","method":"GET","path":"/api/users","status":200,"duration_ms":45}
{"timestamp":"2025-01-20T10:15:45Z","level":"info","service":"auth-service","host":"prod-02","message":"User authenticated","user_id":"usr_abc123","ip":"192.168.1.100"}
{"timestamp":"2025-01-20T10:16:12Z","level":"error","service":"database","host":"db-01","message":"Connection pool exhausted","active_connections":100,"max_connections":100}
{"timestamp":"2025-01-20T10:16:15Z","level":"warning","service":"monitoring","host":"prod-01","message":"High CPU usage detected","cpu_percent":94.5}
{"timestamp":"2025-01-20T10:17:23Z","level":"error","service":"api-gateway","host":"prod-01","message":"Upstream timeout","path":"/api/reports","timeout_ms":30000}
{"timestamp":"2025-01-20T10:18:45Z","level":"info","service":"scheduler","host":"worker-01","message":"Cron job completed","job":"cleanup_sessions","duration_ms":1200}
{"timestamp":"2025-01-20T10:19:12Z","level":"critical","service":"database","host":"db-01","message":"Replication lag critical","lag_seconds":450}
{"timestamp":"2025-01-20T10:20:33Z","level":"warning","service":"storage","host":"storage-01","message":"Disk space low","available_gb":5.2,"total_gb":100}
{"timestamp":"2025-01-20T10:21:45Z","level":"info","service":"api-gateway","host":"prod-02","message":"Request processed","method":"POST","path":"/api/orders","status":201,"duration_ms":120}
{"timestamp":"2025-01-20T10:22:18Z","level":"error","service":"email-service","host":"worker-01","message":"SMTP connection failed","smtp_host":"mail.example.com","error_code":"ECONNREFUSED"}`,

  application: `2025-01-20 10:15:32 INFO [system] Server started successfully on port 8080
2025-01-20 10:15:45 INFO [auth] User admin logged in from 192.168.1.100
2025-01-20 10:16:12 ERROR [database] Connection timeout to 10.0.0.5:3306 after 30s
2025-01-20 10:16:15 WARNING [disk] Disk usage above 85% on /var/log (87.3%)
2025-01-20 10:17:23 INFO [api] GET /api/users - 200 OK - 45ms - 192.168.1.100
2025-01-20 10:18:45 ERROR [network] Failed to reach external service at 203.0.113.42
2025-01-20 10:19:12 INFO [cache] Cache cleared - 2,450 entries removed
2025-01-20 10:20:33 ERROR [auth] Failed login attempt from 192.168.1.150 - invalid password
2025-01-20 10:21:45 WARNING [memory] Memory usage at 92% (7.36GB/8GB)
2025-01-20 10:22:18 CRITICAL [database] Primary database connection lost - failover initiated
2025-01-20 10:23:50 INFO [backup] Daily backup completed - 2.3GB compressed
2025-01-20 10:24:12 ERROR [api] POST /api/upload - 500 Internal Server Error - file too large
2025-01-20 10:25:33 WARNING [ssl] Certificate for api.example.com expires in 7 days
2025-01-20 10:26:45 INFO [scheduler] Cron job cleanup_logs executed successfully
2025-01-20 10:27:12 ERROR [auth] Brute force detected from 192.168.1.150 - account locked`,
};

const LogAnalyzer = () => {
  const [logInput, setLogInput] = useState("");
  const [logFormat, setLogFormat] = useState<LogFormat>("auto");
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<ParsedLogEntry["severity"][]>([]);
  const [hostFilter, setHostFilter] = useState("");
  const [serviceFilter, setServiceFilter] = useState("");
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [expandedCorrelation, setExpandedCorrelation] = useState<number | null>(null);

  const { entries, detectedFormat } = useMemo(() => {
    if (!logInput.trim()) return { entries: [], detectedFormat: "auto" as LogFormat };
    return parseLogs(logInput, logFormat);
  }, [logInput, logFormat]);

  const stats = useMemo(() => computeStats(entries), [entries]);
  const correlations = useMemo(() => correlateEvents(entries), [entries]);
  const securityFindings = useMemo(() => detectSecurityFindings(entries), [entries]);
  const healthScore = useMemo(() => computeHealthScore(stats, securityFindings), [stats, securityFindings]);

  const filteredEntries = useMemo(() =>
    filterEntries(entries, {
      severity: severityFilter.length ? severityFilter : undefined,
      search: searchTerm || undefined,
      host: hostFilter || undefined,
      service: serviceFilter || undefined,
    }), [entries, severityFilter, searchTerm, hostFilter, serviceFilter]);

  const uniqueHosts = useMemo(() => [...new Set(entries.map(e => e.host).filter(Boolean))] as string[], [entries]);
  const uniqueServices = useMemo(() => [...new Set(entries.map(e => e.service).filter(Boolean))] as string[], [entries]);

  const handleExport = useCallback((format: "csv" | "json") => {
    const data = format === "csv" ? exportToCSV(filteredEntries) : exportToJSON(filteredEntries);
    const blob = new Blob([data], { type: format === "csv" ? "text/csv" : "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logs-export-${new Date().toISOString().slice(0, 10)}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${filteredEntries.length} entries as ${format.toUpperCase()}`);
  }, [filteredEntries]);

  const toggleSeverity = (sev: ParsedLogEntry["severity"]) => {
    setSeverityFilter(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  const clearAll = () => {
    setLogInput(""); setSearchTerm(""); setSeverityFilter([]);
    setHostFilter(""); setServiceFilter(""); setExpandedRow(null);
    setActiveTab("dashboard"); setAiAnalysis(null);
  };

  const runAIAnalysis = async () => {
    if (!entries.length) return;
    setAiLoading(true);
    setAiAnalysis(null);
    try {
      const errorSummary = stats.topErrors.slice(0, 5).map(e => `- ${e.message} (${e.count}x)`).join("\n");
      const secSummary = securityFindings.slice(0, 3).map(f => `- [${f.severity}] ${f.title}: ${f.description}`).join("\n");
      const prompt = `You are a senior Linux systems engineer. Analyze these server logs and provide actionable root cause analysis.

LOG SUMMARY:
- Total events: ${stats.total}, Format: ${detectedFormat}
- Error rate: ${((stats.bySeverity.error + stats.bySeverity.critical) / stats.total * 100).toFixed(1)}%
- Critical: ${stats.bySeverity.critical}, Errors: ${stats.bySeverity.error}, Warnings: ${stats.bySeverity.warning}
- Services: ${uniqueServices.join(", ") || "N/A"}
- Hosts: ${uniqueHosts.join(", ") || "N/A"}
- Health Score: ${healthScore.score}/100 (${healthScore.grade})

TOP ERRORS:
${errorSummary || "None"}

SECURITY FINDINGS:
${secSummary || "None detected"}

SAMPLE LOG ENTRIES (first 10 errors/criticals):
${entries.filter(e => e.severity === "error" || e.severity === "critical").slice(0, 10).map(e => e.raw).join("\n")}

Provide:
1. **Root Cause Analysis** — What's likely causing the issues
2. **Impact Assessment** — Business/system impact
3. **Immediate Actions** — Quick fixes to apply now
4. **Long-term Fixes** — Architectural improvements
5. **Commands to Run** — Specific Linux commands to diagnose/fix

Be specific and practical. Use markdown formatting.`;

      const { data, error } = await supabase.functions.invoke("text-tools", {
        body: { action: "custom", text: prompt, customPrompt: "Respond with detailed technical analysis in markdown format. Be specific with commands and file paths." },
      });
      if (error) throw error;
      setAiAnalysis(data?.result || data?.enhanced || "Analysis complete but no output received.");
    } catch (err: any) {
      toast.error("AI analysis failed: " + (err.message || "Unknown error"));
    } finally {
      setAiLoading(false);
    }
  };

  const hasData = entries.length > 0;
  const errorRate = hasData ? ((stats.bySeverity.error + stats.bySeverity.critical + stats.bySeverity.emergency + stats.bySeverity.alert) / stats.total * 100).toFixed(1) : "0";

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-6 max-w-[1600px]">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 shadow-lg shadow-primary/5">
                <Activity className="w-7 h-7 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Log Analyzer Pro</h1>
                <p className="text-sm text-muted-foreground">Production-grade log parsing, security analysis & AI-powered insights</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {hasData && (
                <>
                  <Badge variant="outline" className="font-mono text-xs px-3 py-1">
                    {detectedFormat.toUpperCase()} • {entries.length} entries
                  </Badge>
                  <Button variant="outline" size="sm" onClick={() => handleExport("csv")} className="gap-1.5">
                    <Download className="w-3.5 h-3.5" /> CSV
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => handleExport("json")} className="gap-1.5">
                    <Download className="w-3.5 h-3.5" /> JSON
                  </Button>
                </>
              )}
              <Button variant="ghost" size="sm" onClick={clearAll} className="gap-1.5">
                <Trash2 className="w-3.5 h-3.5" /> Clear
              </Button>
            </div>
          </div>

          {/* Input Section */}
          <Card className="border-border/40 shadow-lg mb-6 overflow-hidden">
            <CardContent className="p-4">
              <div className="flex items-end gap-4 mb-3">
                <div className="flex-1">
                  <Label className="text-xs text-muted-foreground mb-1 block">Log Format</Label>
                  <Select value={logFormat} onValueChange={(v) => setLogFormat(v as LogFormat)}>
                    <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">🔍 Auto-detect</SelectItem>
                      <SelectItem value="syslog">📋 Syslog</SelectItem>
                      <SelectItem value="json">📦 JSON</SelectItem>
                      <SelectItem value="nginx">🌐 Nginx / Apache</SelectItem>
                      <SelectItem value="systemd">⚙️ Systemd Journal</SelectItem>
                      <SelectItem value="application">📝 Application Log</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex gap-2">
                  <Select onValueChange={(v) => { setLogInput(SAMPLE_LOGS[v] || ""); toast.success("Sample loaded"); }}>
                    <SelectTrigger className="h-9 w-[160px]"><SelectValue placeholder="Load sample..." /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="syslog">Syslog Sample</SelectItem>
                      <SelectItem value="json">JSON Sample</SelectItem>
                      <SelectItem value="application">App Log Sample</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="outline" size="sm" className="h-9 gap-1.5" onClick={() => {
                    const input = document.createElement("input"); input.type = "file"; input.accept = ".log,.txt,.json";
                    input.onchange = (e) => {
                      const file = (e.target as HTMLInputElement).files?.[0];
                      if (file) { const reader = new FileReader(); reader.onload = (ev) => { setLogInput(ev.target?.result as string); toast.success(`Loaded ${file.name}`); }; reader.readAsText(file); }
                    }; input.click();
                  }}>
                    <Upload className="w-3.5 h-3.5" /> Upload
                  </Button>
                </div>
              </div>
              <Textarea
                placeholder="Paste your logs here... Supports syslog, JSON, nginx, systemd, and application log formats."
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                className="font-mono text-xs h-36 resize-y bg-muted/30 border-border/50"
              />
              {logInput && (
                <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                  <CheckCircle2 className="w-3 h-3 text-primary" />
                  Detected: <Badge variant="secondary" className="text-xs">{detectedFormat}</Badge>
                  • {entries.length} lines parsed • {stats.bySeverity.error + stats.bySeverity.critical} errors
                </div>
              )}
            </CardContent>
          </Card>

          {hasData && (
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
              <TabsList className="grid w-full grid-cols-6 h-11 bg-muted/50">
                <TabsTrigger value="dashboard" className="text-xs gap-1.5 data-[state=active]:shadow-md"><BarChart3 className="w-3.5 h-3.5" /> Dashboard</TabsTrigger>
                <TabsTrigger value="logs" className="text-xs gap-1.5 data-[state=active]:shadow-md"><FileText className="w-3.5 h-3.5" /> Log Viewer</TabsTrigger>
                <TabsTrigger value="security" className="text-xs gap-1.5 data-[state=active]:shadow-md">
                  <Shield className="w-3.5 h-3.5" /> Security
                  {securityFindings.length > 0 && <span className="ml-1 bg-destructive text-destructive-foreground rounded-full w-4 h-4 text-[10px] flex items-center justify-center">{securityFindings.length}</span>}
                </TabsTrigger>
                <TabsTrigger value="correlation" className="text-xs gap-1.5 data-[state=active]:shadow-md"><Link2 className="w-3.5 h-3.5" /> Correlation</TabsTrigger>
                <TabsTrigger value="patterns" className="text-xs gap-1.5 data-[state=active]:shadow-md"><TrendingUp className="w-3.5 h-3.5" /> Patterns</TabsTrigger>
                <TabsTrigger value="ai-insights" className="text-xs gap-1.5 data-[state=active]:shadow-md"><Brain className="w-3.5 h-3.5" /> AI Insights</TabsTrigger>
              </TabsList>

              {/* ==================== DASHBOARD TAB ==================== */}
              <TabsContent value="dashboard">
                <div className="space-y-4">
                  {/* Health Score Banner */}
                  <Card className="border-border/40 overflow-hidden">
                    <div className={`h-1 ${healthScore.score >= 85 ? "bg-green-500" : healthScore.score >= 70 ? "bg-yellow-500" : healthScore.score >= 55 ? "bg-orange-500" : "bg-red-500"}`} />
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className={`w-16 h-16 rounded-xl flex items-center justify-center text-2xl font-bold text-white ${healthScore.score >= 85 ? "bg-green-500" : healthScore.score >= 70 ? "bg-yellow-500" : healthScore.score >= 55 ? "bg-orange-500" : "bg-red-500"}`}>
                            {healthScore.grade}
                          </div>
                          <div>
                            <h3 className="text-lg font-bold text-foreground">System Health: {healthScore.score}/100</h3>
                            <p className="text-sm text-muted-foreground">
                              {healthScore.score >= 85 ? "Systems operating normally" : healthScore.score >= 70 ? "Minor issues detected — review recommended" : healthScore.score >= 55 ? "Multiple issues — investigation needed" : "Critical issues — immediate action required"}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-6 text-center">
                          <div><p className="text-2xl font-bold text-foreground">{stats.total}</p><p className="text-[10px] text-muted-foreground uppercase tracking-wider">Events</p></div>
                          <div><p className="text-2xl font-bold text-destructive">{stats.bySeverity.error + stats.bySeverity.critical}</p><p className="text-[10px] text-muted-foreground uppercase tracking-wider">Errors</p></div>
                          <div><p className="text-2xl font-bold text-yellow-500">{stats.bySeverity.warning}</p><p className="text-[10px] text-muted-foreground uppercase tracking-wider">Warnings</p></div>
                          <div><p className="text-2xl font-bold text-foreground">{securityFindings.length}</p><p className="text-[10px] text-muted-foreground uppercase tracking-wider">Threats</p></div>
                        </div>
                      </div>
                      {healthScore.factors.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {healthScore.factors.map((f, i) => (
                            <Badge key={i} variant="outline" className="text-xs gap-1">
                              <span className="text-destructive font-bold">{f.impact}</span> {f.name}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Metric Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                    <MetricCard label="Total Events" value={stats.total} icon={<FileText className="w-4 h-4" />} />
                    <MetricCard label="Error Rate" value={`${errorRate}%`} icon={<Activity className="w-4 h-4" />} color={parseFloat(errorRate) > 10 ? "text-destructive" : "text-primary"} />
                    <MetricCard label="Critical" value={stats.bySeverity.critical + stats.bySeverity.emergency} icon={<AlertCircle className="w-4 h-4" />} color="text-red-500" />
                    <MetricCard label="Unique IPs" value={stats.topIPs.length} icon={<Globe className="w-4 h-4" />} />
                    <MetricCard label="Services" value={uniqueServices.length} icon={<Server className="w-4 h-4" />} />
                    <MetricCard label="Hosts" value={uniqueHosts.length} icon={<Network className="w-4 h-4" />} />
                  </div>

                  <div className="grid md:grid-cols-2 gap-4">
                    {/* Severity Distribution */}
                    <Card className="border-border/40">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="w-4 h-4" /> Severity Distribution</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {SEVERITY_OPTIONS.map(sev => {
                            const count = stats.bySeverity[sev];
                            const pct = stats.total ? (count / stats.total * 100) : 0;
                            if (count === 0) return null;
                            return (
                              <div key={sev} className="flex items-center gap-2">
                                <span className="text-xs w-16 capitalize text-muted-foreground">{sev}</span>
                                <div className="flex-1 h-5 bg-muted/30 rounded-full overflow-hidden">
                                  <div className={`h-full rounded-full transition-all ${getSeverityBarColor(sev)}`} style={{ width: `${Math.max(pct, 2)}%` }} />
                                </div>
                                <span className="text-xs font-mono w-20 text-right text-muted-foreground">{count} ({pct.toFixed(1)}%)</span>
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>

                    {/* Top Errors */}
                    <Card className="border-border/40">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-destructive" /> Top Errors</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[200px]">
                          {stats.topErrors.length === 0 ? (
                            <div className="text-center py-8 text-muted-foreground">
                              <CheckCircle2 className="w-8 h-8 mx-auto mb-2 opacity-30" />
                              <p className="text-xs">No errors found</p>
                            </div>
                          ) : (
                            <div className="space-y-2">
                              {stats.topErrors.map((err, i) => (
                                <div key={i} className="p-2.5 rounded-lg bg-destructive/5 border border-destructive/10">
                                  <p className="text-xs font-mono text-foreground truncate">{err.message}</p>
                                  <p className="text-xs text-destructive font-semibold mt-1">{err.count} occurrences</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Services, Hosts, IPs */}
                  <div className="grid md:grid-cols-3 gap-4">
                    {stats.byService.length > 0 && (
                      <Card className="border-border/40">
                        <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Server className="w-4 h-4" /> Services</CardTitle></CardHeader>
                        <CardContent>
                          <div className="space-y-1.5">
                            {stats.byService.map((s, i) => (
                              <div key={i} className="flex justify-between items-center text-xs">
                                <span className="font-mono text-foreground">{s.name}</span>
                                <Badge variant="secondary" className="text-xs">{s.count}</Badge>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                    {stats.byHost.length > 0 && (
                      <Card className="border-border/40">
                        <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Network className="w-4 h-4" /> Hosts</CardTitle></CardHeader>
                        <CardContent>
                          <div className="space-y-1.5">
                            {stats.byHost.map((h, i) => (
                              <div key={i} className="flex justify-between items-center text-xs">
                                <span className="font-mono text-foreground">{h.name}</span>
                                <Badge variant="secondary" className="text-xs">{h.count}</Badge>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                    {stats.topIPs.length > 0 && (
                      <Card className="border-border/40">
                        <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Globe className="w-4 h-4" /> Top IPs</CardTitle></CardHeader>
                        <CardContent>
                          <div className="space-y-1.5">
                            {stats.topIPs.map((ip, i) => (
                              <div key={i} className="flex justify-between items-center text-xs">
                                <span className="font-mono text-foreground">{ip.ip}</span>
                                <Badge variant="secondary" className="text-xs">{ip.count}</Badge>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                  </div>

                  {/* Timeline */}
                  {stats.eventsPerMinute.length > 1 && (
                    <Card className="border-border/40">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2"><Activity className="w-4 h-4" /> Event Timeline</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex items-end gap-1 h-24">
                          {stats.eventsPerMinute.map((point, i) => {
                            const maxCount = Math.max(...stats.eventsPerMinute.map(p => p.count));
                            const height = maxCount ? (point.count / maxCount * 100) : 0;
                            return (
                              <div key={i} className="flex-1 flex flex-col items-center gap-1 group relative">
                                <div className="w-full bg-primary/60 hover:bg-primary rounded-t transition-all min-h-[2px]" style={{ height: `${height}%` }} />
                                <div className="absolute -top-6 left-1/2 -translate-x-1/2 hidden group-hover:block bg-popover border border-border rounded px-2 py-1 text-xs whitespace-nowrap shadow-lg z-10">
                                  {point.time}: {point.count} events
                                </div>
                              </div>
                            );
                          })}
                        </div>
                        <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
                          <span>{stats.eventsPerMinute[0]?.time}</span>
                          <span>{stats.eventsPerMinute[stats.eventsPerMinute.length - 1]?.time}</span>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>

              {/* ==================== LOG VIEWER TAB ==================== */}
              <TabsContent value="logs">
                <Card className="border-border/40 mb-4">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm flex items-center gap-2"><Filter className="w-4 h-4" /> Filters & Search</CardTitle>
                      <span className="text-xs text-muted-foreground font-mono">{filteredEntries.length} / {entries.length}</span>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex gap-2">
                      <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                        <Input placeholder="Full-text search across all log entries..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="pl-9 h-9 text-sm" />
                      </div>
                      {uniqueHosts.length > 0 && (
                        <Select value={hostFilter} onValueChange={setHostFilter}>
                          <SelectTrigger className="w-[150px] h-9"><SelectValue placeholder="All hosts" /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All hosts</SelectItem>
                            {uniqueHosts.map(h => <SelectItem key={h} value={h}>{h}</SelectItem>)}
                          </SelectContent>
                        </Select>
                      )}
                      {uniqueServices.length > 0 && (
                        <Select value={serviceFilter} onValueChange={setServiceFilter}>
                          <SelectTrigger className="w-[150px] h-9"><SelectValue placeholder="All services" /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All services</SelectItem>
                            {uniqueServices.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                          </SelectContent>
                        </Select>
                      )}
                      {(searchTerm || severityFilter.length || hostFilter || serviceFilter) && (
                        <Button variant="ghost" size="sm" className="h-9" onClick={() => { setSearchTerm(""); setSeverityFilter([]); setHostFilter(""); setServiceFilter(""); }}>
                          <RefreshCw className="w-3.5 h-3.5" />
                        </Button>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {SEVERITY_OPTIONS.map(sev => {
                        const count = stats.bySeverity[sev];
                        if (count === 0) return null;
                        const active = severityFilter.includes(sev);
                        return (
                          <button key={sev} onClick={() => toggleSeverity(sev)}
                            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium transition-all border ${active ? `${getSeverityBadgeColor(sev)} border-transparent` : "bg-muted/30 text-muted-foreground border-border/40 hover:bg-muted/60"}`}>
                            {SEVERITY_ICONS[sev]}
                            <span className="capitalize">{sev}</span>
                            <span className="opacity-70">({count})</span>
                          </button>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border/40">
                  <ScrollArea className="h-[500px]">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-muted/30">
                          <TableHead className="w-8 text-xs">#</TableHead>
                          <TableHead className="w-[140px] text-xs">Timestamp</TableHead>
                          <TableHead className="w-[80px] text-xs">Severity</TableHead>
                          <TableHead className="w-[100px] text-xs">Service</TableHead>
                          <TableHead className="w-[110px] text-xs">IP</TableHead>
                          <TableHead className="text-xs">Message</TableHead>
                          <TableHead className="w-10"></TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredEntries.length === 0 ? (
                          <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-12">No matching entries</TableCell></TableRow>
                        ) : filteredEntries.map(entry => (
                          <>
                            <TableRow key={entry.id} className={`cursor-pointer hover:bg-muted/50 transition-colors ${expandedRow === entry.id ? "bg-muted/30" : ""}`}
                              onClick={() => setExpandedRow(expandedRow === entry.id ? null : entry.id)}>
                              <TableCell className="font-mono text-xs text-muted-foreground">{entry.id}</TableCell>
                              <TableCell className="font-mono text-xs">{entry.timestamp || "—"}</TableCell>
                              <TableCell>
                                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${getSeverityColor(entry.severity)}`}>
                                  {SEVERITY_ICONS[entry.severity]} {entry.severity}
                                </span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{entry.service || "—"}</TableCell>
                              <TableCell className="font-mono text-xs">{entry.ip || "—"}</TableCell>
                              <TableCell className="text-xs truncate max-w-[400px]">{entry.message}</TableCell>
                              <TableCell>{expandedRow === entry.id ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}</TableCell>
                            </TableRow>
                            {expandedRow === entry.id && (
                              <TableRow key={`${entry.id}-detail`}>
                                <TableCell colSpan={7} className="bg-muted/20 p-4">
                                  <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                      <Label className="text-xs font-semibold">Raw Log Entry</Label>
                                      <Button variant="ghost" size="sm" className="h-6 text-xs gap-1" onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(entry.raw); toast.success("Copied"); }}>
                                        <Copy className="w-3 h-3" /> Copy
                                      </Button>
                                    </div>
                                    <pre className="text-xs font-mono bg-background p-3 rounded-lg border border-border overflow-x-auto whitespace-pre-wrap">{entry.raw}</pre>
                                    {Object.keys(entry.fields).length > 0 && (
                                      <div>
                                        <Label className="text-xs font-semibold mb-2 block">Extracted Fields</Label>
                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                          {Object.entries(entry.fields).map(([k, v]) => (
                                            <div key={k} className="bg-background p-2 rounded-lg border border-border">
                                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{k}</span>
                                              <p className="text-xs font-mono truncate mt-0.5">{v}</p>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </TableCell>
                              </TableRow>
                            )}
                          </>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </Card>
              </TabsContent>

              {/* ==================== SECURITY TAB ==================== */}
              <TabsContent value="security">
                <div className="space-y-4">
                  {/* Security Score */}
                  <Card className="border-border/40 overflow-hidden">
                    <div className={`h-1 ${securityFindings.length === 0 ? "bg-green-500" : securityFindings.some(f => f.severity === "critical") ? "bg-red-500" : "bg-yellow-500"}`} />
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <ShieldAlert className={`w-8 h-8 ${securityFindings.length === 0 ? "text-green-500" : "text-destructive"}`} />
                        <div>
                          <h3 className="font-bold text-foreground">
                            {securityFindings.length === 0 ? "No Security Threats Detected" : `${securityFindings.length} Security Finding${securityFindings.length > 1 ? "s" : ""} Detected`}
                          </h3>
                          <p className="text-sm text-muted-foreground">
                            {securityFindings.filter(f => f.severity === "critical").length} critical • {securityFindings.filter(f => f.severity === "high").length} high • {securityFindings.filter(f => f.severity === "medium").length} medium
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {securityFindings.length === 0 ? (
                    <Card className="border-border/40">
                      <CardContent className="py-16 text-center">
                        <Shield className="w-16 h-16 mx-auto mb-4 text-green-500/30" />
                        <p className="text-lg font-medium text-foreground mb-1">All Clear</p>
                        <p className="text-sm text-muted-foreground">No security threats identified in the analyzed logs</p>
                      </CardContent>
                    </Card>
                  ) : (
                    <div className="space-y-3">
                      {securityFindings.map((finding, i) => (
                        <Card key={i} className={`border-border/40 overflow-hidden ${finding.severity === "critical" ? "border-l-4 border-l-red-500" : finding.severity === "high" ? "border-l-4 border-l-orange-500" : "border-l-4 border-l-yellow-500"}`}>
                          <CardContent className="p-4">
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <ShieldAlert className={`w-5 h-5 ${finding.severity === "critical" ? "text-red-500" : finding.severity === "high" ? "text-orange-500" : "text-yellow-500"}`} />
                                <h4 className="font-semibold text-foreground">{finding.title}</h4>
                              </div>
                              <Badge variant={finding.severity === "critical" ? "destructive" : "secondary"}
                                className={`text-xs uppercase ${finding.severity === "high" ? "bg-orange-500 text-white" : finding.severity === "medium" ? "bg-yellow-500 text-white" : ""}`}>
                                {finding.severity}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-3">{finding.description}</p>
                            <div className="bg-muted/30 rounded-lg p-3 border border-border/50">
                              <p className="text-xs font-semibold text-foreground mb-1 flex items-center gap-1"><Zap className="w-3 h-3" /> Recommendation</p>
                              <p className="text-xs text-muted-foreground">{finding.recommendation}</p>
                            </div>
                            {finding.entries.length > 0 && (
                              <Collapsible>
                                <CollapsibleTrigger className="flex items-center gap-1 text-xs text-primary hover:underline mt-2">
                                  <Eye className="w-3 h-3" /> View {finding.entries.length} related log entries
                                </CollapsibleTrigger>
                                <CollapsibleContent>
                                  <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
                                    {finding.entries.slice(0, 10).map((e, j) => (
                                      <pre key={j} className="text-[11px] font-mono bg-background p-2 rounded border border-border overflow-x-auto whitespace-pre-wrap">{e.raw}</pre>
                                    ))}
                                    {finding.entries.length > 10 && <p className="text-xs text-muted-foreground text-center">...and {finding.entries.length - 10} more</p>}
                                  </div>
                                </CollapsibleContent>
                              </Collapsible>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}

                  {/* Suspicious IPs */}
                  <Card className="border-border/40">
                    <CardHeader className="pb-3"><CardTitle className="text-sm flex items-center gap-2"><Eye className="w-4 h-4" /> Suspicious IP Analysis</CardTitle></CardHeader>
                    <CardContent>
                      {(() => {
                        const suspiciousEntries = entries.filter(e =>
                          e.message.toLowerCase().includes("failed") || e.message.toLowerCase().includes("denied") ||
                          e.message.toLowerCase().includes("forbidden") || e.message.toLowerCase().includes("unauthorized") ||
                          e.message.includes("403") || e.message.includes("401")
                        );
                        const suspiciousIPs = new Map<string, { count: number; events: string[] }>();
                        suspiciousEntries.forEach(e => {
                          if (e.ip) {
                            const existing = suspiciousIPs.get(e.ip) || { count: 0, events: [] };
                            existing.count++;
                            if (existing.events.length < 3) existing.events.push(e.message.substring(0, 60));
                            suspiciousIPs.set(e.ip, existing);
                          }
                        });
                        const sorted = Array.from(suspiciousIPs.entries()).sort((a, b) => b[1].count - a[1].count);
                        if (sorted.length === 0) return <p className="text-xs text-muted-foreground text-center py-8">No suspicious IPs found</p>;
                        return (
                          <div className="space-y-2">
                            {sorted.map(([ip, data], i) => (
                              <div key={i} className="p-3 rounded-lg bg-muted/20 border border-border/50">
                                <div className="flex justify-between items-center mb-1">
                                  <span className="font-mono text-sm font-semibold text-foreground">{ip}</span>
                                  <Badge variant="destructive" className="text-xs">{data.count} suspicious events</Badge>
                                </div>
                                <div className="space-y-0.5">
                                  {data.events.map((ev, j) => <p key={j} className="text-[11px] text-muted-foreground font-mono truncate">• {ev}</p>)}
                                </div>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* ==================== CORRELATION TAB ==================== */}
              <TabsContent value="correlation">
                <Card className="border-border/40">
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2"><Link2 className="w-4 h-4" /> Event Correlation</CardTitle>
                    <CardDescription className="text-xs">Errors correlated with nearby events by service, host, and IP</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {correlations.length === 0 ? (
                      <div className="text-center py-12 text-muted-foreground">
                        <Link2 className="w-12 h-12 mx-auto mb-3 opacity-20" />
                        <p className="text-sm">No correlated events found</p>
                        <p className="text-xs mt-1">Events are correlated by proximity, shared service, host, or IP</p>
                      </div>
                    ) : (
                      <ScrollArea className="h-[500px]">
                        <div className="space-y-3">
                          {correlations.map((corr, i) => (
                            <div key={i} className={`rounded-lg border overflow-hidden ${corr.primary.severity === "critical" ? "border-red-500/30" : "border-border/50"}`}>
                              <button className="w-full p-3 text-left bg-muted/20 hover:bg-muted/40 transition-colors"
                                onClick={() => setExpandedCorrelation(expandedCorrelation === i ? null : i)}>
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-2">
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${getSeverityColor(corr.primary.severity)}`}>
                                      {corr.primary.severity}
                                    </span>
                                    <span className="text-xs font-mono truncate max-w-[400px]">{corr.primary.message}</span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <Badge variant="outline" className="text-[10px]">{corr.correlation}</Badge>
                                    <Badge variant="secondary" className="text-[10px]">{corr.related.length} related</Badge>
                                    {expandedCorrelation === i ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                                  </div>
                                </div>
                              </button>
                              {expandedCorrelation === i && (
                                <div className="p-3 space-y-2 border-t border-border/30">
                                  <div className="p-2 rounded bg-destructive/5 border border-destructive/10">
                                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Primary Event</p>
                                    <pre className="text-xs font-mono whitespace-pre-wrap">{corr.primary.raw}</pre>
                                  </div>
                                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                    <ArrowRight className="w-3 h-3" /> Related events:
                                  </div>
                                  {corr.related.map((rel, j) => (
                                    <div key={j} className="p-2 rounded bg-muted/20 border border-border/30">
                                      <div className="flex items-center gap-2 mb-1">
                                        <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${getSeverityColor(rel.severity)}`}>{rel.severity}</span>
                                        <span className="text-[10px] text-muted-foreground">{rel.timestamp}</span>
                                      </div>
                                      <pre className="text-[11px] font-mono whitespace-pre-wrap">{rel.raw}</pre>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* ==================== PATTERNS TAB ==================== */}
              <TabsContent value="patterns">
                <div className="grid md:grid-cols-2 gap-4">
                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm flex items-center gap-2"><TrendingUp className="w-4 h-4" /> Recurring Patterns</CardTitle>
                      <CardDescription className="text-xs">Messages grouped by template similarity</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[400px]">
                        {stats.patterns.length === 0 ? (
                          <p className="text-xs text-muted-foreground text-center py-12">No recurring patterns found</p>
                        ) : (
                          <div className="space-y-2">
                            {stats.patterns.map((p, i) => (
                              <div key={i} className={`p-3 rounded-lg border ${getSeverityColor(p.severity)} border-border/30`}>
                                <div className="flex justify-between items-start mb-1">
                                  <Badge variant="secondary" className="text-[10px]">{p.count}x</Badge>
                                  <span className={`text-[10px] uppercase font-semibold ${getSeverityColor(p.severity)}`}>{p.severity}</span>
                                </div>
                                <p className="text-xs font-mono break-all">{p.pattern}</p>
                              </div>
                            ))}
                          </div>
                        )}
                      </ScrollArea>
                    </CardContent>
                  </Card>

                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm flex items-center gap-2"><Gauge className="w-4 h-4" /> Anomaly Detection</CardTitle>
                      <CardDescription className="text-xs">Automated anomaly identification</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {parseFloat(errorRate) > 20 && <AnomalyCard type="High Error Rate" description={`Error rate is ${errorRate}% — significantly above normal (< 5%)`} level="critical" />}
                        {parseFloat(errorRate) > 5 && parseFloat(errorRate) <= 20 && <AnomalyCard type="Elevated Error Rate" description={`Error rate is ${errorRate}% — above typical threshold`} level="warning" />}
                        {stats.topIPs.some(ip => ip.count > entries.length * 0.3) && <AnomalyCard type="IP Concentration" description="Single IP responsible for >30% of traffic" level="warning" />}
                        {stats.bySeverity.critical > 0 && <AnomalyCard type="Critical Events" description={`${stats.bySeverity.critical} critical events — immediate attention needed`} level="critical" />}
                        {stats.patterns.some(p => p.count >= 5 && (p.severity === "error" || p.severity === "critical")) && <AnomalyCard type="Repeated Errors" description="Same error pattern occurring 5+ times" level="warning" />}
                        {correlations.length > 5 && <AnomalyCard type="High Correlation Density" description={`${correlations.length} correlated event chains — possible cascading failure`} level="warning" />}
                        {parseFloat(errorRate) <= 5 && stats.bySeverity.critical === 0 && correlations.length <= 5 && (
                          <div className="text-center py-8 text-muted-foreground">
                            <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-green-500/40" />
                            <p className="text-xs">No anomalies detected — logs look healthy</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* ==================== AI INSIGHTS TAB ==================== */}
              <TabsContent value="ai-insights">
                <div className="space-y-4">
                  <Card className="border-border/40 overflow-hidden">
                    <div className="h-1 bg-gradient-to-r from-primary via-purple-500 to-primary" />
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-primary/10">
                            <Brain className="w-6 h-6 text-primary" />
                          </div>
                          <div>
                            <h3 className="font-bold text-foreground">AI Root Cause Analysis</h3>
                            <p className="text-sm text-muted-foreground">Powered by AI — analyzes your logs for root causes, impact, and remediation steps</p>
                          </div>
                        </div>
                        <Button onClick={runAIAnalysis} disabled={aiLoading} className="gap-2">
                          {aiLoading ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</> : <><Brain className="w-4 h-4" /> Run Analysis</>}
                        </Button>
                      </div>

                      {!aiAnalysis && !aiLoading && (
                        <div className="text-center py-12 border border-dashed border-border rounded-lg bg-muted/10">
                          <Brain className="w-12 h-12 mx-auto mb-3 text-primary/20" />
                          <p className="text-sm text-muted-foreground mb-1">Click "Run Analysis" to get AI-powered insights</p>
                          <p className="text-xs text-muted-foreground">The AI will analyze your log patterns, identify root causes, and suggest fixes</p>
                        </div>
                      )}

                      {aiLoading && (
                        <div className="text-center py-12 border border-dashed border-border rounded-lg bg-muted/10">
                          <Loader2 className="w-10 h-10 mx-auto mb-3 text-primary animate-spin" />
                          <p className="text-sm text-foreground mb-1">Analyzing {entries.length} log entries...</p>
                          <p className="text-xs text-muted-foreground">Identifying patterns, correlating events, and generating recommendations</p>
                        </div>
                      )}

                      {aiAnalysis && (
                        <div className="prose prose-sm dark:prose-invert max-w-none bg-muted/10 rounded-lg p-6 border border-border/50">
                          <div className="whitespace-pre-wrap text-sm text-foreground font-mono leading-relaxed">{aiAnalysis}</div>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Quick Insights Summary */}
                  <div className="grid md:grid-cols-2 gap-4">
                    <Card className="border-border/40">
                      <CardHeader className="pb-3"><CardTitle className="text-sm">Summary Report</CardTitle></CardHeader>
                      <CardContent className="space-y-3 text-xs">
                        <div className="p-3 rounded-lg bg-muted/30 space-y-1.5">
                          <p><span className="font-semibold">Time Range:</span> {stats.timeRange.start || "N/A"} → {stats.timeRange.end || "N/A"}</p>
                          <p><span className="font-semibold">Format:</span> {detectedFormat}</p>
                          <p><span className="font-semibold">Total Events:</span> {stats.total}</p>
                          <p><span className="font-semibold">Error Rate:</span> {errorRate}%</p>
                          <p><span className="font-semibold">Health Score:</span> {healthScore.score}/100 ({healthScore.grade})</p>
                          <p><span className="font-semibold">Security Findings:</span> {securityFindings.length}</p>
                          <p><span className="font-semibold">Correlated Events:</span> {correlations.length}</p>
                        </div>
                      </CardContent>
                    </Card>

                    <Card className="border-border/40">
                      <CardHeader className="pb-3"><CardTitle className="text-sm">Prioritized Recommendations</CardTitle></CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {parseFloat(errorRate) > 5 && <RecommendationItem text="High error rate detected. Review top errors and address root causes." priority="high" />}
                          {stats.bySeverity.critical > 0 && <RecommendationItem text="Critical events present. These require immediate investigation." priority="high" />}
                          {securityFindings.some(f => f.severity === "critical") && <RecommendationItem text="Critical security findings. Review and remediate immediately." priority="high" />}
                          {correlations.length > 3 && <RecommendationItem text="Multiple correlated event chains. Investigate for cascading failures." priority="medium" />}
                          {stats.patterns.filter(p => p.count >= 5).length > 0 && <RecommendationItem text="Repeated error patterns. Fix recurring issues to reduce noise." priority="medium" />}
                          <RecommendationItem text="Set up automated alerting for critical severity events." priority="low" />
                          <RecommendationItem text="Implement structured logging (JSON) for better parsing." priority="low" />
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          )}

          {!hasData && (
            <div className="text-center py-20 text-muted-foreground">
              <Activity className="w-16 h-16 mx-auto mb-4 opacity-10" />
              <p className="text-lg font-medium mb-1">Paste logs above to get started</p>
              <p className="text-sm">Supports syslog, JSON, nginx, systemd, and application log formats</p>
              <p className="text-xs mt-2 opacity-60">Or load a sample to explore the tool</p>
            </div>
          )}
        </div>
      </div>
    </Sidebar>
  );
};

// Helper Components
function MetricCard({ label, value, icon, color }: { label: string; value: string | number; icon: React.ReactNode; color?: string }) {
  return (
    <Card className="border-border/40 hover:shadow-md transition-shadow">
      <CardContent className="p-3">
        <div className="flex items-center gap-2 mb-1">
          <span className={`${color || "text-muted-foreground"}`}>{icon}</span>
          <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</span>
        </div>
        <p className={`text-xl font-bold ${color || "text-foreground"}`}>{value}</p>
      </CardContent>
    </Card>
  );
}

function AnomalyCard({ type, description, level }: { type: string; description: string; level: "critical" | "warning" }) {
  return (
    <div className={`p-3 rounded-lg border ${level === "critical" ? "bg-red-500/5 border-red-500/20" : "bg-yellow-500/5 border-yellow-500/20"}`}>
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle className={`w-3.5 h-3.5 ${level === "critical" ? "text-red-500" : "text-yellow-500"}`} />
        <span className="text-xs font-semibold text-foreground">{type}</span>
        <Badge variant={level === "critical" ? "destructive" : "secondary"} className="text-[10px] ml-auto">{level}</Badge>
      </div>
      <p className="text-xs text-muted-foreground">{description}</p>
    </div>
  );
}

function RecommendationItem({ text, priority }: { text: string; priority: "high" | "medium" | "low" }) {
  const colors = { high: "bg-red-500", medium: "bg-yellow-500", low: "bg-blue-500" };
  return (
    <div className="flex items-start gap-2 p-2 rounded-lg bg-muted/20">
      <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${colors[priority]}`} />
      <p className="text-xs text-muted-foreground">{text}</p>
    </div>
  );
}

function getSeverityBarColor(severity: string): string {
  switch (severity) {
    case "emergency": case "alert": case "critical": return "bg-red-500";
    case "error": return "bg-destructive";
    case "warning": return "bg-yellow-500";
    case "notice": case "info": return "bg-blue-500";
    case "debug": return "bg-muted-foreground/50";
    default: return "bg-muted-foreground/30";
  }
}

export default LogAnalyzer;
