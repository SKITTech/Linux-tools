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
import {
  FileText, Search, AlertTriangle, CheckCircle2, Download, Trash2, Upload, BarChart3,
  Activity, Shield, Eye, Filter, TrendingUp, Zap, Terminal, XCircle, Info, AlertCircle,
  Bug, ChevronDown, ChevronUp, Copy, RefreshCw,
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
import {
  parseLogs, computeStats, filterEntries, exportToCSV, exportToJSON,
  getSeverityColor, getSeverityBadgeColor,
  type ParsedLogEntry, type LogFormat, type LogStats,
} from "@/utils/logParser";

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

  const { entries, detectedFormat } = useMemo(() => {
    if (!logInput.trim()) return { entries: [], detectedFormat: "auto" as LogFormat };
    return parseLogs(logInput, logFormat);
  }, [logInput, logFormat]);

  const stats = useMemo(() => computeStats(entries), [entries]);

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
    setLogInput("");
    setSearchTerm("");
    setSeverityFilter([]);
    setHostFilter("");
    setServiceFilter("");
    setExpandedRow(null);
    setActiveTab("dashboard");
  };

  const hasData = entries.length > 0;
  const errorRate = hasData ? ((stats.bySeverity.error + stats.bySeverity.critical + stats.bySeverity.emergency + stats.bySeverity.alert) / stats.total * 100).toFixed(1) : "0";

  // Detect potential security issues
  const securityAlerts = useMemo(() => {
    const alerts: { type: string; message: string; count: number }[] = [];
    const failedLogins = entries.filter(e => e.message.toLowerCase().includes("failed") && (e.message.toLowerCase().includes("login") || e.message.toLowerCase().includes("password")));
    if (failedLogins.length >= 3) alerts.push({ type: "Brute Force", message: `${failedLogins.length} failed login attempts detected`, count: failedLogins.length });
    const ips403 = entries.filter(e => e.message.includes("403") || e.message.includes("Forbidden"));
    if (ips403.length > 0) alerts.push({ type: "Access Denied", message: `${ips403.length} forbidden access attempts`, count: ips403.length });
    const criticals = entries.filter(e => e.severity === "critical" || e.severity === "emergency");
    if (criticals.length > 0) alerts.push({ type: "Critical Events", message: `${criticals.length} critical/emergency events`, count: criticals.length });
    return alerts;
  }, [entries]);

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-6 max-w-[1600px]">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20">
                <Activity className="w-7 h-7 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Log Analyzer</h1>
                <p className="text-sm text-muted-foreground">Multi-format log parsing, analysis & pattern detection</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {hasData && (
                <>
                  <Badge variant="outline" className="font-mono text-xs">
                    {detectedFormat.toUpperCase()} • {entries.length} entries
                  </Badge>
                  <Button variant="outline" size="sm" onClick={() => handleExport("csv")}>
                    <Download className="w-3.5 h-3.5 mr-1" /> CSV
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => handleExport("json")}>
                    <Download className="w-3.5 h-3.5 mr-1" /> JSON
                  </Button>
                </>
              )}
              <Button variant="ghost" size="sm" onClick={clearAll}>
                <Trash2 className="w-3.5 h-3.5 mr-1" /> Clear
              </Button>
            </div>
          </div>

          {/* Input Section */}
          <Card className="border-border/40 shadow-lg mb-6">
            <CardContent className="p-4">
              <div className="flex items-end gap-4 mb-3">
                <div className="flex-1">
                  <Label className="text-xs text-muted-foreground mb-1 block">Log Format</Label>
                  <Select value={logFormat} onValueChange={(v) => setLogFormat(v as LogFormat)}>
                    <SelectTrigger className="h-9">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">Auto-detect</SelectItem>
                      <SelectItem value="syslog">Syslog</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="nginx">Nginx / Apache</SelectItem>
                      <SelectItem value="systemd">Systemd Journal</SelectItem>
                      <SelectItem value="application">Application Log</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex gap-2">
                  <Select onValueChange={(v) => { setLogInput(SAMPLE_LOGS[v] || ""); toast.success("Sample loaded"); }}>
                    <SelectTrigger className="h-9 w-[160px]">
                      <SelectValue placeholder="Load sample..." />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="syslog">Syslog Sample</SelectItem>
                      <SelectItem value="json">JSON Sample</SelectItem>
                      <SelectItem value="application">App Log Sample</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="outline" size="sm" className="h-9" onClick={() => { const input = document.createElement("input"); input.type = "file"; input.accept = ".log,.txt,.json"; input.onchange = (e) => { const file = (e.target as HTMLInputElement).files?.[0]; if (file) { const reader = new FileReader(); reader.onload = (ev) => { setLogInput(ev.target?.result as string); toast.success(`Loaded ${file.name}`); }; reader.readAsText(file); } }; input.click(); }}>
                    <Upload className="w-3.5 h-3.5 mr-1" /> Upload
                  </Button>
                </div>
              </div>
              <Textarea
                placeholder="Paste your logs here... Supports syslog, JSON, nginx, systemd, and application log formats. Auto-detection enabled."
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                className="font-mono text-xs h-40 resize-y bg-muted/30"
              />
              {logInput && (
                <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                  <CheckCircle2 className="w-3 h-3 text-primary" />
                  Detected: <Badge variant="secondary" className="text-xs">{detectedFormat}</Badge>
                  • {entries.length} lines parsed
                  • {stats.bySeverity.error + stats.bySeverity.critical} errors found
                </div>
              )}
            </CardContent>
          </Card>

          {hasData && (
            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
              <TabsList className="grid w-full grid-cols-5 h-10">
                <TabsTrigger value="dashboard" className="text-xs gap-1.5"><BarChart3 className="w-3.5 h-3.5" /> Dashboard</TabsTrigger>
                <TabsTrigger value="logs" className="text-xs gap-1.5"><FileText className="w-3.5 h-3.5" /> Log Viewer</TabsTrigger>
                <TabsTrigger value="patterns" className="text-xs gap-1.5"><TrendingUp className="w-3.5 h-3.5" /> Patterns</TabsTrigger>
                <TabsTrigger value="security" className="text-xs gap-1.5"><Shield className="w-3.5 h-3.5" /> Security</TabsTrigger>
                <TabsTrigger value="insights" className="text-xs gap-1.5"><Zap className="w-3.5 h-3.5" /> Insights</TabsTrigger>
              </TabsList>

              {/* Dashboard Tab */}
              <TabsContent value="dashboard">
                <div className="space-y-4">
                  {/* Summary Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                    <MetricCard label="Total Events" value={stats.total} icon={<FileText className="w-4 h-4" />} />
                    <MetricCard label="Errors" value={stats.bySeverity.error} icon={<XCircle className="w-4 h-4" />} color="text-destructive" />
                    <MetricCard label="Warnings" value={stats.bySeverity.warning} icon={<AlertTriangle className="w-4 h-4" />} color="text-yellow-500" />
                    <MetricCard label="Critical" value={stats.bySeverity.critical + stats.bySeverity.emergency} icon={<AlertCircle className="w-4 h-4" />} color="text-red-500" />
                    <MetricCard label="Error Rate" value={`${errorRate}%`} icon={<Activity className="w-4 h-4" />} color={parseFloat(errorRate) > 10 ? "text-destructive" : "text-primary"} />
                    <MetricCard label="Unique IPs" value={stats.topIPs.length} icon={<Eye className="w-4 h-4" />} />
                  </div>

                  {/* Severity Distribution */}
                  <div className="grid md:grid-cols-2 gap-4">
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
                                  <div
                                    className={`h-full rounded-full transition-all ${getSeverityBarColor(sev)}`}
                                    style={{ width: `${Math.max(pct, 2)}%` }}
                                  />
                                </div>
                                <span className="text-xs font-mono w-16 text-right text-muted-foreground">{count} ({pct.toFixed(1)}%)</span>
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>

                    <Card className="border-border/40">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-destructive" /> Top Errors</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[200px]">
                          {stats.topErrors.length === 0 ? (
                            <p className="text-xs text-muted-foreground text-center py-8">No errors found 🎉</p>
                          ) : (
                            <div className="space-y-2">
                              {stats.topErrors.map((err, i) => (
                                <div key={i} className="p-2 rounded bg-destructive/5 border border-destructive/10">
                                  <p className="text-xs font-mono text-foreground truncate">{err.message}</p>
                                  <p className="text-xs text-destructive font-medium mt-1">{err.count} occurrences</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Services and IPs */}
                  <div className="grid md:grid-cols-3 gap-4">
                    {stats.byService.length > 0 && (
                      <Card className="border-border/40">
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Services</CardTitle>
                        </CardHeader>
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
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Hosts</CardTitle>
                        </CardHeader>
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
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Top IP Addresses</CardTitle>
                        </CardHeader>
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
                                <div
                                  className="w-full bg-primary/60 hover:bg-primary rounded-t transition-all min-h-[2px]"
                                  style={{ height: `${height}%` }}
                                />
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

              {/* Log Viewer Tab */}
              <TabsContent value="logs">
                <Card className="border-border/40">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm flex items-center gap-2"><Filter className="w-4 h-4" /> Filters</CardTitle>
                      <span className="text-xs text-muted-foreground">{filteredEntries.length} / {entries.length} entries</span>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {/* Search */}
                    <div className="flex gap-2">
                      <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                        <Input
                          placeholder="Full-text search..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-9 h-9 text-sm"
                        />
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
                    {/* Severity filter chips */}
                    <div className="flex flex-wrap gap-1.5">
                      {SEVERITY_OPTIONS.map(sev => {
                        const count = stats.bySeverity[sev];
                        if (count === 0) return null;
                        const active = severityFilter.includes(sev);
                        return (
                          <button
                            key={sev}
                            onClick={() => toggleSeverity(sev)}
                            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium transition-all border ${
                              active
                                ? `${getSeverityBadgeColor(sev)} border-transparent`
                                : "bg-muted/30 text-muted-foreground border-border/40 hover:bg-muted/60"
                            }`}
                          >
                            {SEVERITY_ICONS[sev]}
                            <span className="capitalize">{sev}</span>
                            <span className="opacity-70">({count})</span>
                          </button>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                {/* Log Table */}
                <Card className="border-border/40 mt-4">
                  <ScrollArea className="h-[500px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
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
                            <TableRow
                              key={entry.id}
                              className={`cursor-pointer hover:bg-muted/50 ${expandedRow === entry.id ? "bg-muted/30" : ""}`}
                              onClick={() => setExpandedRow(expandedRow === entry.id ? null : entry.id)}
                            >
                              <TableCell className="font-mono text-xs text-muted-foreground">{entry.id}</TableCell>
                              <TableCell className="font-mono text-xs">{entry.timestamp || "—"}</TableCell>
                              <TableCell>
                                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${getSeverityColor(entry.severity)}`}>
                                  {SEVERITY_ICONS[entry.severity]}
                                  {entry.severity}
                                </span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{entry.service || "—"}</TableCell>
                              <TableCell className="font-mono text-xs">{entry.ip || "—"}</TableCell>
                              <TableCell className="text-xs truncate max-w-[400px]">{entry.message}</TableCell>
                              <TableCell>
                                {expandedRow === entry.id ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                              </TableCell>
                            </TableRow>
                            {expandedRow === entry.id && (
                              <TableRow key={`${entry.id}-detail`}>
                                <TableCell colSpan={7} className="bg-muted/20 p-4">
                                  <div className="space-y-2">
                                    <div className="flex items-center justify-between">
                                      <Label className="text-xs font-semibold">Raw Log Entry</Label>
                                      <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(entry.raw); toast.success("Copied"); }}>
                                        <Copy className="w-3 h-3 mr-1" /> Copy
                                      </Button>
                                    </div>
                                    <pre className="text-xs font-mono bg-background p-3 rounded border border-border overflow-x-auto whitespace-pre-wrap">{entry.raw}</pre>
                                    {Object.keys(entry.fields).length > 0 && (
                                      <div>
                                        <Label className="text-xs font-semibold mb-1 block">Extracted Fields</Label>
                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                          {Object.entries(entry.fields).map(([k, v]) => (
                                            <div key={k} className="bg-background p-2 rounded border border-border">
                                              <span className="text-[10px] text-muted-foreground">{k}</span>
                                              <p className="text-xs font-mono truncate">{v}</p>
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

              {/* Patterns Tab */}
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
                      <CardTitle className="text-sm flex items-center gap-2"><Activity className="w-4 h-4" /> Anomaly Indicators</CardTitle>
                      <CardDescription className="text-xs">Potential issues detected from log patterns</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {parseFloat(errorRate) > 20 && (
                          <AnomalyCard type="High Error Rate" description={`Error rate is ${errorRate}% — significantly above normal (< 5%)`} level="critical" />
                        )}
                        {parseFloat(errorRate) > 5 && parseFloat(errorRate) <= 20 && (
                          <AnomalyCard type="Elevated Error Rate" description={`Error rate is ${errorRate}% — above typical threshold (< 5%)`} level="warning" />
                        )}
                        {stats.topIPs.some(ip => ip.count > entries.length * 0.3) && (
                          <AnomalyCard type="IP Concentration" description="Single IP responsible for >30% of traffic" level="warning" />
                        )}
                        {stats.bySeverity.critical > 0 && (
                          <AnomalyCard type="Critical Events Present" description={`${stats.bySeverity.critical} critical events detected — immediate attention needed`} level="critical" />
                        )}
                        {stats.patterns.some(p => p.count >= 5 && (p.severity === "error" || p.severity === "critical")) && (
                          <AnomalyCard type="Repeated Errors" description="Same error pattern occurring 5+ times — likely systematic issue" level="warning" />
                        )}
                        {parseFloat(errorRate) <= 5 && stats.bySeverity.critical === 0 && (
                          <div className="text-center py-8 text-muted-foreground">
                            <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-primary/40" />
                            <p className="text-xs">No anomalies detected — logs look healthy</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* Security Tab */}
              <TabsContent value="security">
                <div className="grid md:grid-cols-2 gap-4">
                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm flex items-center gap-2"><Shield className="w-4 h-4" /> Security Alerts</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {securityAlerts.length === 0 ? (
                        <div className="text-center py-12 text-muted-foreground">
                          <Shield className="w-10 h-10 mx-auto mb-2 opacity-20" />
                          <p className="text-xs">No security issues detected</p>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {securityAlerts.map((alert, i) => (
                            <div key={i} className="p-3 rounded-lg bg-destructive/5 border border-destructive/20">
                              <div className="flex items-center gap-2 mb-1">
                                <AlertTriangle className="w-4 h-4 text-destructive" />
                                <span className="text-sm font-semibold text-foreground">{alert.type}</span>
                              </div>
                              <p className="text-xs text-muted-foreground">{alert.message}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm flex items-center gap-2"><Eye className="w-4 h-4" /> Suspicious IPs</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {(() => {
                        const suspiciousEntries = entries.filter(e =>
                          e.message.toLowerCase().includes("failed") ||
                          e.message.toLowerCase().includes("denied") ||
                          e.message.toLowerCase().includes("forbidden") ||
                          e.message.toLowerCase().includes("unauthorized") ||
                          e.message.includes("403") || e.message.includes("401")
                        );
                        const suspiciousIPs = new Map<string, number>();
                        suspiciousEntries.forEach(e => {
                          if (e.ip) suspiciousIPs.set(e.ip, (suspiciousIPs.get(e.ip) || 0) + 1);
                        });
                        const sorted = Array.from(suspiciousIPs.entries()).sort((a, b) => b[1] - a[1]);
                        if (sorted.length === 0) return (
                          <div className="text-center py-12 text-muted-foreground">
                            <CheckCircle2 className="w-10 h-10 mx-auto mb-2 opacity-20" />
                            <p className="text-xs">No suspicious IPs found</p>
                          </div>
                        );
                        return (
                          <div className="space-y-2">
                            {sorted.map(([ip, count], i) => (
                              <div key={i} className="flex justify-between items-center p-2 rounded bg-muted/30">
                                <span className="font-mono text-xs">{ip}</span>
                                <Badge variant="destructive" className="text-xs">{count} events</Badge>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* Insights Tab */}
              <TabsContent value="insights">
                <div className="grid md:grid-cols-2 gap-4">
                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm">Summary Report</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-xs">
                      <div className="p-3 rounded bg-muted/30 space-y-1">
                        <p><span className="font-semibold">Time Range:</span> {stats.timeRange.start || "N/A"} → {stats.timeRange.end || "N/A"}</p>
                        <p><span className="font-semibold">Total Events:</span> {stats.total}</p>
                        <p><span className="font-semibold">Format:</span> {detectedFormat}</p>
                        <p><span className="font-semibold">Error Rate:</span> {errorRate}%</p>
                        <p><span className="font-semibold">Unique Services:</span> {uniqueServices.length}</p>
                        <p><span className="font-semibold">Unique Hosts:</span> {uniqueHosts.length}</p>
                        <p><span className="font-semibold">Unique IPs:</span> {stats.topIPs.length}</p>
                      </div>

                      <div>
                        <Label className="text-xs font-semibold mb-2 block">Health Score</Label>
                        <div className="flex items-center gap-3">
                          <div className="flex-1 h-3 bg-muted/30 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${getHealthColor(parseFloat(errorRate))}`}
                              style={{ width: `${Math.max(100 - parseFloat(errorRate) * 5, 10)}%` }}
                            />
                          </div>
                          <span className="font-bold text-sm">{Math.max(100 - Math.round(parseFloat(errorRate) * 5), 0)}/100</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border-border/40">
                    <CardHeader>
                      <CardTitle className="text-sm">Recommendations</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {parseFloat(errorRate) > 5 && (
                          <RecommendationItem text="High error rate detected. Review top errors and address root causes." priority="high" />
                        )}
                        {stats.bySeverity.critical > 0 && (
                          <RecommendationItem text="Critical events present. These require immediate investigation." priority="high" />
                        )}
                        {securityAlerts.length > 0 && (
                          <RecommendationItem text="Security alerts detected. Review suspicious activity and consider blocking malicious IPs." priority="high" />
                        )}
                        {stats.patterns.filter(p => p.count >= 5).length > 0 && (
                          <RecommendationItem text="Repeated log patterns found. Consider fixing recurring issues to reduce noise." priority="medium" />
                        )}
                        {stats.bySeverity.warning > stats.total * 0.2 && (
                          <RecommendationItem text="High warning count. Review warnings to prevent escalation to errors." priority="medium" />
                        )}
                        <RecommendationItem text="Set up automated alerting for critical and error severity events." priority="low" />
                        <RecommendationItem text="Implement log rotation and retention policies to manage storage." priority="low" />
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          )}

          {!hasData && (
            <div className="text-center py-20 text-muted-foreground">
              <Activity className="w-16 h-16 mx-auto mb-4 opacity-10" />
              <p className="text-lg font-medium mb-1">Paste logs above to get started</p>
              <p className="text-sm">Supports syslog, JSON, nginx, systemd, and application log formats</p>
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
    <Card className="border-border/40">
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
    <div className="flex items-start gap-2 p-2 rounded bg-muted/20">
      <div className={`w-1.5 h-1.5 rounded-full mt-1.5 ${colors[priority]}`} />
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

function getHealthColor(errorRate: number): string {
  if (errorRate > 20) return "bg-red-500";
  if (errorRate > 10) return "bg-yellow-500";
  return "bg-green-500";
}

export default LogAnalyzer;
