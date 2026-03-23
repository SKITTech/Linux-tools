import { useState, useRef } from "react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Wifi, Activity, Search, Globe, CheckCircle2, XCircle, Clock, Loader2,
  Server, Shield, Zap, Copy, Check,
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
import { supabase } from "@/integrations/supabase/client";

/* ─── Types ─── */
interface PingResult { seq: number; time: number; status: string }
interface PingSummary { sent: number; received: number; lost: number; lossPercent: number; stats: { min: number; max: number; avg: number } | null }
interface DnsRecord { name: string; type: string; ttl: number; data: string }

/* ─── Helpers ─── */
const StatusBadge = ({ status }: { status: "open" | "closed" | "timeout" | "error" | "ok" }) => {
  const map = {
    open: { color: "bg-[hsl(var(--success))]", label: "OPEN", icon: CheckCircle2 },
    ok: { color: "bg-[hsl(var(--success))]", label: "OK", icon: CheckCircle2 },
    closed: { color: "bg-destructive", label: "CLOSED", icon: XCircle },
    timeout: { color: "bg-[hsl(45,90%,50%)]", label: "TIMEOUT", icon: Clock },
    error: { color: "bg-destructive", label: "ERROR", icon: XCircle },
  };
  const { color, label, icon: Icon } = map[status] || map.error;
  return (
    <Badge className={`${color} text-white gap-1 font-mono text-xs`}>
      <Icon className="w-3 h-3" /> {label}
    </Badge>
  );
};

const TerminalOutput = ({ children, title }: { children: React.ReactNode; title: string }) => {
  const [copied, setCopied] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const handleCopy = async () => {
    const text = ref.current?.innerText || "";
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Copied!");
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="rounded-xl overflow-hidden border border-terminal-border">
      <div className="flex items-center justify-between px-4 py-2.5 bg-[hsl(var(--terminal-bg))] border-b border-terminal-border">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-destructive/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[hsl(45,90%,50%)]/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[hsl(var(--success))]/70" />
          </div>
          <span className="text-xs font-mono text-terminal-text/70">{title}</span>
        </div>
        <Button size="sm" variant="ghost" onClick={handleCopy} className="h-6 px-2 text-terminal-text/60 hover:text-terminal-text hover:bg-terminal-border/40">
          {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        </Button>
      </div>
      <div ref={ref} className="p-4 bg-[hsl(var(--terminal-bg))] font-mono text-sm text-terminal-text max-h-[400px] overflow-y-auto">
        {children}
      </div>
    </div>
  );
};

const Field = ({ label, required, hint, children }: { label: string; required?: boolean; hint?: string; children: React.ReactNode }) => (
  <div className="space-y-1.5">
    <Label className="text-foreground text-sm">
      {label} {required && <span className="text-destructive">*</span>}
    </Label>
    {children}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
);

/* ─── Quick port presets ─── */
const PORT_PRESETS = [
  { port: 22, label: "SSH" },
  { port: 80, label: "HTTP" },
  { port: 443, label: "HTTPS" },
  { port: 3306, label: "MySQL" },
  { port: 5432, label: "PostgreSQL" },
  { port: 8080, label: "Alt HTTP" },
];

const DNS_TYPES = [
  { value: "A", label: "A (IPv4 Address)" },
  { value: "AAAA", label: "AAAA (IPv6 Address)" },
  { value: "MX", label: "MX (Mail Exchange)" },
  { value: "TXT", label: "TXT (Text Records)" },
  { value: "NS", label: "NS (Name Servers)" },
  { value: "CNAME", label: "CNAME (Canonical Name)" },
  { value: "SOA", label: "SOA (Start of Authority)" },
  { value: "CAA", label: "CAA (Certificate Authority)" },
];

/* ─── Main Component ─── */
const NetworkDiagnostics = () => {
  // Ping state
  const [pingHost, setPingHost] = useState("");
  const [pingLoading, setPingLoading] = useState(false);
  const [pingResults, setPingResults] = useState<PingResult[] | null>(null);
  const [pingSummary, setPingSummary] = useState<PingSummary | null>(null);

  // Port state
  const [portHost, setPortHost] = useState("");
  const [portNumber, setPortNumber] = useState("");
  const [portLoading, setPortLoading] = useState(false);
  const [portResult, setPortResult] = useState<any>(null);

  // DNS state
  const [dnsQuery, setDnsQuery] = useState("");
  const [dnsType, setDnsType] = useState("A");
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsResult, setDnsResult] = useState<{ domain: string; queryType: string; status: string; records: DnsRecord[]; authority: DnsRecord[]; queryTime: number; server: string } | null>(null);

  /* ─── Ping Handler ─── */
  const handlePing = async () => {
    if (!pingHost.trim()) { toast.error("Please enter a hostname"); return; }
    setPingLoading(true);
    setPingResults(null);
    setPingSummary(null);

    try {
      const { data, error } = await supabase.functions.invoke('ping-check', {
        body: { host: pingHost.trim(), count: 6 },
      });
      if (error) throw error;
      setPingResults(data.results);
      setPingSummary(data.summary);
      toast.success("Ping completed");
    } catch (err: any) {
      toast.error(err.message || "Ping failed");
    } finally {
      setPingLoading(false);
    }
  };

  /* ─── Port Handler ─── */
  const handlePort = async () => {
    if (!portHost.trim() || !portNumber.trim()) { toast.error("Enter hostname and port"); return; }
    const port = parseInt(portNumber);
    if (isNaN(port) || port < 1 || port > 65535) { toast.error("Port must be 1-65535"); return; }

    setPortLoading(true);
    setPortResult(null);

    try {
      const { data, error } = await supabase.functions.invoke('check-port', {
        body: { host: portHost.trim(), port, timeout: 5000 },
      });
      if (error) throw error;
      setPortResult(data);
      if (data.status === 'open') toast.success(`Port ${port} is open`);
      else toast.error(`Port ${port} is ${data.status}`);
    } catch (err: any) {
      toast.error(err.message || "Port check failed");
    } finally {
      setPortLoading(false);
    }
  };

  /* ─── DNS Handler ─── */
  const handleDns = async () => {
    if (!dnsQuery.trim()) { toast.error("Please enter a domain"); return; }
    setDnsLoading(true);
    setDnsResult(null);

    try {
      const { data, error } = await supabase.functions.invoke('dns-lookup', {
        body: { domain: dnsQuery.trim(), type: dnsType },
      });
      if (error) throw error;
      setDnsResult(data);
      toast.success(`Found ${data.records.length} records`);
    } catch (err: any) {
      toast.error(err.message || "DNS lookup failed");
    } finally {
      setDnsLoading(false);
    }
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Hero Header */}
        <header className="relative border-b border-border overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
          <div className="relative container mx-auto px-4 py-8 sm:px-6 lg:px-8">
            <div className="flex items-start gap-4">
              <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 shrink-0">
                <Wifi className="w-7 h-7 text-primary" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <h1 className="text-2xl font-bold text-foreground tracking-tight">Network Diagnostics</h1>
                  <Badge variant="secondary" className="text-xs font-mono">LIVE</Badge>
                </div>
                <p className="text-sm text-muted-foreground max-w-2xl">
                  Real-time connectivity tests, port scanning, and DNS lookups — powered by backend functions.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
              {[
                { icon: Activity, label: "HTTP Ping", desc: "Live check" },
                { icon: Shield, label: "Port Scan", desc: "TCP connect" },
                { icon: Globe, label: "DNS Lookup", desc: "10+ record types" },
                { icon: Zap, label: "Real-time", desc: "No simulation" },
              ].map(({ icon: Icon, label, desc }) => (
                <div key={label} className="flex items-center gap-3 px-4 py-3 rounded-xl bg-card/60 backdrop-blur-sm border border-border/60">
                  <Icon className="w-4 h-4 text-accent shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-foreground truncate">{label}</p>
                    <p className="text-xs text-muted-foreground">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </header>

        {/* Main */}
        <main className="container mx-auto px-4 py-8 sm:px-6 lg:px-8">
          <Card className="border-border overflow-hidden">
            <CardHeader className="bg-card pb-0">
              <Tabs defaultValue="ping" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="ping" className="gap-1.5 text-xs sm:text-sm">
                    <Activity className="w-3.5 h-3.5 hidden sm:block" /> Ping Test
                  </TabsTrigger>
                  <TabsTrigger value="port" className="gap-1.5 text-xs sm:text-sm">
                    <Server className="w-3.5 h-3.5 hidden sm:block" /> Port Checker
                  </TabsTrigger>
                  <TabsTrigger value="dns" className="gap-1.5 text-xs sm:text-sm">
                    <Search className="w-3.5 h-3.5 hidden sm:block" /> DNS Lookup
                  </TabsTrigger>
                </TabsList>

                <CardContent className="px-0 sm:px-6 pt-6">
                  {/* ── Ping Tab ── */}
                  <TabsContent value="ping" className="space-y-5 mt-0 px-4 sm:px-0">
                    <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
                      <Field label="Hostname or URL" required hint="e.g. google.com, github.com">
                        <Input
                          placeholder="google.com"
                          value={pingHost}
                          onChange={(e) => setPingHost(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && handlePing()}
                          className="bg-background border-input"
                        />
                      </Field>
                      <Button onClick={handlePing} disabled={pingLoading} className="gap-2 h-10">
                        {pingLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
                        {pingLoading ? "Pinging..." : "Run Ping"}
                      </Button>
                    </div>

                    {pingResults && (
                      <TerminalOutput title={`ping ${pingHost}`}>
                        <p className="text-muted-foreground mb-2">HTTP connectivity check to {pingHost}</p>
                        {pingResults.map((r) => (
                          <div key={r.seq} className="flex items-center gap-3 py-1">
                            <span className="text-muted-foreground w-16">seq={r.seq}</span>
                            <StatusBadge status={r.status === 'ok' ? 'ok' : r.status === 'timeout' ? 'timeout' : 'error'} />
                            <span className="text-terminal-text">time={r.time}ms</span>
                          </div>
                        ))}
                        {pingSummary && (
                          <div className="mt-4 pt-3 border-t border-terminal-border text-xs">
                            <p>{pingSummary.sent} packets sent, {pingSummary.received} received, {pingSummary.lossPercent}% loss</p>
                            {pingSummary.stats && (
                              <p className="text-accent">rtt min/avg/max = {pingSummary.stats.min}/{pingSummary.stats.avg}/{pingSummary.stats.max} ms</p>
                            )}
                          </div>
                        )}
                      </TerminalOutput>
                    )}
                  </TabsContent>

                  {/* ── Port Tab ── */}
                  <TabsContent value="port" className="space-y-5 mt-0 px-4 sm:px-0">
                    <div className="grid sm:grid-cols-[1fr_auto_auto] gap-3 items-end">
                      <Field label="Hostname or IP" required>
                        <Input
                          placeholder="example.com"
                          value={portHost}
                          onChange={(e) => setPortHost(e.target.value)}
                          className="bg-background border-input"
                        />
                      </Field>
                      <Field label="Port" required>
                        <Input
                          type="number"
                          placeholder="443"
                          value={portNumber}
                          onChange={(e) => setPortNumber(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && handlePort()}
                          className="bg-background border-input w-24"
                          min={1}
                          max={65535}
                        />
                      </Field>
                      <Button onClick={handlePort} disabled={portLoading} className="gap-2 h-10">
                        {portLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                        {portLoading ? "Checking..." : "Check"}
                      </Button>
                    </div>

                    {/* Quick port presets */}
                    <div className="flex flex-wrap gap-2">
                      <span className="text-xs text-muted-foreground self-center mr-1">Quick:</span>
                      {PORT_PRESETS.map(({ port, label }) => (
                        <Button
                          key={port}
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs font-mono gap-1"
                          onClick={() => setPortNumber(String(port))}
                        >
                          :{port} <span className="text-muted-foreground">{label}</span>
                        </Button>
                      ))}
                    </div>

                    {portResult && (
                      <TerminalOutput title={`port-check ${portResult.host}:${portResult.port}`}>
                        <div className="space-y-2">
                          <div className="flex items-center gap-3">
                            <span className="text-muted-foreground w-20">Status:</span>
                            <StatusBadge status={portResult.status} />
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-muted-foreground w-20">Host:</span>
                            <span>{portResult.host}:{portResult.port}</span>
                          </div>
                          {portResult.service && (
                            <div className="flex items-center gap-3">
                              <span className="text-muted-foreground w-20">Service:</span>
                              <span>{portResult.service}</span>
                            </div>
                          )}
                          {portResult.responseTime !== undefined && (
                            <div className="flex items-center gap-3">
                              <span className="text-muted-foreground w-20">Latency:</span>
                              <span>{portResult.responseTime}ms</span>
                            </div>
                          )}
                          {portResult.ipVersion && (
                            <div className="flex items-center gap-3">
                              <span className="text-muted-foreground w-20">IP Version:</span>
                              <span>{portResult.ipVersion}</span>
                            </div>
                          )}
                          {portResult.error && (
                            <div className="flex items-center gap-3">
                              <span className="text-muted-foreground w-20">Detail:</span>
                              <span className="text-destructive">{portResult.error}</span>
                            </div>
                          )}
                        </div>
                      </TerminalOutput>
                    )}
                  </TabsContent>

                  {/* ── DNS Tab ── */}
                  <TabsContent value="dns" className="space-y-5 mt-0 px-4 sm:px-0">
                    <div className="grid sm:grid-cols-[1fr_auto_auto] gap-3 items-end">
                      <Field label="Domain Name" required>
                        <Input
                          placeholder="example.com"
                          value={dnsQuery}
                          onChange={(e) => setDnsQuery(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && handleDns()}
                          className="bg-background border-input"
                        />
                      </Field>
                      <Field label="Record Type">
                        <Select value={dnsType} onValueChange={setDnsType}>
                          <SelectTrigger className="bg-background border-input w-48">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-popover border-border z-50">
                            {DNS_TYPES.map(t => (
                              <SelectItem key={t.value} value={t.value} className="hover:bg-accent">{t.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </Field>
                      <Button onClick={handleDns} disabled={dnsLoading} className="gap-2 h-10">
                        {dnsLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                        {dnsLoading ? "Looking up..." : "Lookup"}
                      </Button>
                    </div>

                    {dnsResult && (
                      <TerminalOutput title={`dig ${dnsResult.domain} ${dnsResult.queryType}`}>
                        <p className="text-muted-foreground mb-3">
                          ;; Got answer: status={dnsResult.status}, server={dnsResult.server}, time={dnsResult.queryTime}ms
                        </p>

                        {dnsResult.records.length > 0 ? (
                          <>
                            <p className="text-accent mb-1">;; ANSWER SECTION ({dnsResult.records.length} records):</p>
                            <div className="space-y-1">
                              {dnsResult.records.map((r, i) => (
                                <div key={i} className="flex gap-3 text-terminal-text">
                                  <span className="text-muted-foreground min-w-[180px] truncate">{r.name}</span>
                                  <span className="text-muted-foreground w-12 text-right">{r.ttl}</span>
                                  <span className="w-12 text-accent">{r.type}</span>
                                  <span className="flex-1 break-all">{r.data}</span>
                                </div>
                              ))}
                            </div>
                          </>
                        ) : (
                          <p className="text-destructive">;; No records found for {dnsResult.queryType}</p>
                        )}

                        {dnsResult.authority.length > 0 && (
                          <>
                            <p className="text-accent mt-4 mb-1">;; AUTHORITY SECTION:</p>
                            <div className="space-y-1">
                              {dnsResult.authority.map((r, i) => (
                                <div key={i} className="flex gap-3 text-terminal-text/70">
                                  <span className="text-muted-foreground min-w-[180px] truncate">{r.name}</span>
                                  <span className="text-muted-foreground w-12 text-right">{r.ttl}</span>
                                  <span className="w-12">{r.type}</span>
                                  <span className="flex-1 break-all">{r.data}</span>
                                </div>
                              ))}
                            </div>
                          </>
                        )}

                        <p className="text-muted-foreground mt-4 text-xs">
                          ;; Query time: {dnsResult.queryTime} msec | SERVER: {dnsResult.server}
                        </p>
                      </TerminalOutput>
                    )}
                  </TabsContent>
                </CardContent>
              </Tabs>
            </CardHeader>
          </Card>
        </main>
      </div>
    </Sidebar>
  );
};

export default NetworkDiagnostics;
