import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Wifi, Activity, Search, Globe, CheckCircle2, XCircle, Clock, Loader2,
  Server, Shield, Zap, Copy, Check, ArrowLeft, MapPin, FileText, ArrowRightLeft,
  Lock, Eye, Network, ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";

/* ─── Tool Definitions ─── */
interface ToolDef {
  id: string;
  name: string;
  desc: string;
  icon: any;
  category: string;
}

const TOOLS: ToolDef[] = [
  { id: "dns-lookup", name: "DNS Lookup", desc: "See all DNS records of a domain", icon: Search, category: "DNS Tools" },
  { id: "mx-lookup", name: "MX Lookup", desc: "Mail exchange records of a domain", icon: FileText, category: "DNS Tools" },
  { id: "ns-lookup", name: "NS Lookup", desc: "Name server records of a domain", icon: Server, category: "DNS Tools" },
  { id: "cname-lookup", name: "CNAME Lookup", desc: "Canonical name records of a domain", icon: ArrowRightLeft, category: "DNS Tools" },
  { id: "txt-lookup", name: "TXT Lookup", desc: "Text records of a domain (SPF, DKIM)", icon: FileText, category: "DNS Tools" },
  { id: "soa-lookup", name: "SOA Lookup", desc: "Start of Authority record", icon: Globe, category: "DNS Tools" },
  { id: "reverse-dns", name: "Reverse DNS", desc: "Resolve IP to hostname", icon: ArrowRightLeft, category: "DNS Tools" },
  { id: "whats-my-ip", name: "What is My IP", desc: "Lookup your own IP address", icon: Eye, category: "IP Tools" },
  { id: "ip-geolocation", name: "IP Geolocation", desc: "Find physical location of any IP", icon: MapPin, category: "IP Tools" },
  { id: "ping", name: "Ping Test", desc: "Send HTTP requests & measure latency", icon: Activity, category: "IP Tools" },
  { id: "website-to-ip", name: "Website to IP", desc: "Find IP address of a domain", icon: MapPin, category: "IP Tools" },
  { id: "whois", name: "WHOIS Lookup", desc: "Check domain registration details", icon: Search, category: "IP Tools" },
  { id: "port-check", name: "Port Checker", desc: "Check if a port is open on a host", icon: Shield, category: "Network Tools" },
  { id: "http-headers", name: "HTTP Headers", desc: "View HTTP response headers of a URL", icon: FileText, category: "Network Tools" },
  { id: "ssl-check", name: "SSL Checker", desc: "Check if a domain has valid SSL", icon: Lock, category: "Network Tools" },
];

const CATEGORIES = ["DNS Tools", "IP Tools", "Network Tools"];

const DNS_TYPES = [
  { value: "A", label: "A (IPv4)" }, { value: "AAAA", label: "AAAA (IPv6)" },
  { value: "MX", label: "MX (Mail)" }, { value: "TXT", label: "TXT (Text)" },
  { value: "NS", label: "NS (Nameserver)" }, { value: "CNAME", label: "CNAME" },
  { value: "SOA", label: "SOA" }, { value: "CAA", label: "CAA" },
  { value: "SRV", label: "SRV" }, { value: "PTR", label: "PTR" },
];

const PORT_PRESETS = [
  { port: 22, label: "SSH" }, { port: 80, label: "HTTP" }, { port: 443, label: "HTTPS" },
  { port: 3306, label: "MySQL" }, { port: 5432, label: "PostgreSQL" }, { port: 8080, label: "Alt HTTP" },
  { port: 27017, label: "MongoDB" }, { port: 6379, label: "Redis" },
];

const Field = ({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) => (
  <div className="space-y-1.5">
    <Label className="text-foreground text-sm font-medium">{label}</Label>
    {children}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
);

const StatusBadge = ({ status }: { status: string }) => {
  const map: Record<string, { cls: string; label: string; icon: any }> = {
    open: { cls: "bg-[hsl(var(--success))] text-[hsl(var(--success-foreground))]", label: "OPEN", icon: CheckCircle2 },
    ok: { cls: "bg-[hsl(var(--success))] text-[hsl(var(--success-foreground))]", label: "OK", icon: CheckCircle2 },
    closed: { cls: "bg-destructive text-destructive-foreground", label: "CLOSED", icon: XCircle },
    timeout: { cls: "bg-[hsl(45,90%,50%)] text-foreground", label: "TIMEOUT", icon: Clock },
    error: { cls: "bg-destructive text-destructive-foreground", label: "ERROR", icon: XCircle },
  };
  const s = map[status] || map.error;
  const Icon = s.icon;
  return <Badge className={`${s.cls} gap-1`}><Icon className="w-3 h-3" />{s.label}</Badge>;
};

const catMeta: Record<string, { icon: any; color: string; desc: string }> = {
  "DNS Tools": { icon: Globe, color: "text-blue-500", desc: "Domain name resolution & records" },
  "IP Tools": { icon: Network, color: "text-emerald-500", desc: "IP analysis & geolocation" },
  "Network Tools": { icon: Shield, color: "text-amber-500", desc: "Port scanning & security checks" },
};

const CopyBtn = ({ text }: { text: string }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); toast.success("Copied"); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 rounded hover:bg-muted transition-colors">
      {copied ? <Check className="w-3 h-3 text-primary" /> : <Copy className="w-3 h-3 text-muted-foreground" />}
    </button>
  );
};

const NetworkDiagnosticsContent = () => {
  const [activeTool, setActiveTool] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [domain, setDomain] = useState("");
  const [dnsType, setDnsType] = useState("A");
  const [ipInput, setIpInput] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [pingHost, setPingHost] = useState("");
  const [portHost, setPortHost] = useState("");
  const [portNumber, setPortNumber] = useState("");

  const openTool = (id: string) => { setActiveTool(id); setResult(null); };

  /* ─── API helpers ─── */
  const callEdge = async (fn: string, body: any) => {
    setLoading(true); setResult(null);
    try {
      const { data, error } = await supabase.functions.invoke(fn, { body });
      if (error) throw error;
      setResult(data);
    } catch (err: any) {
      setResult({ error: err.message || "Request failed" });
      toast.error("Request failed");
    } finally { setLoading(false); }
  };

  const runDnsLookup = (type?: string) => callEdge("dns-lookup", { domain, type: type || dnsType });
  const runPing = () => callEdge("ping-check", { host: pingHost });
  const runPortCheck = () => callEdge("check-port", { host: portHost, port: parseInt(portNumber) });
  const runNetworkTool = (tool: string) => {
    const input = tool === "ip-geolocation" ? ipInput : (tool === "whats-my-ip" ? "" : (tool === "website-to-ip" ? domain : urlInput));
    callEdge("network-tools", { tool, input });
  };

  const handleRun = () => {
    if (!activeTool) return;
    if (["dns-lookup", "mx-lookup", "ns-lookup", "cname-lookup", "txt-lookup", "soa-lookup"].includes(activeTool)) {
      const typeMap: Record<string, string> = { "mx-lookup": "MX", "ns-lookup": "NS", "cname-lookup": "CNAME", "txt-lookup": "TXT", "soa-lookup": "SOA" };
      runDnsLookup(typeMap[activeTool]);
    } else if (activeTool === "reverse-dns") { runDnsLookup("PTR"); }
    else if (activeTool === "ping") { runPing(); }
    else if (activeTool === "port-check") { runPortCheck(); }
    else { runNetworkTool(activeTool); }
  };

  /* ─── Render tool form ─── */
  const renderToolForm = () => {
    if (!activeTool) return null;

    if (["dns-lookup", "mx-lookup", "ns-lookup", "cname-lookup", "txt-lookup", "soa-lookup"].includes(activeTool)) {
      return (
        <div className="space-y-4">
          <Field label="Domain" hint="e.g. google.com">
            <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" onKeyDown={e => e.key === "Enter" && handleRun()} />
          </Field>
          {activeTool === "dns-lookup" && (
            <Field label="Record Type">
              <Select value={dnsType} onValueChange={setDnsType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{DNS_TYPES.map(t => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
          )}
          <Button onClick={handleRun} disabled={loading || !domain} className="w-full gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Lookup
          </Button>
        </div>
      );
    }

    if (activeTool === "reverse-dns") {
      return (
        <div className="space-y-4">
          <Field label="IP Address" hint="e.g. 8.8.8.8">
            <Input value={ipInput} onChange={e => setIpInput(e.target.value)} placeholder="8.8.8.8" onKeyDown={e => e.key === "Enter" && handleRun()} />
          </Field>
          <Button onClick={() => { setDomain(ipInput); handleRun(); }} disabled={loading || !ipInput} className="w-full gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRightLeft className="w-4 h-4" />} Reverse Lookup
          </Button>
        </div>
      );
    }

    if (activeTool === "ping") {
      return (
        <div className="space-y-4">
          <Field label="Host / Domain" hint="e.g. google.com or 8.8.8.8">
            <Input value={pingHost} onChange={e => setPingHost(e.target.value)} placeholder="google.com" onKeyDown={e => e.key === "Enter" && handleRun()} />
          </Field>
          <Button onClick={handleRun} disabled={loading || !pingHost} className="w-full gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />} Ping
          </Button>
        </div>
      );
    }

    if (activeTool === "port-check") {
      return (
        <div className="space-y-4">
          <Field label="Host" hint="e.g. google.com">
            <Input value={portHost} onChange={e => setPortHost(e.target.value)} placeholder="example.com" />
          </Field>
          <Field label="Port">
            <Input type="number" value={portNumber} onChange={e => setPortNumber(e.target.value)} placeholder="443" onKeyDown={e => e.key === "Enter" && handleRun()} />
          </Field>
          <div className="flex flex-wrap gap-1.5">
            {PORT_PRESETS.map(p => (
              <button key={p.port} onClick={() => setPortNumber(String(p.port))}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${portNumber === String(p.port) ? "bg-primary text-primary-foreground border-primary" : "bg-muted/50 text-muted-foreground border-border hover:bg-muted"}`}>
                {p.label} ({p.port})
              </button>
            ))}
          </div>
          <Button onClick={handleRun} disabled={loading || !portHost || !portNumber} className="w-full gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />} Check Port
          </Button>
        </div>
      );
    }

    if (activeTool === "ip-geolocation") {
      return (
        <div className="space-y-4">
          <Field label="IP Address" hint="Leave empty for your own IP">
            <Input value={ipInput} onChange={e => setIpInput(e.target.value)} placeholder="8.8.8.8" onKeyDown={e => e.key === "Enter" && handleRun()} />
          </Field>
          <Button onClick={handleRun} disabled={loading} className="w-full gap-2">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <MapPin className="w-4 h-4" />} Locate IP
          </Button>
        </div>
      );
    }

    if (activeTool === "whats-my-ip") {
      return (
        <Button onClick={handleRun} disabled={loading} className="w-full gap-2">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />} Find My IP
        </Button>
      );
    }

    // Generic URL-based tools
    const placeholder = activeTool === "website-to-ip" ? "example.com" : "https://example.com";
    const isUrlTool = ["http-headers", "ssl-check"].includes(activeTool);
    return (
      <div className="space-y-4">
        <Field label={isUrlTool ? "URL" : "Domain"} hint={`e.g. ${placeholder}`}>
          <Input value={isUrlTool ? urlInput : domain} onChange={e => isUrlTool ? setUrlInput(e.target.value) : setDomain(e.target.value)} placeholder={placeholder} onKeyDown={e => e.key === "Enter" && handleRun()} />
        </Field>
        <Button onClick={handleRun} disabled={loading || !(isUrlTool ? urlInput : domain)} className="w-full gap-2">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Run
        </Button>
      </div>
    );
  };

  /* ─── Render result ─── */
  const renderResult = () => {
    if (loading) return <div className="flex items-center justify-center py-12 gap-3"><Loader2 className="w-5 h-5 animate-spin text-primary" /><span className="text-sm text-muted-foreground">Running live query...</span></div>;
    if (!result) return null;
    if (result.error) return <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/20 text-destructive text-sm">{result.error}</div>;

    return (
      <div className="space-y-2">
        {result.status && <StatusBadge status={result.status} />}
        {/* Terminal-style output */}
        <div className="rounded-xl bg-muted/30 border border-border overflow-hidden">
          <div className="flex items-center gap-1.5 px-4 py-2 bg-muted/50 border-b border-border">
            <div className="w-3 h-3 rounded-full bg-destructive/60" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <div className="w-3 h-3 rounded-full bg-green-500/60" />
            <span className="ml-2 text-xs text-muted-foreground font-mono">results</span>
          </div>
          <div className="p-4 font-mono text-xs space-y-1 max-h-[400px] overflow-auto">
            {renderResultData(result)}
          </div>
        </div>
      </div>
    );
  };

  const renderResultData = (data: any, depth = 0): React.ReactNode => {
    if (typeof data === "string" || typeof data === "number" || typeof data === "boolean") {
      return <div className="flex items-center gap-2"><span className="text-foreground">{String(data)}</span><CopyBtn text={String(data)} /></div>;
    }
    if (Array.isArray(data)) {
      return data.map((item, i) => <div key={i} className="border-b border-border/30 last:border-0 py-1">{renderResultData(item, depth + 1)}</div>);
    }
    if (data && typeof data === "object") {
      return Object.entries(data).filter(([k]) => !["raw", "rawHeaders"].includes(k)).map(([key, val]) => (
        <div key={key} className="flex gap-2 py-0.5" style={{ paddingLeft: depth * 12 }}>
          <span className="text-primary shrink-0">{key}:</span>
          <span className="text-foreground break-all">{typeof val === "object" ? renderResultData(val, depth + 1) : String(val)}</span>
          {typeof val === "string" && <CopyBtn text={val} />}
        </div>
      ));
    }
    return null;
  };

  return (
    <div className="bg-background">
      <main className="py-4">
        {activeTool ? (
          <div className="space-y-6">
            <Button variant="ghost" onClick={() => { setActiveTool(null); setResult(null); }} className="gap-2 text-muted-foreground hover:text-foreground -ml-2">
              <ArrowLeft className="w-4 h-4" /> Back to All Tools
            </Button>
            <Card className="border-border">
              <div className="p-6 border-b border-border">
                <div className="flex items-center gap-3">
                  {(() => { const t = TOOLS.find(x => x.id === activeTool); const Icon = t?.icon || Globe; return <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-primary/10 border border-primary/20"><Icon className="w-5 h-5 text-primary" /></div>; })()}
                  <div>
                    <h2 className="text-lg font-bold text-foreground">{TOOLS.find(t => t.id === activeTool)?.name}</h2>
                    <p className="text-sm text-muted-foreground">{TOOLS.find(t => t.id === activeTool)?.desc}</p>
                  </div>
                </div>
              </div>
              <CardContent className="p-6 space-y-6">
                {renderToolForm()}
                {renderResult()}
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="space-y-10">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              {[
                { icon: Globe, label: `${TOOLS.filter(t => t.category === "DNS Tools").length} DNS Tools`, desc: "Records & Resolution" },
                { icon: Network, label: `${TOOLS.filter(t => t.category === "IP Tools").length} IP Tools`, desc: "Detection & Lookup" },
                { icon: Shield, label: `${TOOLS.filter(t => t.category === "Network Tools").length} Network Tools`, desc: "Scanning & Analysis" },
                { icon: Zap, label: "Real-time", desc: "Live backend queries" },
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
            {CATEGORIES.map(cat => {
              const meta = catMeta[cat];
              const Icon = meta.icon;
              const tools = TOOLS.filter(t => t.category === cat);
              return (
                <section key={cat}>
                  <div className="flex items-center gap-3 mb-4">
                    <Icon className={`w-5 h-5 ${meta.color}`} />
                    <h2 className="text-lg font-bold text-foreground">{cat}</h2>
                    <span className="text-xs text-muted-foreground">— {meta.desc}</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {tools.map(tool => {
                      const TIcon = tool.icon;
                      return (
                        <Card key={tool.id} className="group cursor-pointer border-border hover:border-primary/40 hover:shadow-md transition-all duration-200" onClick={() => openTool(tool.id)}>
                          <CardContent className="p-4 flex items-center gap-3">
                            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-muted group-hover:bg-primary/10 transition-colors shrink-0">
                              <TIcon className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors truncate">{tool.name}</p>
                              <p className="text-xs text-muted-foreground truncate">{tool.desc}</p>
                            </div>
                            <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-primary transition-colors shrink-0" />
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </section>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
};

export default NetworkDiagnosticsContent;
