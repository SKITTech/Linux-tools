import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Wifi, Activity, Search, Globe, CheckCircle2, XCircle, Clock, Loader2,
  Server, Shield, Zap, Copy, Check, ArrowLeft, MapPin, FileText, ArrowRightLeft,
  Lock, Eye, Network, Scan, Radio, MonitorSmartphone, ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
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
  // DNS Tools
  { id: "dns-lookup", name: "DNS Lookup", desc: "See all DNS records of a domain", icon: Search, category: "DNS Tools" },
  { id: "mx-lookup", name: "MX Lookup", desc: "Mail exchange records of a domain", icon: FileText, category: "DNS Tools" },
  { id: "ns-lookup", name: "NS Lookup", desc: "Name server records of a domain", icon: Server, category: "DNS Tools" },
  { id: "cname-lookup", name: "CNAME Lookup", desc: "Canonical name records of a domain", icon: ArrowRightLeft, category: "DNS Tools" },
  { id: "txt-lookup", name: "TXT Lookup", desc: "Text records of a domain (SPF, DKIM)", icon: FileText, category: "DNS Tools" },
  { id: "soa-lookup", name: "SOA Lookup", desc: "Start of Authority record", icon: Globe, category: "DNS Tools" },
  { id: "reverse-dns", name: "Reverse DNS", desc: "Resolve IP to hostname", icon: ArrowRightLeft, category: "DNS Tools" },

  // IP Tools
  { id: "whats-my-ip", name: "What is My IP", desc: "Lookup your own IP address", icon: Eye, category: "IP Tools" },
  { id: "ip-geolocation", name: "IP Geolocation", desc: "Find physical location of any IP", icon: MapPin, category: "IP Tools" },
  { id: "ping", name: "Ping Test", desc: "Send HTTP requests & measure latency", icon: Activity, category: "IP Tools" },
  { id: "website-to-ip", name: "Website to IP", desc: "Find IP address of a domain", icon: MapPin, category: "IP Tools" },
  { id: "whois", name: "WHOIS Lookup", desc: "Check domain registration details", icon: Search, category: "IP Tools" },

  // Network Tools
  { id: "port-check", name: "Port Checker", desc: "Check if a port is open on a host", icon: Shield, category: "Network Tools" },
  { id: "http-headers", name: "HTTP Headers", desc: "View HTTP response headers of a URL", icon: FileText, category: "Network Tools" },
  { id: "ssl-check", name: "SSL Checker", desc: "Check if a domain has valid SSL", icon: Lock, category: "Network Tools" },
];

const CATEGORIES = ["DNS Tools", "IP Tools", "Network Tools"];

/* ─── Shared ─── */
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
  const entry = map[status] || map.error;
  const Icon = entry.icon;
  return <Badge className={`${entry.cls} gap-1 font-mono text-xs`}><Icon className="w-3 h-3" /> {entry.label}</Badge>;
};

const ResultPanel = ({ title, children, onCopy }: { title: string; children: React.ReactNode; onCopy?: string }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    if (onCopy) {
      await navigator.clipboard.writeText(onCopy);
      setCopied(true);
      toast.success("Copied!");
      setTimeout(() => setCopied(false), 2000);
    }
  };
  return (
    <div className="rounded-xl overflow-hidden border border-[hsl(var(--terminal-border))]">
      <div className="flex items-center justify-between px-4 py-2.5 bg-[hsl(var(--terminal-bg))] border-b border-[hsl(var(--terminal-border))]">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-destructive/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[hsl(45,90%,50%)]/70" />
            <span className="w-2.5 h-2.5 rounded-full bg-[hsl(var(--success))]/70" />
          </div>
          <span className="text-xs font-mono text-[hsl(var(--terminal-text))]/70">{title}</span>
        </div>
        {onCopy && (
          <Button size="sm" variant="ghost" onClick={handleCopy} className="h-6 px-2 text-[hsl(var(--terminal-text))]/60 hover:text-[hsl(var(--terminal-text))] hover:bg-[hsl(var(--terminal-border))]/40">
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          </Button>
        )}
      </div>
      <div className="p-4 bg-[hsl(var(--terminal-bg))] font-mono text-sm text-[hsl(var(--terminal-text))] max-h-[500px] overflow-y-auto">
        {children}
      </div>
    </div>
  );
};

/* ─── Main ─── */
const NetworkDiagnostics = () => {
  const [activeTool, setActiveTool] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState("DNS Tools");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  // Form states
  const [domain, setDomain] = useState("");
  const [dnsType, setDnsType] = useState("A");
  const [ipInput, setIpInput] = useState("");
  const [urlInput, setUrlInput] = useState("");
  const [pingHost, setPingHost] = useState("");
  const [portHost, setPortHost] = useState("");
  const [portNumber, setPortNumber] = useState("");

  const resetResults = () => { setResult(null); };

  const openTool = (id: string) => {
    setActiveTool(id);
    setResult(null);
    // Auto-set DNS type for shortcut lookups
    if (id === "mx-lookup") setDnsType("MX");
    else if (id === "ns-lookup") setDnsType("NS");
    else if (id === "cname-lookup") setDnsType("CNAME");
    else if (id === "txt-lookup") setDnsType("TXT");
    else if (id === "soa-lookup") setDnsType("SOA");
    else if (id === "dns-lookup") setDnsType("A");
  };

  /* ─── Handlers ─── */
  const runDnsLookup = async () => {
    if (!domain.trim()) { toast.error("Enter a domain"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('dns-lookup', {
        body: { domain: domain.trim(), type: dnsType },
      });
      if (error) throw error;
      setResult({ type: 'dns', data });
      toast.success(`Found ${data.records.length} records`);
    } catch (err: any) { toast.error(err.message || "DNS lookup failed"); }
    finally { setLoading(false); }
  };

  const runReverseDns = async () => {
    if (!ipInput.trim()) { toast.error("Enter an IP address"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'reverse-dns', ip: ipInput.trim() },
      });
      if (error) throw error;
      setResult({ type: 'reverse-dns', data });
      toast.success(`Found ${data.hostnames?.length || 0} hostnames`);
    } catch (err: any) { toast.error(err.message || "Reverse DNS failed"); }
    finally { setLoading(false); }
  };

  const runWhatsMyIP = async () => {
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'whats-my-ip' },
      });
      if (error) throw error;
      setResult({ type: 'whats-my-ip', data });
    } catch (err: any) { toast.error(err.message || "Failed"); }
    finally { setLoading(false); }
  };

  const runPing = async () => {
    if (!pingHost.trim()) { toast.error("Enter a hostname"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('ping-check', {
        body: { host: pingHost.trim(), count: 6 },
      });
      if (error) throw error;
      setResult({ type: 'ping', data });
      toast.success("Ping completed");
    } catch (err: any) { toast.error(err.message || "Ping failed"); }
    finally { setLoading(false); }
  };

  const runWebsiteToIP = async () => {
    if (!domain.trim()) { toast.error("Enter a domain"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'website-to-ip', domain: domain.trim() },
      });
      if (error) throw error;
      setResult({ type: 'website-to-ip', data });
    } catch (err: any) { toast.error(err.message || "Failed"); }
    finally { setLoading(false); }
  };

  const runWhois = async () => {
    if (!domain.trim()) { toast.error("Enter a domain"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'whois', query: domain.trim() },
      });
      if (error) throw error;
      setResult({ type: 'whois', data });
    } catch (err: any) { toast.error(err.message || "WHOIS failed"); }
    finally { setLoading(false); }
  };

  const runPortCheck = async () => {
    if (!portHost.trim() || !portNumber.trim()) { toast.error("Enter host and port"); return; }
    const port = parseInt(portNumber);
    if (isNaN(port) || port < 1 || port > 65535) { toast.error("Invalid port"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('check-port', {
        body: { host: portHost.trim(), port, timeout: 5000 },
      });
      if (error) throw error;
      setResult({ type: 'port', data });
      toast.success(`Port ${port} is ${data.status}`);
    } catch (err: any) { toast.error(err.message || "Port check failed"); }
    finally { setLoading(false); }
  };

  const runHttpHeaders = async () => {
    if (!urlInput.trim()) { toast.error("Enter a URL"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'http-headers', url: urlInput.trim() },
      });
      if (error) throw error;
      setResult({ type: 'http-headers', data });
    } catch (err: any) { toast.error(err.message || "Failed"); }
    finally { setLoading(false); }
  };

  const runSSLCheck = async () => {
    if (!domain.trim()) { toast.error("Enter a domain"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'ssl-check', domain: domain.trim() },
      });
      if (error) throw error;
      setResult({ type: 'ssl-check', data });
    } catch (err: any) { toast.error(err.message || "SSL check failed"); }
    finally { setLoading(false); }
  };

  const runIPGeolocation = async () => {
    if (!ipInput.trim()) { toast.error("Enter an IP address"); return; }
    setLoading(true); resetResults();
    try {
      const { data, error } = await supabase.functions.invoke('network-tools', {
        body: { tool: 'ip-geolocation', ip: ipInput.trim() },
      });
      if (error) throw error;
      setResult({ type: 'ip-geolocation', data });
      toast.success(`Geolocation found for ${data.ip}`);
    } catch (err: any) { toast.error(err.message || "Geolocation failed"); }
    finally { setLoading(false); }
  };

  /* ─── Tool Forms ─── */
  const renderToolForm = () => {
    const tool = TOOLS.find(t => t.id === activeTool);
    if (!tool) return null;

    switch (activeTool) {
      case "dns-lookup": case "mx-lookup": case "ns-lookup": case "cname-lookup": case "txt-lookup": case "soa-lookup":
        return (
          <div className="space-y-4">
            <div className="grid sm:grid-cols-[1fr_auto_auto] gap-3 items-end">
              <Field label="Domain Name" hint="e.g. google.com, github.com">
                <Input placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && runDnsLookup()} className="bg-background border-input" />
              </Field>
              <Field label="Record Type">
                <Select value={dnsType} onValueChange={setDnsType}>
                  <SelectTrigger className="bg-background border-input w-44"><SelectValue /></SelectTrigger>
                  <SelectContent className="bg-popover border-border z-50">
                    {DNS_TYPES.map(t => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </Field>
              <Button onClick={runDnsLookup} disabled={loading} className="gap-2 h-10">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                {loading ? "Looking up..." : "Lookup"}
              </Button>
            </div>
          </div>
        );

      case "reverse-dns":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="IP Address" hint="e.g. 8.8.8.8, 1.1.1.1">
              <Input placeholder="8.8.8.8" value={ipInput} onChange={e => setIpInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && runReverseDns()} className="bg-background border-input" />
            </Field>
            <Button onClick={runReverseDns} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRightLeft className="w-4 h-4" />}
              {loading ? "Resolving..." : "Resolve"}
            </Button>
          </div>
        );

      case "whats-my-ip":
        return (
          <div className="flex items-center gap-4">
            <p className="text-sm text-muted-foreground">Click below to discover your public IP address and geolocation info.</p>
            <Button onClick={runWhatsMyIP} disabled={loading} className="gap-2 shrink-0">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              {loading ? "Detecting..." : "Detect My IP"}
            </Button>
          </div>
        );

      case "ip-geolocation":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="IP Address" hint="e.g. 8.8.8.8, 1.1.1.1, or any public IP">
              <Input placeholder="8.8.8.8" value={ipInput} onChange={e => setIpInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && runIPGeolocation()} className="bg-background border-input" />
            </Field>
            <Button onClick={runIPGeolocation} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <MapPin className="w-4 h-4" />}
              {loading ? "Locating..." : "Geolocate"}
            </Button>
          </div>
        );

      case "ping":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="Hostname or URL" hint="e.g. google.com, github.com">
              <Input placeholder="google.com" value={pingHost} onChange={e => setPingHost(e.target.value)} onKeyDown={e => e.key === 'Enter' && runPing()} className="bg-background border-input" />
            </Field>
            <Button onClick={runPing} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
              {loading ? "Pinging..." : "Run Ping"}
            </Button>
          </div>
        );

      case "website-to-ip":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="Domain" hint="e.g. google.com">
              <Input placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && runWebsiteToIP()} className="bg-background border-input" />
            </Field>
            <Button onClick={runWebsiteToIP} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <MapPin className="w-4 h-4" />}
              {loading ? "Resolving..." : "Find IP"}
            </Button>
          </div>
        );

      case "whois":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="Domain Name" hint="e.g. google.com, github.com">
              <Input placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && runWhois()} className="bg-background border-input" />
            </Field>
            <Button onClick={runWhois} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              {loading ? "Looking up..." : "WHOIS Lookup"}
            </Button>
          </div>
        );

      case "port-check":
        return (
          <div className="space-y-4">
            <div className="grid sm:grid-cols-[1fr_7rem_auto] gap-3 items-end">
              <Field label="Hostname or IP">
                <Input placeholder="example.com" value={portHost} onChange={e => setPortHost(e.target.value)} className="bg-background border-input" />
              </Field>
              <Field label="Port">
                <Input type="number" placeholder="443" value={portNumber} onChange={e => setPortNumber(e.target.value)} onKeyDown={e => e.key === 'Enter' && runPortCheck()} className="bg-background border-input" min={1} max={65535} />
              </Field>
              <Button onClick={runPortCheck} disabled={loading} className="gap-2 h-10">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                {loading ? "Checking..." : "Check Port"}
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="text-xs text-muted-foreground self-center mr-1">Quick:</span>
              {PORT_PRESETS.map(({ port, label }) => (
                <Button key={port} variant="outline" size="sm" className="h-7 text-xs font-mono gap-1" onClick={() => setPortNumber(String(port))}>
                  :{port} <span className="text-muted-foreground">{label}</span>
                </Button>
              ))}
            </div>
          </div>
        );

      case "http-headers":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="URL" hint="e.g. https://google.com">
              <Input placeholder="https://example.com" value={urlInput} onChange={e => setUrlInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && runHttpHeaders()} className="bg-background border-input" />
            </Field>
            <Button onClick={runHttpHeaders} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
              {loading ? "Fetching..." : "Get Headers"}
            </Button>
          </div>
        );

      case "ssl-check":
        return (
          <div className="grid sm:grid-cols-[1fr_auto] gap-3 items-end">
            <Field label="Domain" hint="e.g. google.com">
              <Input placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && runSSLCheck()} className="bg-background border-input" />
            </Field>
            <Button onClick={runSSLCheck} disabled={loading} className="gap-2 h-10">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
              {loading ? "Checking..." : "Check SSL"}
            </Button>
          </div>
        );

      default: return null;
    }
  };

  /* ─── Result Renderers ─── */
  const renderResult = () => {
    if (!result) return null;
    const { type, data } = result;

    switch (type) {
      case 'dns':
        return (
          <ResultPanel title={`dig ${data.domain} ${data.queryType}`} onCopy={JSON.stringify(data, null, 2)}>
            <p className="text-muted-foreground mb-3">;; status={data.status}, server={data.server}, time={data.queryTime}ms</p>
            {data.records.length > 0 ? (
              <>
                <p className="text-accent mb-1">;; ANSWER SECTION ({data.records.length} records):</p>
                {data.records.map((r: any, i: number) => (
                  <div key={i} className="flex gap-3">
                    <span className="text-muted-foreground min-w-[160px] truncate">{r.name}</span>
                    <span className="text-muted-foreground w-12 text-right">{r.ttl}</span>
                    <span className="w-12 text-accent">{r.type}</span>
                    <span className="flex-1 break-all">{r.data}</span>
                  </div>
                ))}
              </>
            ) : <p className="text-destructive">;; No records found</p>}
            {data.authority?.length > 0 && (
              <>
                <p className="text-accent mt-4 mb-1">;; AUTHORITY SECTION:</p>
                {data.authority.map((r: any, i: number) => (
                  <div key={i} className="flex gap-3 text-[hsl(var(--terminal-text))]/70">
                    <span className="text-muted-foreground min-w-[160px] truncate">{r.name}</span>
                    <span className="text-muted-foreground w-12 text-right">{r.ttl}</span>
                    <span className="w-12">{r.type}</span>
                    <span className="flex-1 break-all">{r.data}</span>
                  </div>
                ))}
              </>
            )}
          </ResultPanel>
        );

      case 'reverse-dns':
        return (
          <ResultPanel title={`reverse-dns ${data.ip}`} onCopy={JSON.stringify(data, null, 2)}>
            <div className="space-y-2">
              <div className="flex gap-3"><span className="text-muted-foreground w-24">IP:</span><span>{data.ip}</span></div>
              <div className="flex gap-3"><span className="text-muted-foreground w-24">Status:</span><span>{data.status}</span></div>
              <div className="flex gap-3"><span className="text-muted-foreground w-24">Query:</span><span>{data.query}</span></div>
              <div className="flex gap-3 items-start"><span className="text-muted-foreground w-24">Hostnames:</span>
                <div>{data.hostnames?.length > 0 ? data.hostnames.map((h: string, i: number) => <div key={i} className="text-accent">{h}</div>) : <span className="text-destructive">No PTR records found</span>}</div>
              </div>
            </div>
          </ResultPanel>
        );

      case 'whats-my-ip':
        return (
          <ResultPanel title="my-ip" onCopy={data.ip}>
            <div className="space-y-2">
              {Object.entries(data).map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <span className="text-muted-foreground w-24 capitalize">{k.replace(/([A-Z])/g, ' $1')}:</span>
                  <span className={k === 'ip' ? 'text-accent font-bold text-base' : ''}>{String(v)}</span>
                </div>
              ))}
            </div>
          </ResultPanel>
        );

      case 'ping':
        return (
          <ResultPanel title={`ping ${data.host || pingHost}`} onCopy={JSON.stringify(data, null, 2)}>
            <p className="text-muted-foreground mb-2">HTTP connectivity check to {data.host || pingHost}</p>
            {data.results?.map((r: any) => (
              <div key={r.seq} className="flex items-center gap-3 py-1">
                <span className="text-muted-foreground w-16">seq={r.seq}</span>
                <StatusBadge status={r.status === 'ok' ? 'ok' : r.status === 'timeout' ? 'timeout' : 'error'} />
                <span>time={r.time}ms</span>
              </div>
            ))}
            {data.summary && (
              <div className="mt-4 pt-3 border-t border-[hsl(var(--terminal-border))] text-xs">
                <p>{data.summary.sent} packets sent, {data.summary.received} received, {data.summary.lossPercent}% loss</p>
                {data.summary.stats && <p className="text-accent">rtt min/avg/max = {data.summary.stats.min}/{data.summary.stats.avg}/{data.summary.stats.max} ms</p>}
              </div>
            )}
          </ResultPanel>
        );

      case 'website-to-ip':
        return (
          <ResultPanel title={`resolve ${data.domain}`} onCopy={JSON.stringify(data, null, 2)}>
            <div className="space-y-2">
              <div className="flex gap-3"><span className="text-muted-foreground w-24">Domain:</span><span>{data.domain}</span></div>
              <div className="flex gap-3 items-start"><span className="text-muted-foreground w-24">IPv4:</span>
                <div>{data.ipv4?.length > 0 ? data.ipv4.map((ip: string, i: number) => <div key={i} className="text-accent">{ip}</div>) : <span className="text-muted-foreground">None</span>}</div>
              </div>
              <div className="flex gap-3 items-start"><span className="text-muted-foreground w-24">IPv6:</span>
                <div>{data.ipv6?.length > 0 ? data.ipv6.map((ip: string, i: number) => <div key={i} className="text-accent">{ip}</div>) : <span className="text-muted-foreground">None</span>}</div>
              </div>
              <div className="flex gap-3"><span className="text-muted-foreground w-24">IPv6 Ready:</span>
                {data.hasIPv6 ? <Badge className="bg-[hsl(var(--success))] text-[hsl(var(--success-foreground))] text-xs">Yes</Badge> : <Badge variant="secondary" className="text-xs">No</Badge>}
              </div>
            </div>
          </ResultPanel>
        );

      case 'whois':
        return (
          <ResultPanel title={`whois ${data.query || data.name}`} onCopy={JSON.stringify(data, null, 2)}>
            {data.error ? (
              <p className="text-destructive">{data.error}</p>
            ) : (
              <div className="space-y-2">
                <div className="flex gap-3"><span className="text-muted-foreground w-28">Domain:</span><span className="text-accent">{data.name}</span></div>
                <div className="flex gap-3"><span className="text-muted-foreground w-28">Registrar:</span><span>{data.registrar}</span></div>
                <div className="flex gap-3"><span className="text-muted-foreground w-28">Created:</span><span>{data.created}</span></div>
                <div className="flex gap-3"><span className="text-muted-foreground w-28">Updated:</span><span>{data.updated}</span></div>
                <div className="flex gap-3"><span className="text-muted-foreground w-28">Expires:</span><span>{data.expires}</span></div>
                <div className="flex gap-3 items-start"><span className="text-muted-foreground w-28">Status:</span>
                  <div className="flex flex-wrap gap-1">{(data.status || []).map((s: string, i: number) => <Badge key={i} variant="secondary" className="text-xs font-mono">{s}</Badge>)}</div>
                </div>
                <div className="flex gap-3 items-start"><span className="text-muted-foreground w-28">Nameservers:</span>
                  <div>{(data.nameservers || []).map((ns: string, i: number) => <div key={i}>{ns}</div>)}</div>
                </div>
              </div>
            )}
          </ResultPanel>
        );

      case 'port':
        return (
          <ResultPanel title={`port-check ${data.host}:${data.port}`} onCopy={JSON.stringify(data, null, 2)}>
            <div className="space-y-2">
              <div className="flex items-center gap-3"><span className="text-muted-foreground w-24">Status:</span><StatusBadge status={data.status} /></div>
              <div className="flex gap-3"><span className="text-muted-foreground w-24">Host:</span><span>{data.host}:{data.port}</span></div>
              {data.service && <div className="flex gap-3"><span className="text-muted-foreground w-24">Service:</span><span>{data.service}</span></div>}
              {data.responseTime !== undefined && <div className="flex gap-3"><span className="text-muted-foreground w-24">Latency:</span><span>{data.responseTime}ms</span></div>}
              {data.error && <div className="flex gap-3"><span className="text-muted-foreground w-24">Detail:</span><span className="text-destructive">{data.error}</span></div>}
            </div>
          </ResultPanel>
        );

      case 'http-headers':
        return (
          <ResultPanel title={`headers ${data.url}`} onCopy={JSON.stringify(data.headers, null, 2)}>
            <div className="space-y-2 mb-4">
              <div className="flex gap-3"><span className="text-muted-foreground w-28">Status:</span><span>{data.status} {data.statusText}</span></div>
              <div className="flex gap-3"><span className="text-muted-foreground w-28">Response Time:</span><span>{data.responseTime}ms</span></div>
              {data.redirected && <div className="flex gap-3"><span className="text-muted-foreground w-28">Final URL:</span><span>{data.finalUrl}</span></div>}
            </div>
            <p className="text-accent mb-2">;; HEADERS:</p>
            {Object.entries(data.headers || {}).map(([k, v]) => (
              <div key={k} className="flex gap-3 py-0.5">
                <span className="text-accent min-w-[200px] truncate">{k}:</span>
                <span className="break-all">{String(v)}</span>
              </div>
            ))}
          </ResultPanel>
        );

      case 'ssl-check':
        return (
          <ResultPanel title={`ssl-check ${data.domain}`} onCopy={JSON.stringify(data, null, 2)}>
            <div className="space-y-2">
              <div className="flex items-center gap-3"><span className="text-muted-foreground w-28">SSL Valid:</span>
                {data.sslValid
                  ? <Badge className="bg-[hsl(var(--success))] text-[hsl(var(--success-foreground))] gap-1 text-xs"><Lock className="w-3 h-3" /> SECURE</Badge>
                  : <Badge className="bg-destructive text-destructive-foreground gap-1 text-xs"><XCircle className="w-3 h-3" /> INVALID</Badge>}
              </div>
              {data.statusCode && <div className="flex gap-3"><span className="text-muted-foreground w-28">Status Code:</span><span>{data.statusCode}</span></div>}
              {data.responseTime && <div className="flex gap-3"><span className="text-muted-foreground w-28">Response Time:</span><span>{data.responseTime}ms</span></div>}
              {data.protocol && <div className="flex gap-3"><span className="text-muted-foreground w-28">Protocol:</span><span>{data.protocol}</span></div>}
              {data.error && <div className="flex gap-3"><span className="text-muted-foreground w-28">Error:</span><span className="text-destructive">{data.error}</span></div>}
            </div>
          </ResultPanel>
        );

      case 'ip-geolocation':
        return (
          <ResultPanel title={`geolocate ${data.ip}`} onCopy={JSON.stringify(data, null, 2)}>
            {data.error ? (
              <p className="text-destructive">{data.error}</p>
            ) : (
              <div className="space-y-4">
                <div className="grid sm:grid-cols-2 gap-x-8 gap-y-2">
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">IP Address:</span><span className="text-accent font-bold">{data.ip}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Continent:</span><span>{data.continent}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Country:</span><span>{data.country} {data.countryCode ? `(${data.countryCode})` : ''}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Region:</span><span>{data.region} {data.regionCode ? `(${data.regionCode})` : ''}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">City:</span><span>{data.city}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">ZIP Code:</span><span>{data.zip}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Latitude:</span><span>{data.lat}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Longitude:</span><span>{data.lon}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Timezone:</span><span>{data.timezone}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Currency:</span><span>{data.currency}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">ISP:</span><span>{data.isp}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">Organization:</span><span>{data.org}</span></div>
                  <div className="flex gap-3"><span className="text-muted-foreground w-28">AS Number:</span><span>{data.as}</span></div>
                  {data.reverse && <div className="flex gap-3"><span className="text-muted-foreground w-28">Reverse DNS:</span><span>{data.reverse}</span></div>}
                </div>
                <div className="flex flex-wrap gap-2 pt-2 border-t border-[hsl(var(--terminal-border))]">
                  {data.mobile && <Badge variant="secondary" className="text-xs">📱 Mobile</Badge>}
                  {data.proxy && <Badge className="bg-destructive text-destructive-foreground text-xs">🛡️ Proxy/VPN</Badge>}
                  {data.hosting && <Badge variant="secondary" className="text-xs">☁️ Hosting/DC</Badge>}
                  {!data.mobile && !data.proxy && !data.hosting && <Badge className="bg-[hsl(var(--success))] text-[hsl(var(--success-foreground))] text-xs">✓ Residential</Badge>}
                </div>
              </div>
            )}
          </ResultPanel>
        );

      default: return null;
    }
  };

  /* ─── Category colors ─── */
  const catMeta: Record<string, { icon: any; color: string; desc: string }> = {
    "DNS Tools": { icon: Globe, color: "text-primary", desc: "Lookup DNS records, reverse DNS, and more" },
    "IP Tools": { icon: Network, color: "text-accent", desc: "IP detection, ping, WHOIS, and domain resolution" },
    "Network Tools": { icon: Shield, color: "text-[hsl(var(--success))]", desc: "Port scanning, HTTP headers, and SSL verification" },
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Hero */}
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
                  Professional-grade DNS, IP, and network tools — all live, no simulation.
                </p>
              </div>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
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
          </div>
        </header>

        <main className="container mx-auto px-4 py-8 sm:px-6 lg:px-8">
          {activeTool ? (
            /* ─── Active Tool View ─── */
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
            /* ─── Tools Directory ─── */
            <div className="space-y-10">
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
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                      {tools.map(tool => {
                        const TIcon = tool.icon;
                        return (
                          <Card
                            key={tool.id}
                            className="group cursor-pointer border-border hover:border-primary/40 hover:shadow-md transition-all duration-200"
                            onClick={() => openTool(tool.id)}
                          >
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
    </Sidebar>
  );
};

export default NetworkDiagnostics;
