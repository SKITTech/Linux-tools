import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import {
  Shield, Copy, Check, Download, Terminal, AlertTriangle,
  ShieldCheck, ShieldX, BookOpen, Wrench, Zap, Info, Eye,
  ChevronRight, Search, FileText, Lock
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// ── Types & Constants ──

type FirewallSystem = "iptables" | "nftables" | "ufw" | "firewalld";
type Protocol = "tcp" | "udp" | "icmp";
type Direction = "inbound" | "outbound";
type RuleAction = "accept" | "drop" | "reject";
type FirewalldZone = "public" | "internal" | "dmz" | "work" | "home" | "trusted" | "drop" | "block";

interface GeneratorState {
  system: FirewallSystem;
  port: string;
  protocol: Protocol;
  direction: Direction;
  action: RuleAction;
  sourceIp: string;
  zone: FirewalldZone;
  commonService: string;
}

const COMMON_SERVICES: { label: string; ports: string; protocol: Protocol }[] = [
  { label: "Web Server (80,443)", ports: "80,443", protocol: "tcp" },
  { label: "SSH Server (22)", ports: "22", protocol: "tcp" },
  { label: "DNS (53)", ports: "53", protocol: "udp" },
  { label: "FTP (21,20)", ports: "21,20", protocol: "tcp" },
  { label: "RDP (3389)", ports: "3389", protocol: "tcp" },
  { label: "MySQL/MariaDB (3306)", ports: "3306", protocol: "tcp" },
  { label: "PostgreSQL (5432)", ports: "5432", protocol: "tcp" },
  { label: "MongoDB (27017)", ports: "27017", protocol: "tcp" },
  { label: "Elasticsearch (9200,9300)", ports: "9200,9300", protocol: "tcp" },
  { label: "Kubernetes (6443)", ports: "6443", protocol: "tcp" },
  { label: "Docker (2375,2376)", ports: "2375,2376", protocol: "tcp" },
  { label: "SMTP Server (25,465,587)", ports: "25,465,587", protocol: "tcp" },
  { label: "Redis (6379)", ports: "6379", protocol: "tcp" },
  { label: "Webmin (10000)", ports: "10000", protocol: "tcp" },
  { label: "Cockpit (9090)", ports: "9090", protocol: "tcp" },
  { label: "WireGuard (51820)", ports: "51820", protocol: "udp" },
  { label: "OpenVPN (1194)", ports: "1194", protocol: "udp" },
];

const WELL_KNOWN_PORTS: Record<string, string> = {
  "22": "SSH", "80": "HTTP", "443": "HTTPS", "53": "DNS",
  "25": "SMTP", "110": "POP3", "143": "IMAP", "993": "IMAPS",
  "995": "POP3S", "587": "SMTP Submission", "465": "SMTPS",
  "21": "FTP", "20": "FTP-data", "3306": "MySQL", "5432": "PostgreSQL",
  "6379": "Redis", "27017": "MongoDB", "8080": "HTTP-alt", "8443": "HTTPS-alt",
  "3389": "RDP", "5900": "VNC", "1194": "OpenVPN", "51820": "WireGuard",
  "2049": "NFS", "111": "RPCBind", "123": "NTP", "161": "SNMP",
  "10000": "Webmin", "1723": "PPTP", "500": "IKE/IPSec", "514": "Syslog",
  "873": "rsync", "2222": "SSH-alt", "8888": "Alt-HTTP", "9090": "Cockpit",
};

const SYSTEM_DESCRIPTIONS: Record<FirewallSystem, string> = {
  iptables: "The classic Linux packet filtering framework. Most widely documented and used.",
  nftables: "Modern replacement for iptables with better syntax and performance. Default in newer distros.",
  ufw: "Uncomplicated Firewall — a user-friendly frontend for iptables on Ubuntu/Debian.",
  firewalld: "Dynamic firewall manager with zone support. Default on RHEL, CentOS, Fedora.",
};

// ── Command Generation ──

function generateCommands(state: GeneratorState): string[] {
  const ports = state.port.split(",").map(p => p.trim()).filter(Boolean);
  if (ports.length === 0) return [];

  const commands: string[] = [];

  for (const port of ports) {
    switch (state.system) {
      case "iptables": {
        const chain = state.direction === "inbound" ? "INPUT" : "OUTPUT";
        const target = state.action === "accept" ? "ACCEPT" : state.action === "drop" ? "DROP" : "REJECT";
        let cmd = `iptables -A ${chain} -p ${state.protocol}`;
        if (state.sourceIp) cmd += ` -s ${state.sourceIp}`;
        if (state.protocol !== "icmp") cmd += ` --dport ${port}`;
        cmd += ` -j ${target}`;
        commands.push(cmd);
        break;
      }
      case "nftables": {
        const chain = state.direction === "inbound" ? "input" : "output";
        const action = state.action;
        let cmd = `nft add rule inet filter ${chain} ${state.protocol}`;
        if (state.sourceIp) cmd += ` ip saddr ${state.sourceIp}`;
        if (state.protocol !== "icmp") cmd += ` dport ${port}`;
        cmd += ` ${action}`;
        commands.push(cmd);
        break;
      }
      case "ufw": {
        const actionStr = state.action === "accept" ? "allow" : "deny";
        const dirStr = state.direction === "inbound" ? "in" : "out";
        let cmd = `ufw ${actionStr} ${dirStr}`;
        if (state.sourceIp) cmd += ` from ${state.sourceIp}`;
        cmd += ` to any port ${port} proto ${state.protocol}`;
        commands.push(cmd);
        break;
      }
      case "firewalld": {
        if (state.action === "accept") {
          commands.push(`firewall-cmd --zone=${state.zone} --add-port=${port}/${state.protocol} --permanent`);
        } else {
          commands.push(`firewall-cmd --zone=${state.zone} --add-rich-rule='rule family="ipv4"${state.sourceIp ? ` source address="${state.sourceIp}"` : ""} port port="${port}" protocol="${state.protocol}" ${state.action === "drop" ? "drop" : "reject"}'  --permanent`);
        }
        break;
      }
    }
  }

  // Add reload command for firewalld
  if (state.system === "firewalld") {
    commands.push("firewall-cmd --reload");
  }

  return commands;
}

// ── Rule Parser for Review Tab ──

interface ParsedRule {
  original: string;
  action: string;
  protocol: string;
  port: string;
  source: string;
  destination: string;
  direction: string;
  explanation: string;
  risk: "safe" | "warning" | "danger";
  riskNote: string;
}

function parseFirewallRules(input: string): ParsedRule[] {
  const lines = input.split("\n").filter(l => l.trim() && !l.trim().startsWith("#"));
  const results: ParsedRule[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    let parsed: ParsedRule = {
      original: trimmed,
      action: "unknown",
      protocol: "any",
      port: "all",
      source: "any",
      destination: "any",
      direction: "inbound",
      explanation: "",
      risk: "safe",
      riskNote: "",
    };

    // iptables
    if (/^(sudo\s+)?iptables/i.test(trimmed)) {
      const actionMatch = trimmed.match(/-j\s+(\w+)/i);
      const protoMatch = trimmed.match(/-p\s+(\w+)/i);
      const portMatch = trimmed.match(/--dport\s+([\d:,-]+)/i);
      const srcMatch = trimmed.match(/-s\s+([\d./]+)/i);
      const dstMatch = trimmed.match(/-d\s+([\d./]+)/i);
      const chainMatch = trimmed.match(/-A\s+(\w+)/i);

      parsed.action = actionMatch?.[1] || "unknown";
      parsed.protocol = protoMatch?.[1] || "any";
      parsed.port = portMatch?.[1] || "all";
      parsed.source = srcMatch?.[1] || "any";
      parsed.destination = dstMatch?.[1] || "any";
      parsed.direction = chainMatch?.[1] === "OUTPUT" ? "outbound" : "inbound";

      const portName = WELL_KNOWN_PORTS[parsed.port] || "";
      const actionWord = parsed.action === "ACCEPT" ? "Allow" : parsed.action === "DROP" ? "Silently drop" : parsed.action === "REJECT" ? "Reject" : parsed.action;
      parsed.explanation = `${actionWord} ${parsed.protocol.toUpperCase()} traffic on port ${parsed.port}${portName ? ` (${portName})` : ""} from ${parsed.source}`;
    }
    // ufw
    else if (/^(sudo\s+)?ufw/i.test(trimmed)) {
      const allowDeny = /ufw\s+(allow|deny|reject)/i.exec(trimmed);
      const portMatch = /port\s+([\d:,-]+)/i.exec(trimmed) || /\b(\d+)\b/.exec(trimmed.replace(/^.*?(allow|deny|reject)\s*/i, ""));
      const fromMatch = /from\s+([\d./]+)/i.exec(trimmed);
      const protoMatch = /proto\s+(\w+)/i.exec(trimmed);

      parsed.action = allowDeny?.[1]?.toUpperCase() || "unknown";
      parsed.port = portMatch?.[1] || "all";
      parsed.source = fromMatch?.[1] || "any";
      parsed.protocol = protoMatch?.[1] || "any";
      const portName = WELL_KNOWN_PORTS[parsed.port] || "";
      parsed.explanation = `${parsed.action === "ALLOW" ? "Allow" : "Block"} ${parsed.protocol} traffic on port ${parsed.port}${portName ? ` (${portName})` : ""} from ${parsed.source}`;
    }
    // firewall-cmd
    else if (/firewall-cmd/i.test(trimmed)) {
      const portMatch = /--add-port=([\d/-]+)/i.exec(trimmed);
      const svcMatch = /--add-service=(\w+)/i.exec(trimmed);
      const zoneMatch = /--zone=(\w+)/i.exec(trimmed);

      if (portMatch) {
        const [port, proto] = portMatch[1].split("/");
        parsed.port = port;
        parsed.protocol = proto || "tcp";
        parsed.action = "ALLOW";
        parsed.explanation = `Allow ${parsed.protocol} traffic on port ${port} in ${zoneMatch?.[1] || "default"} zone`;
      } else if (svcMatch) {
        parsed.action = "ALLOW";
        parsed.explanation = `Allow the ${svcMatch[1]} service in ${zoneMatch?.[1] || "default"} zone`;
      } else {
        parsed.explanation = "Firewalld configuration command";
      }
    }
    // nft
    else if (/^(sudo\s+)?nft/i.test(trimmed)) {
      const actionMatch = /(accept|drop|reject)\s*$/i.exec(trimmed);
      const portMatch = /dport\s+([\d,-]+)/i.exec(trimmed);
      const srcMatch = /saddr\s+([\d./]+)/i.exec(trimmed);
      const protoMatch = /\b(tcp|udp|icmp)\b/i.exec(trimmed);

      parsed.action = actionMatch?.[1]?.toUpperCase() || "unknown";
      parsed.port = portMatch?.[1] || "all";
      parsed.source = srcMatch?.[1] || "any";
      parsed.protocol = protoMatch?.[1] || "any";
      parsed.explanation = `${parsed.action === "ACCEPT" ? "Allow" : "Block"} ${parsed.protocol} on port ${parsed.port} from ${parsed.source}`;
    } else {
      parsed.explanation = "Unrecognized rule format";
      parsed.risk = "warning";
      parsed.riskNote = "Could not parse this rule — verify manually";
    }

    // Risk assessment
    if (parsed.port === "all" && (parsed.action === "ACCEPT" || parsed.action === "ALLOW")) {
      parsed.risk = "danger";
      parsed.riskNote = "⚠️ This opens ALL ports — extremely dangerous!";
    } else if (parsed.source === "any" && parsed.port === "22" && (parsed.action === "ACCEPT" || parsed.action === "ALLOW")) {
      parsed.risk = "warning";
      parsed.riskNote = "SSH open to all IPs — consider restricting to specific source";
    } else if (parsed.source === "any" && parsed.port === "3306") {
      parsed.risk = "warning";
      parsed.riskNote = "Database port open to all — restrict to application server IPs";
    } else if (["DROP", "REJECT", "DENY"].includes(parsed.action)) {
      parsed.risk = "safe";
      parsed.riskNote = "Blocking rule — good for security";
    }

    results.push(parsed);
  }

  return results;
}

// ── Diagnostic Commands ──

interface DiagnosticCommand {
  command: string;
  description: string;
  category: "status" | "list" | "debug" | "save";
}

function getDiagnosticCommands(system: FirewallSystem): DiagnosticCommand[] {
  switch (system) {
    case "iptables":
      return [
        { command: "iptables -L -v -n", description: "List all rules with verbose output and numeric addresses", category: "list" },
        { command: "iptables -L -v -n --line-numbers", description: "List rules with line numbers for easy reference", category: "list" },
        { command: "iptables -S", description: "Print all rules in iptables-save format", category: "list" },
        { command: "iptables -t nat -L -v -n", description: "List NAT table rules (port forwarding, masquerading)", category: "list" },
        { command: "iptables -t mangle -L -v -n", description: "List mangle table rules (packet alteration)", category: "list" },
        { command: "systemctl status iptables", description: "Check iptables service status", category: "status" },
        { command: "iptables -Z", description: "Zero all packet and byte counters in all chains", category: "debug" },
        { command: "iptables -L -v -n | grep DROP", description: "Show only DROP rules to find blocked traffic", category: "debug" },
        { command: "cat /var/log/syslog | grep iptables", description: "Check syslog for iptables log entries", category: "debug" },
        { command: "dmesg | grep -i iptables", description: "Check kernel messages for iptables entries", category: "debug" },
        { command: "iptables-save > /etc/iptables/rules.v4", description: "Save current rules persistently (Debian/Ubuntu)", category: "save" },
        { command: "service iptables save", description: "Save current rules persistently (RHEL/CentOS)", category: "save" },
        { command: "iptables -F && iptables -X", description: "Flush all rules and delete custom chains (⚠️ dangerous)", category: "debug" },
      ];
    case "nftables":
      return [
        { command: "nft list ruleset", description: "Show the entire nftables ruleset", category: "list" },
        { command: "nft list tables", description: "List all tables", category: "list" },
        { command: "nft list table inet filter", description: "List rules in the inet filter table", category: "list" },
        { command: "nft list chain inet filter input", description: "List rules in the input chain", category: "list" },
        { command: "nft monitor", description: "Monitor nftables events in real-time", category: "debug" },
        { command: "systemctl status nftables", description: "Check nftables service status", category: "status" },
        { command: "nft -a list ruleset", description: "List ruleset with handle numbers for deletion", category: "list" },
        { command: "nft flush ruleset", description: "Clear all rules (⚠️ dangerous)", category: "debug" },
        { command: "nft list ruleset > /etc/nftables.conf", description: "Save current rules to config file", category: "save" },
        { command: "systemctl enable nftables", description: "Enable nftables to start on boot", category: "save" },
      ];
    case "ufw":
      return [
        { command: "ufw status", description: "Show UFW status and active rules", category: "status" },
        { command: "ufw status verbose", description: "Show detailed status with default policies", category: "status" },
        { command: "ufw status numbered", description: "Show rules with numbers for easy deletion", category: "list" },
        { command: "ufw app list", description: "List available application profiles", category: "list" },
        { command: "ufw app info OpenSSH", description: "Show details for an application profile", category: "list" },
        { command: "ufw show raw", description: "Show raw iptables rules behind UFW", category: "debug" },
        { command: "ufw show listening", description: "Show listening ports and associated rules", category: "debug" },
        { command: "cat /var/log/ufw.log | tail -50", description: "Check recent UFW log entries", category: "debug" },
        { command: "ufw enable", description: "Enable UFW firewall", category: "status" },
        { command: "ufw disable", description: "Disable UFW firewall (⚠️ disables all protection)", category: "status" },
        { command: "ufw reset", description: "Reset UFW to default settings (⚠️ removes all rules)", category: "debug" },
      ];
    case "firewalld":
      return [
        { command: "firewall-cmd --state", description: "Check if firewalld is running", category: "status" },
        { command: "firewall-cmd --list-all", description: "List all rules in the default zone", category: "list" },
        { command: "firewall-cmd --list-all-zones", description: "List rules for all zones", category: "list" },
        { command: "firewall-cmd --get-active-zones", description: "Show which zones are active and on which interfaces", category: "status" },
        { command: "firewall-cmd --get-default-zone", description: "Show the current default zone", category: "status" },
        { command: "firewall-cmd --list-services", description: "List allowed services in the default zone", category: "list" },
        { command: "firewall-cmd --list-ports", description: "List open ports in the default zone", category: "list" },
        { command: "firewall-cmd --list-rich-rules", description: "List rich rules for granular control", category: "list" },
        { command: "firewall-cmd --get-log-denied", description: "Check logging level for denied packets", category: "debug" },
        { command: "firewall-cmd --set-log-denied=all", description: "Enable logging for all denied packets", category: "debug" },
        { command: "journalctl -u firewalld -f", description: "Follow firewalld logs in real-time", category: "debug" },
        { command: "firewall-cmd --runtime-to-permanent", description: "Save runtime rules to permanent config", category: "save" },
        { command: "firewall-cmd --reload", description: "Reload firewalld to apply permanent changes", category: "save" },
        { command: "systemctl status firewalld", description: "Check firewalld service status", category: "status" },
      ];
  }
}

// ── Copy helper ──
function useCopyState() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success("Copied to clipboard!");
    setTimeout(() => setCopiedId(null), 2000);
  };
  return { copiedId, copy };
}

// ── Component ──

const FirewallGenerator = () => {
  const [activeTab, setActiveTab] = useState("generator");
  const { copiedId, copy } = useCopyState();

  // Generator state
  const [gen, setGen] = useState<GeneratorState>({
    system: "firewalld",
    port: "",
    protocol: "tcp",
    direction: "inbound",
    action: "accept",
    sourceIp: "",
    zone: "public",
    commonService: "",
  });

  // Review state
  const [reviewInput, setReviewInput] = useState("");
  const parsedRules = useMemo(() => reviewInput.trim() ? parseFirewallRules(reviewInput) : [], [reviewInput]);

  // Diagnostics state
  const [diagSystem, setDiagSystem] = useState<FirewallSystem>("iptables");
  const [diagFilter, setDiagFilter] = useState<string>("all");
  const diagnosticCommands = useMemo(() => getDiagnosticCommands(diagSystem), [diagSystem]);
  const filteredDiagCmds = useMemo(() =>
    diagFilter === "all" ? diagnosticCommands : diagnosticCommands.filter(c => c.category === diagFilter),
    [diagnosticCommands, diagFilter]
  );

  // Generated commands
  const commands = useMemo(() => generateCommands(gen), [gen]);

  const handleServiceSelect = (value: string) => {
    const svc = COMMON_SERVICES.find(s => s.label === value);
    if (svc) {
      setGen(prev => ({ ...prev, port: svc.ports, protocol: svc.protocol, commonService: value }));
    }
  };

  const copyAllCommands = () => {
    copy(commands.join("\n"), "all-cmds");
  };

  const downloadScript = () => {
    const header = gen.system === "iptables" || gen.system === "ufw"
      ? `#!/bin/bash\n# Firewall Rules — Generated by SysToolKit\n# System: ${gen.system} | Date: ${new Date().toISOString().split("T")[0]}\n\nset -euo pipefail\n\n`
      : gen.system === "nftables"
      ? `#!/usr/sbin/nft -f\n# Firewall Rules — Generated by SysToolKit\n# Date: ${new Date().toISOString().split("T")[0]}\n\n`
      : `#!/bin/bash\n# Firewall Rules — Generated by SysToolKit\n# System: firewalld | Date: ${new Date().toISOString().split("T")[0]}\n\nset -euo pipefail\n\n`;

    const content = header + commands.join("\n") + "\n";
    const ext = gen.system === "nftables" ? ".nft" : ".sh";
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `firewall-rules${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Script downloaded!");
  };

  const riskColor = (risk: ParsedRule["risk"]) => {
    switch (risk) {
      case "safe": return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
      case "warning": return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "danger": return "bg-red-500/15 text-red-400 border-red-500/30";
    }
  };

  const categoryIcon = (cat: string) => {
    switch (cat) {
      case "status": return <ShieldCheck className="w-3.5 h-3.5" />;
      case "list": return <Search className="w-3.5 h-3.5" />;
      case "debug": return <Wrench className="w-3.5 h-3.5" />;
      case "save": return <FileText className="w-3.5 h-3.5" />;
      default: return <Terminal className="w-3.5 h-3.5" />;
    }
  };

  const categoryColor = (cat: string) => {
    switch (cat) {
      case "status": return "bg-primary/15 text-primary border-primary/30";
      case "list": return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
      case "debug": return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "save": return "bg-violet-500/15 text-violet-400 border-violet-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-6 max-w-6xl">
          {/* Header */}
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20">
              <Shield className="w-7 h-7 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">Firewall Management Tool</h1>
              <p className="text-sm text-muted-foreground">Generate, understand, and debug Linux firewall rules</p>
            </div>
          </div>

          {/* Main Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="mb-6 w-full justify-start bg-card border border-border">
              <TabsTrigger value="generator" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <Shield className="w-4 h-4" />Firewall Generator
              </TabsTrigger>
              <TabsTrigger value="review" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <BookOpen className="w-4 h-4" />Review & Explanation
              </TabsTrigger>
              <TabsTrigger value="diagnostics" className="gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <Terminal className="w-4 h-4" />Commands & Diagnostics
              </TabsTrigger>
            </TabsList>

            {/* ═══════════════════════════════════════════════ */}
            {/* TAB 1: FIREWALL GENERATOR                      */}
            {/* ═══════════════════════════════════════════════ */}
            <TabsContent value="generator">
              <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                {/* Left: Form */}
                <div className="lg:col-span-3 space-y-5">
                  <Card className="border-border/50 overflow-hidden">
                    <CardHeader className="pb-3 bg-card">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Shield className="w-5 h-5 text-primary" />
                        Firewall Rule Generator
                      </CardTitle>
                      <CardDescription>
                        Generate firewall rules to allow specific ports for various Linux firewall systems.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-5 pt-4">
                      {/* System description */}
                      <div className="rounded-lg bg-primary/5 border border-primary/20 p-3">
                        <p className="text-sm text-primary">{SYSTEM_DESCRIPTIONS[gen.system]}</p>
                      </div>

                      {/* Row 1: System & Port */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <Label className="text-xs text-muted-foreground mb-1.5 block">Select Firewall System</Label>
                          <Select value={gen.system} onValueChange={(v) => setGen(prev => ({ ...prev, system: v as FirewallSystem }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="firewalld">FirewallD</SelectItem>
                              <SelectItem value="iptables">IPTables</SelectItem>
                              <SelectItem value="ufw">UFW (Uncomplicated Firewall)</SelectItem>
                              <SelectItem value="nftables">NFTables</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label className="text-xs text-muted-foreground mb-1.5 block">Port(s)</Label>
                          <Input
                            value={gen.port}
                            onChange={(e) => setGen(prev => ({ ...prev, port: e.target.value, commonService: "" }))}
                            placeholder="80 or 80-85 or 80,443"
                          />
                        </div>
                      </div>

                      {/* Row 2: Protocol & Zone/Direction */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <Label className="text-xs text-muted-foreground mb-1.5 block">Protocol</Label>
                          <Select value={gen.protocol} onValueChange={(v) => setGen(prev => ({ ...prev, protocol: v as Protocol }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="tcp">TCP</SelectItem>
                              <SelectItem value="udp">UDP</SelectItem>
                              <SelectItem value="icmp">ICMP</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {gen.system === "firewalld" ? (
                          <div>
                            <Label className="text-xs text-muted-foreground mb-1.5 block">Zone</Label>
                            <Select value={gen.zone} onValueChange={(v) => setGen(prev => ({ ...prev, zone: v as FirewalldZone }))}>
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="public">Public</SelectItem>
                                <SelectItem value="internal">Internal</SelectItem>
                                <SelectItem value="dmz">DMZ</SelectItem>
                                <SelectItem value="work">Work</SelectItem>
                                <SelectItem value="home">Home</SelectItem>
                                <SelectItem value="trusted">Trusted</SelectItem>
                                <SelectItem value="drop">Drop</SelectItem>
                                <SelectItem value="block">Block</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        ) : (
                          <div>
                            <Label className="text-xs text-muted-foreground mb-1.5 block">Direction</Label>
                            <Select value={gen.direction} onValueChange={(v) => setGen(prev => ({ ...prev, direction: v as Direction }))}>
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="inbound">Inbound (INPUT)</SelectItem>
                                <SelectItem value="outbound">Outbound (OUTPUT)</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        )}
                      </div>

                      {/* Row 3: Action & Common Services */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <Label className="text-xs text-muted-foreground mb-1.5 block">Rule Action</Label>
                          <Select value={gen.action} onValueChange={(v) => setGen(prev => ({ ...prev, action: v as RuleAction }))}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="accept">Allow</SelectItem>
                              <SelectItem value="drop">Drop (Silent)</SelectItem>
                              <SelectItem value="reject">Reject (Send Error)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label className="text-xs text-muted-foreground mb-1.5 block">Common Services</Label>
                          <Select value={gen.commonService} onValueChange={handleServiceSelect}>
                            <SelectTrigger>
                              <SelectValue placeholder="Select a service" />
                            </SelectTrigger>
                            <SelectContent>
                              {COMMON_SERVICES.map(s => (
                                <SelectItem key={s.label} value={s.label}>{s.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      {/* Source IP (optional) */}
                      <div>
                        <Label className="text-xs text-muted-foreground mb-1.5 block">Source IP (optional — leave empty for any)</Label>
                        <Input
                          value={gen.sourceIp}
                          onChange={(e) => setGen(prev => ({ ...prev, sourceIp: e.target.value }))}
                          placeholder="e.g. 192.168.1.0/24"
                        />
                      </div>
                    </CardContent>
                  </Card>

                  {/* Tips Card */}
                  <Card className="border-border/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Info className="w-4 h-4 text-primary" />About Firewall Rules
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm text-muted-foreground mb-3">
                        Firewall rules control traffic to and from your system by allowing or blocking specific ports and services.
                      </p>
                      <div className="space-y-1.5">
                        {[
                          "Always specify the most restrictive rule possible for your needs",
                          "Common HTTP ports: 80 (HTTP), 443 (HTTPS)",
                          "Common SSH port: 22",
                          "SMTP mail ports 25, 465, and 587 use TCP (not UDP)",
                          "Consider limiting SSH access by source IP when possible",
                          "Test your rules after applying them to ensure services work as expected",
                        ].map((tip, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <ChevronRight className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
                            <p className="text-xs text-muted-foreground">{tip}</p>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Right: Live Command Preview */}
                <div className="lg:col-span-2">
                  <div className="sticky top-6 space-y-4">
                    <Card className="border-border/50 bg-[hsl(var(--terminal-bg))] overflow-hidden">
                      <CardHeader className="pb-2 border-b border-[hsl(var(--terminal-border))]">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <div className="flex gap-1.5">
                              <div className="w-3 h-3 rounded-full bg-red-500/80" />
                              <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                              <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                            </div>
                            <span className="text-xs font-mono text-[hsl(var(--terminal-text))]/60 ml-2">Generated Commands</span>
                          </div>
                          <div className="flex gap-1">
                            <Button
                              variant="ghost" size="sm"
                              className="h-7 text-xs text-[hsl(var(--terminal-text))] hover:bg-[hsl(var(--terminal-border))]"
                              onClick={copyAllCommands}
                              disabled={commands.length === 0}
                            >
                              {copiedId === "all-cmds" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                            </Button>
                            <Button
                              variant="ghost" size="sm"
                              className="h-7 text-xs text-[hsl(var(--terminal-text))] hover:bg-[hsl(var(--terminal-border))]"
                              onClick={downloadScript}
                              disabled={commands.length === 0}
                            >
                              <Download className="w-3.5 h-3.5" />
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="p-4">
                        {commands.length === 0 ? (
                          <div className="text-center py-8">
                            <Terminal className="w-8 h-8 text-[hsl(var(--terminal-text))]/30 mx-auto mb-2" />
                            <p className="text-sm text-[hsl(var(--terminal-text))]/40 font-mono">Enter a port to generate commands...</p>
                          </div>
                        ) : (
                          <div className="space-y-2 font-mono text-sm">
                            <p className="text-[hsl(var(--terminal-text))]/50 text-xs mb-3"># {gen.system} rules — {new Date().toLocaleDateString()}</p>
                            {commands.map((cmd, i) => (
                              <div key={i} className="group flex items-start gap-2 hover:bg-[hsl(var(--terminal-border))]/30 rounded px-2 py-1.5 -mx-2">
                                <span className="text-primary/60 select-none">$</span>
                                <code className="flex-1 text-[hsl(var(--terminal-text))] break-all">{cmd}</code>
                                <Button
                                  variant="ghost" size="icon"
                                  className="opacity-0 group-hover:opacity-100 h-6 w-6 shrink-0 text-[hsl(var(--terminal-text))] hover:bg-[hsl(var(--terminal-border))]"
                                  onClick={() => copy(cmd, `cmd-${i}`)}
                                >
                                  {copiedId === `cmd-${i}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                                </Button>
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    {/* Quick port buttons */}
                    <Card className="border-border/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-xs font-medium flex items-center gap-2">
                          <Zap className="w-3.5 h-3.5 text-primary" />Quick Ports
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-wrap gap-1.5">
                          {["22", "80", "443", "3306", "5432", "6379", "8080", "53", "25", "3389"].map(port => (
                            <Button
                              key={port}
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs font-mono"
                              onClick={() => setGen(prev => ({ ...prev, port, commonService: "" }))}
                            >
                              {port}
                              <span className="text-muted-foreground ml-1">{WELL_KNOWN_PORTS[port]}</span>
                            </Button>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </div>
            </TabsContent>

            {/* ═══════════════════════════════════════════════ */}
            {/* TAB 2: REVIEW & EXPLANATION                    */}
            {/* ═══════════════════════════════════════════════ */}
            <TabsContent value="review">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Input */}
                <div className="space-y-4">
                  <Card className="border-border/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Eye className="w-5 h-5 text-primary" />
                        Paste Your Firewall Rules
                      </CardTitle>
                      <CardDescription>
                        Paste iptables, UFW, firewalld, or nftables commands below to get a human-readable explanation.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Textarea
                        value={reviewInput}
                        onChange={(e) => setReviewInput(e.target.value)}
                        placeholder={`Paste rules here, e.g.:\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\nufw allow 443/tcp\nfirewall-cmd --zone=public --add-port=3306/tcp --permanent`}
                        className="min-h-[200px] font-mono text-sm"
                      />
                      <div className="flex gap-2 mt-3">
                        <Button
                          variant="outline" size="sm"
                          onClick={() => setReviewInput(
                            `iptables -A INPUT -p tcp --dport 22 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -s 192.168.1.0/24 -j ACCEPT\niptables -A INPUT -p tcp -j DROP`
                          )}
                        >
                          Load iptables Example
                        </Button>
                        <Button
                          variant="outline" size="sm"
                          onClick={() => setReviewInput(
                            `ufw allow 22/tcp\nufw allow 80/tcp\nufw allow 443/tcp\nufw deny 3306/tcp\nufw allow from 10.0.0.0/8 to any port 5432 proto tcp`
                          )}
                        >
                          Load UFW Example
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Summary stats */}
                  {parsedRules.length > 0 && (
                    <div className="grid grid-cols-3 gap-3">
                      <Card className="border-border/50">
                        <CardContent className="p-3 text-center">
                          <p className="text-2xl font-bold text-foreground">{parsedRules.length}</p>
                          <p className="text-xs text-muted-foreground">Total Rules</p>
                        </CardContent>
                      </Card>
                      <Card className="border-border/50">
                        <CardContent className="p-3 text-center">
                          <p className="text-2xl font-bold text-amber-400">{parsedRules.filter(r => r.risk === "warning").length}</p>
                          <p className="text-xs text-muted-foreground">Warnings</p>
                        </CardContent>
                      </Card>
                      <Card className="border-border/50">
                        <CardContent className="p-3 text-center">
                          <p className="text-2xl font-bold text-red-400">{parsedRules.filter(r => r.risk === "danger").length}</p>
                          <p className="text-xs text-muted-foreground">Dangers</p>
                        </CardContent>
                      </Card>
                    </div>
                  )}
                </div>

                {/* Parsed Output */}
                <div className="space-y-3">
                  {parsedRules.length === 0 ? (
                    <Card className="border-border/50">
                      <CardContent className="py-16 text-center">
                        <BookOpen className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
                        <p className="text-muted-foreground">Paste firewall rules on the left to see explanations here</p>
                      </CardContent>
                    </Card>
                  ) : (
                    parsedRules.map((rule, i) => (
                      <Card key={i} className={`border-border/50 overflow-hidden ${rule.risk === "danger" ? "border-red-500/30" : rule.risk === "warning" ? "border-amber-500/30" : ""}`}>
                        <CardContent className="p-4 space-y-3">
                          {/* Original command */}
                          <div className="flex items-start justify-between gap-2">
                            <code className="text-xs font-mono text-muted-foreground bg-muted/50 px-2 py-1 rounded break-all flex-1">{rule.original}</code>
                            <Badge className={`shrink-0 text-[10px] uppercase font-mono ${riskColor(rule.risk)}`}>
                              {rule.risk}
                            </Badge>
                          </div>

                          {/* Human explanation */}
                          <div className="flex items-start gap-2 bg-primary/5 rounded-lg p-3 border border-primary/10">
                            <BookOpen className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                            <p className="text-sm text-foreground">{rule.explanation}</p>
                          </div>

                          {/* Details */}
                          <div className="flex flex-wrap gap-2">
                            <Badge variant="outline" className="text-[10px] font-mono">
                              {rule.action === "ACCEPT" || rule.action === "ALLOW" ? (
                                <ShieldCheck className="w-3 h-3 mr-1 text-emerald-400" />
                              ) : (
                                <ShieldX className="w-3 h-3 mr-1 text-red-400" />
                              )}
                              {rule.action}
                            </Badge>
                            <Badge variant="outline" className="text-[10px] font-mono">{rule.protocol}</Badge>
                            <Badge variant="outline" className="text-[10px] font-mono">
                              Port: {rule.port}{WELL_KNOWN_PORTS[rule.port] ? ` (${WELL_KNOWN_PORTS[rule.port]})` : ""}
                            </Badge>
                            <Badge variant="outline" className="text-[10px] font-mono">From: {rule.source}</Badge>
                          </div>

                          {/* Risk note */}
                          {rule.riskNote && (
                            <div className={`flex items-start gap-2 rounded-lg p-2.5 border text-xs ${
                              rule.risk === "danger"
                                ? "bg-red-500/10 border-red-500/20 text-red-400"
                                : rule.risk === "warning"
                                ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                                : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                            }`}>
                              <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                              <span>{rule.riskNote}</span>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))
                  )}

                  {/* Best practices */}
                  {parsedRules.length > 0 && (
                    <Card className="border-border/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Lock className="w-4 h-4 text-primary" />
                          Best Practices
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        {[
                          "Restrict SSH (port 22) to specific IP ranges instead of allowing from anywhere",
                          "Always have a default DROP policy for INPUT chain",
                          "Keep database ports (3306, 5432, 6379) restricted to application server IPs only",
                          "Enable logging for dropped packets to monitor blocked attempts",
                          "Regularly audit and remove unused rules",
                          "Always test rules in a staging environment before production",
                        ].map((tip, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <ChevronRight className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
                            <p className="text-xs text-muted-foreground">{tip}</p>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* ═══════════════════════════════════════════════ */}
            {/* TAB 3: COMMANDS & DIAGNOSTICS                  */}
            {/* ═══════════════════════════════════════════════ */}
            <TabsContent value="diagnostics">
              <div className="space-y-6">
                {/* Controls */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <Label className="text-xs text-muted-foreground whitespace-nowrap">Firewall System:</Label>
                    <Select value={diagSystem} onValueChange={(v) => setDiagSystem(v as FirewallSystem)}>
                      <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="iptables">IPTables</SelectItem>
                        <SelectItem value="nftables">NFTables</SelectItem>
                        <SelectItem value="ufw">UFW</SelectItem>
                        <SelectItem value="firewalld">FirewallD</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex gap-1.5">
                    {["all", "status", "list", "debug", "save"].map(cat => (
                      <Button
                        key={cat}
                        variant={diagFilter === cat ? "default" : "outline"}
                        size="sm"
                        className="text-xs capitalize"
                        onClick={() => setDiagFilter(cat)}
                      >
                        {cat === "all" ? "All" : cat}
                      </Button>
                    ))}
                  </div>
                </div>

                {/* Commands Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {filteredDiagCmds.map((cmd, i) => (
                    <Card key={i} className="border-border/50 hover:border-primary/30 transition-colors group">
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-start justify-between gap-2">
                          <Badge className={`text-[10px] uppercase font-mono ${categoryColor(cmd.category)}`}>
                            <span className="mr-1">{categoryIcon(cmd.category)}</span>
                            {cmd.category}
                          </Badge>
                          <Button
                            variant="ghost" size="icon"
                            className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={() => copy(cmd.command, `diag-${i}`)}
                          >
                            {copiedId === `diag-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </Button>
                        </div>
                        <div className="bg-[hsl(var(--terminal-bg))] rounded-lg p-3 border border-[hsl(var(--terminal-border))]">
                          <code className="text-sm font-mono text-[hsl(var(--terminal-text))] break-all">
                            <span className="text-primary/60 mr-1">$</span>{cmd.command}
                          </code>
                        </div>
                        <p className="text-xs text-muted-foreground">{cmd.description}</p>
                        {cmd.command.includes("⚠️") || cmd.command.includes("flush") || cmd.command.includes("-F") || cmd.command.includes("reset") || cmd.command.includes("disable") ? (
                          <div className="flex items-center gap-1.5 text-amber-400">
                            <AlertTriangle className="w-3 h-3" />
                            <span className="text-[10px]">Use with caution</span>
                          </div>
                        ) : null}
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Quick reference */}
                <Card className="border-border/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Info className="w-4 h-4 text-primary" />
                      Quick Reference — {diagSystem}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      {diagSystem === "iptables" && (
                        <>
                          <div>
                            <p className="font-medium text-foreground mb-1">Chains</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-primary">INPUT</code> — Incoming traffic to the server</li>
                              <li><code className="text-primary">OUTPUT</code> — Outgoing traffic from the server</li>
                              <li><code className="text-primary">FORWARD</code> — Traffic routed through the server</li>
                            </ul>
                          </div>
                          <div>
                            <p className="font-medium text-foreground mb-1">Targets</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-emerald-400">ACCEPT</code> — Allow the packet</li>
                              <li><code className="text-red-400">DROP</code> — Silently discard the packet</li>
                              <li><code className="text-amber-400">REJECT</code> — Discard and send error response</li>
                              <li><code className="text-primary">LOG</code> — Log the packet to syslog</li>
                            </ul>
                          </div>
                        </>
                      )}
                      {diagSystem === "nftables" && (
                        <>
                          <div>
                            <p className="font-medium text-foreground mb-1">Tables & Chains</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-primary">inet filter</code> — IPv4+IPv6 filtering</li>
                              <li><code className="text-primary">input</code> — Incoming packets</li>
                              <li><code className="text-primary">output</code> — Outgoing packets</li>
                              <li><code className="text-primary">forward</code> — Routed packets</li>
                            </ul>
                          </div>
                          <div>
                            <p className="font-medium text-foreground mb-1">Verdict Statements</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-emerald-400">accept</code> — Allow</li>
                              <li><code className="text-red-400">drop</code> — Silently discard</li>
                              <li><code className="text-amber-400">reject</code> — Discard with ICMP error</li>
                            </ul>
                          </div>
                        </>
                      )}
                      {diagSystem === "ufw" && (
                        <>
                          <div>
                            <p className="font-medium text-foreground mb-1">Basic Commands</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-primary">ufw enable</code> — Activate the firewall</li>
                              <li><code className="text-primary">ufw disable</code> — Deactivate</li>
                              <li><code className="text-primary">ufw default deny incoming</code> — Default deny</li>
                              <li><code className="text-primary">ufw delete [num]</code> — Delete by rule number</li>
                            </ul>
                          </div>
                          <div>
                            <p className="font-medium text-foreground mb-1">Rule Syntax</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-emerald-400">allow</code> — Permit traffic</li>
                              <li><code className="text-red-400">deny</code> — Block traffic</li>
                              <li><code className="text-amber-400">reject</code> — Block with response</li>
                              <li><code className="text-primary">from IP to any port N</code> — Specific source</li>
                            </ul>
                          </div>
                        </>
                      )}
                      {diagSystem === "firewalld" && (
                        <>
                          <div>
                            <p className="font-medium text-foreground mb-1">Zones</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-primary">public</code> — Default zone, untrusted networks</li>
                              <li><code className="text-primary">trusted</code> — All traffic allowed</li>
                              <li><code className="text-primary">dmz</code> — Publicly accessible servers</li>
                              <li><code className="text-primary">drop</code> — Drop all incoming, no reply</li>
                            </ul>
                          </div>
                          <div>
                            <p className="font-medium text-foreground mb-1">Key Flags</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              <li><code className="text-emerald-400">--permanent</code> — Persist across reboots</li>
                              <li><code className="text-primary">--reload</code> — Apply permanent changes</li>
                              <li><code className="text-amber-400">--add-rich-rule</code> — Complex rules</li>
                              <li><code className="text-primary">--runtime-to-permanent</code> — Save current state</li>
                            </ul>
                          </div>
                        </>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </Sidebar>
  );
};

export default FirewallGenerator;
