import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Shield, Copy, CheckCircle2, Download, Info, Terminal, Search,
  ShieldCheck, ShieldX, ShieldAlert, Plus, Trash2, Edit2, Eye,
  RotateCcw, AlertTriangle, Activity, Globe, Lock, Unlock,
  Server, Zap, FileText, ChevronRight, X, Save, Play
} from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table, TableHeader, TableBody, TableHead, TableRow, TableCell
} from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter
} from "@/components/ui/dialog";

// ── Types ──

interface FirewallRule {
  id: string;
  action: "ACCEPT" | "DROP" | "REJECT" | "LOG";
  direction: "INPUT" | "OUTPUT" | "FORWARD";
  protocol: "tcp" | "udp" | "icmp" | "all";
  source: string;
  destination: string;
  port: string;
  rateLimit: string;
  comment: string;
  enabled: boolean;
}

interface LogEntry {
  id: string;
  timestamp: string;
  action: "ALLOW" | "BLOCK" | "LOG";
  source: string;
  destination: string;
  port: string;
  protocol: string;
  info: string;
}

interface InsightEntry {
  ip: string;
  hits: number;
  lastSeen: string;
  threat: "low" | "medium" | "high" | "critical";
  reason: string;
}

// ── Constants ──

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

const QUICK_RULES = [
  { label: "SSH (22)", port: "22", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "HTTP (80)", port: "80", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "HTTPS (443)", port: "443", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "DNS (53)", port: "53", protocol: "udp" as const, action: "ACCEPT" as const },
  { label: "MySQL (3306)", port: "3306", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "PostgreSQL (5432)", port: "5432", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "Redis (6379)", port: "6379", protocol: "tcp" as const, action: "ACCEPT" as const },
  { label: "Webmin (10000)", port: "10000", protocol: "tcp" as const, action: "ACCEPT" as const },
];

// ── Helpers ──

function generateId() {
  return Math.random().toString(36).substring(2, 10);
}

function getPortName(port: string): string {
  return WELL_KNOWN_PORTS[port] || "";
}

function ruleToPlainEnglish(rule: FirewallRule): string {
  const actionWord = rule.action === "ACCEPT" ? "Allow" : rule.action === "DROP" ? "Silently drop" : rule.action === "REJECT" ? "Reject with error" : "Log";
  const protoStr = rule.protocol === "all" ? "all protocols" : rule.protocol.toUpperCase();
  const portName = rule.port ? getPortName(rule.port) : "";
  const portStr = rule.port ? `port ${rule.port}${portName ? ` (${portName})` : ""}` : "all ports";
  const srcStr = rule.source && rule.source !== "0.0.0.0/0" ? `from ${rule.source}` : "from anywhere";
  const dstStr = rule.destination && rule.destination !== "0.0.0.0/0" ? `to ${rule.destination}` : "";
  const rateStr = rule.rateLimit ? ` (rate limited: ${rule.rateLimit})` : "";
  return `${actionWord} ${protoStr} traffic on ${portStr} ${srcStr}${dstStr ? " " + dstStr : ""} [${rule.direction}]${rateStr}`;
}

function ruleToIptables(rule: FirewallRule): string {
  let cmd = `iptables -A ${rule.direction}`;
  if (rule.protocol !== "all") cmd += ` -p ${rule.protocol}`;
  if (rule.source && rule.source !== "0.0.0.0/0") cmd += ` -s ${rule.source}`;
  if (rule.destination && rule.destination !== "0.0.0.0/0") cmd += ` -d ${rule.destination}`;
  if (rule.port && rule.protocol !== "icmp" && rule.protocol !== "all") cmd += ` --dport ${rule.port}`;
  if (rule.rateLimit) cmd += ` -m limit --limit ${rule.rateLimit}`;
  cmd += ` -m conntrack --ctstate NEW`;
  if (rule.comment) cmd += ` -m comment --comment "${rule.comment}"`;
  cmd += ` -j ${rule.action}`;
  return cmd;
}

function ruleToNftables(rule: FirewallRule): string {
  const chain = rule.direction.toLowerCase();
  let cmd = `    `;
  if (rule.source && rule.source !== "0.0.0.0/0") cmd += `ip saddr ${rule.source} `;
  if (rule.destination && rule.destination !== "0.0.0.0/0") cmd += `ip daddr ${rule.destination} `;
  if (rule.protocol !== "all") cmd += `${rule.protocol} `;
  if (rule.port && rule.protocol !== "icmp" && rule.protocol !== "all") cmd += `dport ${rule.port} `;
  if (rule.rateLimit) cmd += `limit rate ${rule.rateLimit} `;
  cmd += `ct state new ${rule.action.toLowerCase()}`;
  if (rule.comment) cmd += ` comment "${rule.comment}"`;
  return cmd;
}

function validateCustomCommand(cmd: string): { valid: boolean; explanation: string; warnings: string[] } {
  const trimmed = cmd.trim();
  const warnings: string[] = [];

  if (!trimmed) return { valid: false, explanation: "Empty command", warnings };

  // Check for dangerous patterns
  if (/rm\s+-rf|mkfs|dd\s+if=|shutdown|reboot|halt|poweroff/i.test(trimmed)) {
    return { valid: false, explanation: "⛔ This command contains dangerous system operations and is blocked.", warnings: ["Destructive command detected"] };
  }

  const isIptables = /^(sudo\s+)?(iptables|ip6tables)\s+/i.test(trimmed);
  const isNft = /^(sudo\s+)?(nft)\s+/i.test(trimmed);
  const isFirewalld = /^(sudo\s+)?(firewall-cmd)\s+/i.test(trimmed);

  if (!isIptables && !isNft && !isFirewalld) {
    return { valid: false, explanation: "Only iptables, nft, or firewall-cmd commands are accepted.", warnings };
  }

  // Check SSH lockout risk
  if (/DROP.*--dport\s+22\b/i.test(trimmed) || /REJECT.*--dport\s+22\b/i.test(trimmed) || /dport\s+22\s+drop/i.test(trimmed)) {
    warnings.push("⚠️ WARNING: This rule may block SSH access! You could lock yourself out.");
  }

  // Check flush all
  if (/-F\b/.test(trimmed) && !/-A\b/.test(trimmed)) {
    warnings.push("⚠️ This flushes all rules. Make sure you re-add essential rules after.");
  }

  // Build explanation
  let explanation = "";
  if (isIptables) {
    const actionMatch = trimmed.match(/-j\s+(\w+)/);
    const portMatch = trimmed.match(/--dport\s+(\d+)/);
    const srcMatch = trimmed.match(/-s\s+([\d./]+)/);
    const chainMatch = trimmed.match(/-A\s+(\w+)/);
    const action = actionMatch?.[1] || "unknown";
    const port = portMatch?.[1] || "all";
    const src = srcMatch?.[1] || "any";
    const chain = chainMatch?.[1] || "unknown";
    const portName = getPortName(port);
    explanation = `This ${action === "ACCEPT" ? "allows" : action === "DROP" ? "silently drops" : action === "REJECT" ? "rejects" : action.toLowerCase() + "s"} traffic on ${chain} chain, port ${port}${portName ? ` (${portName})` : ""} from ${src}.`;
  } else if (isFirewalld) {
    if (/--add-port/i.test(trimmed)) {
      const portMatch = trimmed.match(/--add-port=([\d/\w]+)/);
      explanation = `Opens port ${portMatch?.[1] || "unknown"} in the firewall zone.`;
    } else if (/--add-service/i.test(trimmed)) {
      const svcMatch = trimmed.match(/--add-service=(\w+)/);
      explanation = `Allows the ${svcMatch?.[1] || "unknown"} service through the firewall.`;
    } else {
      explanation = "Firewalld configuration command.";
    }
  } else {
    explanation = "nftables rule modification.";
  }

  return { valid: true, explanation, warnings };
}

// ── Sample Data Generators ──

function generateSampleLogs(): LogEntry[] {
  const now = Date.now();
  const actions: LogEntry["action"][] = ["ALLOW", "BLOCK", "BLOCK", "ALLOW", "BLOCK", "LOG"];
  const ips = [
    "192.168.1.100", "10.0.0.5", "203.0.113.42", "198.51.100.77",
    "172.16.0.15", "45.33.32.156", "185.220.101.42", "91.240.118.172",
    "62.210.105.116", "23.129.64.130"
  ];
  const ports = ["22", "80", "443", "3306", "8080", "25", "53", "5432", "23", "445"];
  const protos = ["tcp", "udp", "tcp", "tcp", "tcp", "tcp", "udp", "tcp", "tcp", "tcp"];
  const infos = [
    "SSH connection attempt", "HTTP request", "HTTPS connection", "MySQL query attempt",
    "Web proxy access", "SMTP relay attempt", "DNS query", "PostgreSQL connection",
    "Telnet scan detected", "SMB/CIFS probe"
  ];

  return Array.from({ length: 50 }, (_, i) => ({
    id: generateId(),
    timestamp: new Date(now - Math.random() * 3600000).toISOString(),
    action: actions[Math.floor(Math.random() * actions.length)],
    source: ips[Math.floor(Math.random() * ips.length)],
    destination: "10.0.0.1",
    port: ports[i % ports.length],
    protocol: protos[i % protos.length],
    info: infos[i % infos.length],
  })).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

function generateSampleInsights(logs: LogEntry[]): InsightEntry[] {
  const ipMap = new Map<string, { hits: number; lastSeen: string; blocked: number }>();
  for (const log of logs) {
    const existing = ipMap.get(log.source) || { hits: 0, lastSeen: log.timestamp, blocked: 0 };
    existing.hits++;
    if (log.action === "BLOCK") existing.blocked++;
    if (new Date(log.timestamp) > new Date(existing.lastSeen)) existing.lastSeen = log.timestamp;
    ipMap.set(log.source, existing);
  }

  return Array.from(ipMap.entries()).map(([ip, data]) => {
    const blockRate = data.blocked / data.hits;
    let threat: InsightEntry["threat"] = "low";
    let reason = "Normal traffic pattern";
    if (blockRate > 0.8 && data.hits > 5) { threat = "critical"; reason = "Repeated blocked attempts — possible brute-force or port scan"; }
    else if (blockRate > 0.5) { threat = "high"; reason = "High block rate — suspicious activity"; }
    else if (data.hits > 10) { threat = "medium"; reason = "High volume traffic"; }
    return { ip, hits: data.hits, lastSeen: data.lastSeen, threat, reason };
  }).sort((a, b) => b.hits - a.hits);
}

// ── Component ──

const FirewallGenerator = () => {
  const [activeTab, setActiveTab] = useState("rules");
  const [firewallType, setFirewallType] = useState<"iptables" | "nftables">("iptables");

  // Rules state
  const [rules, setRules] = useState<FirewallRule[]>([
    { id: generateId(), action: "ACCEPT", direction: "INPUT", protocol: "tcp", source: "0.0.0.0/0", destination: "0.0.0.0/0", port: "22", rateLimit: "", comment: "Allow SSH", enabled: true },
    { id: generateId(), action: "ACCEPT", direction: "INPUT", protocol: "tcp", source: "0.0.0.0/0", destination: "0.0.0.0/0", port: "80", rateLimit: "", comment: "Allow HTTP", enabled: true },
    { id: generateId(), action: "ACCEPT", direction: "INPUT", protocol: "tcp", source: "0.0.0.0/0", destination: "0.0.0.0/0", port: "443", rateLimit: "", comment: "Allow HTTPS", enabled: true },
  ]);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [ruleHistory, setRuleHistory] = useState<FirewallRule[][]>([]);

  // New rule form
  const emptyRule: FirewallRule = {
    id: "", action: "ACCEPT", direction: "INPUT", protocol: "tcp",
    source: "0.0.0.0/0", destination: "0.0.0.0/0", port: "", rateLimit: "", comment: "", enabled: true,
  };
  const [newRule, setNewRule] = useState<FirewallRule>({ ...emptyRule, id: generateId() });

  // Logs
  const [logs] = useState<LogEntry[]>(() => generateSampleLogs());
  const [logFilter, setLogFilter] = useState<"all" | "ALLOW" | "BLOCK" | "LOG">("all");
  const [logSearch, setLogSearch] = useState("");

  // Insights
  const insights = useMemo(() => generateSampleInsights(logs), [logs]);

  // Custom rules
  const [customCmd, setCustomCmd] = useState("");
  const [customValidation, setCustomValidation] = useState<{ valid: boolean; explanation: string; warnings: string[] } | null>(null);

  // Copied state
  const [copied, setCopied] = useState(false);

  // ── Rule CRUD ──

  const saveHistory = () => setRuleHistory((prev) => [...prev.slice(-9), rules.map((r) => ({ ...r }))]);

  const addRule = () => {
    saveHistory();
    setRules((prev) => [...prev, { ...newRule, id: generateId() }]);
    setNewRule({ ...emptyRule, id: generateId() });
    setShowAddDialog(false);
    toast.success("Rule added");
  };

  const updateRule = () => {
    if (!editingRule) return;
    saveHistory();
    setRules((prev) => prev.map((r) => r.id === editingRule.id ? editingRule : r));
    setEditingRule(null);
    toast.success("Rule updated");
  };

  const deleteRule = (id: string) => {
    const rule = rules.find((r) => r.id === id);
    if (rule?.port === "22" && rule.action === "ACCEPT") {
      toast.error("⚠️ Cannot delete SSH rule — this would lock you out!");
      return;
    }
    saveHistory();
    setRules((prev) => prev.filter((r) => r.id !== id));
    toast.success("Rule deleted");
  };

  const toggleRule = (id: string) => {
    saveHistory();
    setRules((prev) => prev.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const rollback = () => {
    if (ruleHistory.length === 0) { toast.error("No history to rollback"); return; }
    const prev = ruleHistory[ruleHistory.length - 1];
    setRuleHistory((h) => h.slice(0, -1));
    setRules(prev);
    toast.success("Rolled back to previous state");
  };

  const addQuickRule = (qr: typeof QUICK_RULES[number]) => {
    if (rules.some((r) => r.port === qr.port && r.action === qr.action && r.enabled)) {
      toast.info(`Rule for ${qr.label} already exists`);
      return;
    }
    saveHistory();
    setRules((prev) => [...prev, {
      id: generateId(), action: qr.action, direction: "INPUT" as const,
      protocol: qr.protocol, source: "0.0.0.0/0", destination: "0.0.0.0/0",
      port: qr.port, rateLimit: "", comment: `Allow ${qr.label}`, enabled: true,
    }]);
    toast.success(`Added ${qr.label} rule`);
  };

  // ── Script Generation ──

  const generateScript = (): string => {
    const enabledRules = rules.filter((r) => r.enabled);

    if (firewallType === "iptables") {
      let s = `#!/bin/bash
# ═══════════════════════════════════════════════
# Firewall Rules — Generated by SysToolKit
# Type: iptables | Date: ${new Date().toISOString().split("T")[0]}
# ═══════════════════════════════════════════════

set -euo pipefail

echo "🔒 Applying firewall rules..."

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# ── Custom Rules ──
`;
      for (const rule of enabledRules) {
        s += `\n# ${rule.comment || ruleToPlainEnglish(rule)}\n${ruleToIptables(rule)}\n`;
      }
      s += `
# Log dropped
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables_DROP: " --log-level 7

# Save
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
echo "✅ Firewall rules applied successfully!"
`;
      return s;
    }

    // nftables
    let s = `#!/usr/sbin/nft -f
# ═══════════════════════════════════════════════
# Firewall Rules — Generated by SysToolKit
# Type: nftables | Date: ${new Date().toISOString().split("T")[0]}
# ═══════════════════════════════════════════════

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Loopback
    iif lo accept

    # Established
    ct state established,related accept

    # Drop invalid
    ct state invalid drop

    # ── Custom Rules ──
`;
    for (const rule of enabledRules) {
      s += `\n    # ${rule.comment || ruleToPlainEnglish(rule)}\n${ruleToNftables(rule)}\n`;
    }
    s += `
    # Log dropped
    limit rate 5/minute log prefix "nft_DROP: "
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
`;
    return s;
  };

  const script = useMemo(() => generateScript(), [rules, firewallType]);

  const copyScript = () => {
    navigator.clipboard.writeText(script);
    setCopied(true);
    toast.success("Copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadScript = () => {
    const blob = new Blob([script], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = firewallType === "iptables" ? "firewall.sh" : "firewall.nft";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Downloaded!");
  };

  // ── Filtered logs ──
  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (logFilter !== "all" && l.action !== logFilter) return false;
      if (logSearch && !l.source.includes(logSearch) && !l.port.includes(logSearch) && !l.info.toLowerCase().includes(logSearch.toLowerCase())) return false;
      return true;
    });
  }, [logs, logFilter, logSearch]);

  // ── Stats ──
  const allowedCount = logs.filter((l) => l.action === "ALLOW").length;
  const blockedCount = logs.filter((l) => l.action === "BLOCK").length;
  const criticalIPs = insights.filter((i) => i.threat === "critical" || i.threat === "high").length;

  // ── Verdict badge helper ──
  const threatBadge = (t: InsightEntry["threat"]) => {
    const map = {
      low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
      medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
      high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
      critical: "bg-red-500/15 text-red-400 border-red-500/30",
    };
    return <Badge className={`${map[t]} text-[10px] uppercase tracking-wider font-mono`}>{t}</Badge>;
  };

  const actionBadge = (a: string) => {
    if (a === "ALLOW" || a === "ACCEPT") return <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] uppercase font-mono">{a}</Badge>;
    if (a === "BLOCK" || a === "DROP" || a === "REJECT") return <Badge className="bg-red-500/15 text-red-400 border-red-500/30 text-[10px] uppercase font-mono">{a}</Badge>;
    return <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/30 text-[10px] uppercase font-mono">{a}</Badge>;
  };

  // ── Rule Form Component ──
  const RuleForm = ({ rule, onChange, onSave, onCancel, title }: {
    rule: FirewallRule; onChange: (r: FirewallRule) => void; onSave: () => void; onCancel: () => void; title: string;
  }) => (
    <Dialog open onOpenChange={onCancel}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Shield className="w-5 h-5 text-primary" />{title}</DialogTitle>
          <DialogDescription>Configure the firewall rule parameters below.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Action</Label>
              <Select value={rule.action} onValueChange={(v) => onChange({ ...rule, action: v as FirewallRule["action"] })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ACCEPT">✅ ACCEPT</SelectItem>
                  <SelectItem value="DROP">🚫 DROP</SelectItem>
                  <SelectItem value="REJECT">❌ REJECT</SelectItem>
                  <SelectItem value="LOG">📝 LOG</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Direction</Label>
              <Select value={rule.direction} onValueChange={(v) => onChange({ ...rule, direction: v as FirewallRule["direction"] })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="INPUT">INPUT</SelectItem>
                  <SelectItem value="OUTPUT">OUTPUT</SelectItem>
                  <SelectItem value="FORWARD">FORWARD</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Protocol</Label>
              <Select value={rule.protocol} onValueChange={(v) => onChange({ ...rule, protocol: v as FirewallRule["protocol"] })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                  <SelectItem value="all">ALL</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Port</Label>
              <Input value={rule.port} onChange={(e) => onChange({ ...rule, port: e.target.value })} placeholder="e.g. 80, 443, 8080:8090" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Source IP</Label>
              <Input value={rule.source} onChange={(e) => onChange({ ...rule, source: e.target.value })} placeholder="0.0.0.0/0" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Destination IP</Label>
              <Input value={rule.destination} onChange={(e) => onChange({ ...rule, destination: e.target.value })} placeholder="0.0.0.0/0" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Rate Limit</Label>
              <Input value={rule.rateLimit} onChange={(e) => onChange({ ...rule, rateLimit: e.target.value })} placeholder="e.g. 25/minute" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1 block">Comment</Label>
              <Input value={rule.comment} onChange={(e) => onChange({ ...rule, comment: e.target.value })} placeholder="Rule description" />
            </div>
          </div>
          {/* Plain English preview */}
          <div className="bg-muted/50 rounded-lg p-3 border border-border">
            <p className="text-xs text-muted-foreground mb-1 font-medium">Plain English</p>
            <p className="text-sm text-foreground">{ruleToPlainEnglish(rule)}</p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button onClick={onSave}><Save className="w-4 h-4 mr-1" />Save Rule</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-6 max-w-7xl">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20">
                <Shield className="w-7 h-7 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground">Firewall Manager</h1>
                <p className="text-sm text-muted-foreground">Advanced Linux firewall management & monitoring</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Select value={firewallType} onValueChange={(v) => setFirewallType(v as "iptables" | "nftables")}>
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="iptables">iptables</SelectItem>
                  <SelectItem value="nftables">nftables</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={rollback} disabled={ruleHistory.length === 0}>
                <RotateCcw className="w-4 h-4 mr-1" />Rollback
              </Button>
            </div>
          </div>

          {/* Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10"><Shield className="w-5 h-5 text-primary" /></div>
                <div><p className="text-2xl font-bold text-foreground">{rules.filter((r) => r.enabled).length}</p><p className="text-xs text-muted-foreground">Active Rules</p></div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10"><ShieldCheck className="w-5 h-5 text-emerald-500" /></div>
                <div><p className="text-2xl font-bold text-foreground">{allowedCount}</p><p className="text-xs text-muted-foreground">Allowed</p></div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/10"><ShieldX className="w-5 h-5 text-red-500" /></div>
                <div><p className="text-2xl font-bold text-foreground">{blockedCount}</p><p className="text-xs text-muted-foreground">Blocked</p></div>
              </CardContent>
            </Card>
            <Card className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-amber-500/10"><AlertTriangle className="w-5 h-5 text-amber-500" /></div>
                <div><p className="text-2xl font-bold text-foreground">{criticalIPs}</p><p className="text-xs text-muted-foreground">Threats</p></div>
              </CardContent>
            </Card>
          </div>

          {/* Main Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="mb-4 w-full justify-start">
              <TabsTrigger value="rules" className="gap-1.5"><Shield className="w-4 h-4" />Rules</TabsTrigger>
              <TabsTrigger value="logs" className="gap-1.5"><FileText className="w-4 h-4" />Logs</TabsTrigger>
              <TabsTrigger value="insights" className="gap-1.5"><Activity className="w-4 h-4" />Insights</TabsTrigger>
              <TabsTrigger value="custom" className="gap-1.5"><Terminal className="w-4 h-4" />Custom Rules</TabsTrigger>
              <TabsTrigger value="script" className="gap-1.5"><FileText className="w-4 h-4" />Generated Script</TabsTrigger>
            </TabsList>

            {/* ═══ RULES TAB ═══ */}
            <TabsContent value="rules">
              {/* Quick Add */}
              <Card className="mb-4 border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2"><Zap className="w-4 h-4 text-primary" />Quick Add Common Rules</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {QUICK_RULES.map((qr) => (
                      <Button key={qr.port} variant="outline" size="sm" className="text-xs" onClick={() => addQuickRule(qr)}>
                        <Plus className="w-3 h-3 mr-1" />{qr.label}
                      </Button>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Rules Table */}
              <Card className="border-border/50">
                <CardHeader className="pb-3 flex flex-row items-center justify-between">
                  <CardTitle className="text-sm font-medium">Firewall Rules</CardTitle>
                  <div className="flex gap-2">
                    <Button size="sm" onClick={() => { setNewRule({ ...emptyRule, id: generateId() }); setShowAddDialog(true); }}>
                      <Plus className="w-4 h-4 mr-1" />Add Rule
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setShowPreview(true)}>
                      <Eye className="w-4 h-4 mr-1" />Preview
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-12">On</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Chain</TableHead>
                        <TableHead>Proto</TableHead>
                        <TableHead>Port</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead className="hidden md:table-cell">Rate Limit</TableHead>
                        <TableHead className="hidden lg:table-cell">Description</TableHead>
                        <TableHead className="w-20">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rules.map((rule) => (
                        <TableRow key={rule.id} className={!rule.enabled ? "opacity-40" : ""}>
                          <TableCell>
                            <Switch checked={rule.enabled} onCheckedChange={() => toggleRule(rule.id)} />
                          </TableCell>
                          <TableCell>{actionBadge(rule.action)}</TableCell>
                          <TableCell className="font-mono text-xs">{rule.direction}</TableCell>
                          <TableCell className="font-mono text-xs uppercase">{rule.protocol}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {rule.port || "*"}
                            {rule.port && getPortName(rule.port) && (
                              <span className="text-muted-foreground ml-1">({getPortName(rule.port)})</span>
                            )}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{rule.source === "0.0.0.0/0" ? "any" : rule.source}</TableCell>
                          <TableCell className="hidden md:table-cell font-mono text-xs">{rule.rateLimit || "—"}</TableCell>
                          <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">{rule.comment}</TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setEditingRule({ ...rule })}>
                                <Edit2 className="w-3 h-3" />
                              </Button>
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => deleteRule(rule.id)}>
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                      {rules.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                            No rules configured. Add one above or use quick-add.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>

              {/* SSH Safety Warning */}
              <div className="mt-3 flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                <p className="text-xs text-amber-600 dark:text-amber-400">
                  <strong>Safety:</strong> The SSH rule (port 22) cannot be deleted to prevent lockout. Always test rules with <code className="bg-muted px-1 rounded">iptables -L -n -v</code> after applying.
                </p>
              </div>
            </TabsContent>

            {/* ═══ LOGS TAB ═══ */}
            <TabsContent value="logs">
              <Card className="border-border/50">
                <CardHeader className="pb-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2"><FileText className="w-4 h-4 text-primary" />Traffic Logs</CardTitle>
                    <div className="flex gap-2">
                      <div className="relative">
                        <Search className="w-4 h-4 absolute left-2.5 top-2.5 text-muted-foreground" />
                        <Input className="pl-8 h-9 w-48" placeholder="Search IP, port..." value={logSearch} onChange={(e) => setLogSearch(e.target.value)} />
                      </div>
                      <Select value={logFilter} onValueChange={(v) => setLogFilter(v as typeof logFilter)}>
                        <SelectTrigger className="w-28 h-9"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All</SelectItem>
                          <SelectItem value="ALLOW">Allowed</SelectItem>
                          <SelectItem value="BLOCK">Blocked</SelectItem>
                          <SelectItem value="LOG">Logged</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="max-h-[500px] overflow-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Time</TableHead>
                          <TableHead>Action</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Port</TableHead>
                          <TableHead>Proto</TableHead>
                          <TableHead>Info</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredLogs.map((log) => (
                          <TableRow key={log.id}>
                            <TableCell className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </TableCell>
                            <TableCell>{actionBadge(log.action)}</TableCell>
                            <TableCell className="font-mono text-xs">{log.source}</TableCell>
                            <TableCell className="font-mono text-xs">
                              {log.port}
                              {getPortName(log.port) && <span className="text-muted-foreground ml-1">({getPortName(log.port)})</span>}
                            </TableCell>
                            <TableCell className="font-mono text-xs uppercase">{log.protocol}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{log.info}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>
              <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                <Info className="w-3 h-3" /> Showing simulated log data. On a real server, pipe <code className="bg-muted px-1 rounded">journalctl -k --grep="iptables"</code> for live logs.
              </p>
            </TabsContent>

            {/* ═══ INSIGHTS TAB ═══ */}
            <TabsContent value="insights">
              <Card className="border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2"><Activity className="w-4 h-4 text-primary" />IP Activity & Threat Analysis</CardTitle>
                  <CardDescription className="text-xs">IPs ranked by activity with threat assessment based on block patterns.</CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Hits</TableHead>
                        <TableHead>Threat</TableHead>
                        <TableHead>Last Seen</TableHead>
                        <TableHead>Assessment</TableHead>
                        <TableHead className="w-24">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {insights.map((insight) => (
                        <TableRow key={insight.ip}>
                          <TableCell className="font-mono text-sm">{insight.ip}</TableCell>
                          <TableCell className="font-mono">{insight.hits}</TableCell>
                          <TableCell>{threatBadge(insight.threat)}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{new Date(insight.lastSeen).toLocaleTimeString()}</TableCell>
                          <TableCell className="text-xs text-muted-foreground max-w-[200px]">{insight.reason}</TableCell>
                          <TableCell>
                            {(insight.threat === "high" || insight.threat === "critical") && (
                              <Button variant="destructive" size="sm" className="text-xs h-7" onClick={() => {
                                saveHistory();
                                setRules((prev) => [...prev, {
                                  id: generateId(), action: "DROP", direction: "INPUT" as const,
                                  protocol: "all" as const, source: insight.ip, destination: "0.0.0.0/0",
                                  port: "", rateLimit: "", comment: `Block suspicious IP ${insight.ip}`, enabled: true,
                                }]);
                                toast.success(`Blocked ${insight.ip}`);
                              }}>
                                <Lock className="w-3 h-3 mr-1" />Block
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            {/* ═══ CUSTOM RULES TAB ═══ */}
            <TabsContent value="custom">
              <div className="grid gap-4 lg:grid-cols-2">
                <Card className="border-border/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2"><Terminal className="w-4 h-4 text-primary" />Custom Command</CardTitle>
                    <CardDescription className="text-xs">Enter an iptables, nft, or firewall-cmd command. It will be validated and explained.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Textarea
                      className="font-mono text-sm min-h-[120px] bg-[hsl(var(--terminal-bg))] text-[hsl(var(--terminal-text))] border-[hsl(var(--terminal-border))]"
                      placeholder="iptables -A INPUT -p tcp --dport 8080 -j ACCEPT"
                      value={customCmd}
                      onChange={(e) => { setCustomCmd(e.target.value); setCustomValidation(null); }}
                    />
                    <Button className="mt-3" onClick={() => setCustomValidation(validateCustomCommand(customCmd))}>
                      <Play className="w-4 h-4 mr-1" />Validate & Explain
                    </Button>
                  </CardContent>
                </Card>

                <Card className="border-border/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">Validation Result</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {!customValidation ? (
                      <p className="text-sm text-muted-foreground">Enter a command and click validate to see results.</p>
                    ) : (
                      <div className="space-y-3">
                        <div className="flex items-center gap-2">
                          {customValidation.valid ? (
                            <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30">✅ Valid</Badge>
                          ) : (
                            <Badge className="bg-red-500/15 text-red-400 border-red-500/30">❌ Invalid</Badge>
                          )}
                        </div>
                        <div className="bg-muted/50 rounded-lg p-3 border border-border">
                          <p className="text-xs text-muted-foreground mb-1 font-medium">Explanation</p>
                          <p className="text-sm">{customValidation.explanation}</p>
                        </div>
                        {customValidation.warnings.map((w, i) => (
                          <div key={i} className="flex items-start gap-2 p-2 rounded bg-amber-500/10 border border-amber-500/20">
                            <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                            <p className="text-xs text-amber-600 dark:text-amber-400">{w}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Common commands reference */}
              <Card className="mt-4 border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2"><Info className="w-4 h-4 text-primary" />Common Commands Reference</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {[
                      { cmd: "iptables -L -n -v", desc: "List all rules with verbose output" },
                      { cmd: "iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT", desc: "Allow entire subnet" },
                      { cmd: "iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT", desc: "Rate-limit HTTP" },
                      { cmd: "iptables -A INPUT -p tcp --dport 22 -s 10.0.0.5 -j ACCEPT", desc: "Allow SSH from specific IP" },
                      { cmd: "firewall-cmd --add-port=8080/tcp --permanent", desc: "Open port 8080 (firewalld)" },
                      { cmd: "firewall-cmd --add-service=http --permanent", desc: "Allow HTTP service (firewalld)" },
                    ].map((item, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-muted/50 border border-border cursor-pointer hover:bg-muted/80 transition-colors"
                        onClick={() => { setCustomCmd(item.cmd); setCustomValidation(null); toast.info("Command loaded — click Validate"); }}>
                        <code className="text-xs font-mono text-primary block mb-1">{item.cmd}</code>
                        <p className="text-xs text-muted-foreground">{item.desc}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* ═══ GENERATED SCRIPT TAB ═══ */}
            <TabsContent value="script">
              <Card className="border-border/50">
                <CardHeader className="pb-3 flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-sm font-medium flex items-center gap-2"><FileText className="w-4 h-4 text-primary" />Generated {firewallType} Script</CardTitle>
                    <CardDescription className="text-xs">{rules.filter((r) => r.enabled).length} rules configured • Ready to deploy</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={copyScript}>
                      {copied ? <CheckCircle2 className="w-4 h-4 mr-1" /> : <Copy className="w-4 h-4 mr-1" />}
                      {copied ? "Copied" : "Copy"}
                    </Button>
                    <Button size="sm" onClick={downloadScript}>
                      <Download className="w-4 h-4 mr-1" />Download
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <pre className="bg-[hsl(var(--terminal-bg))] text-[hsl(var(--terminal-text))] p-4 rounded-lg border border-[hsl(var(--terminal-border))] overflow-auto max-h-[500px] text-xs font-mono leading-relaxed whitespace-pre">
                    {script}
                  </pre>
                </CardContent>
              </Card>

              {/* Installation steps */}
              <Card className="mt-4 border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2"><Server className="w-4 h-4 text-primary" />Installation Steps</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {(firewallType === "iptables" ? [
                      { step: "1", cmd: "# Upload the script to your server", desc: "scp firewall.sh root@yourserver:/root/" },
                      { step: "2", cmd: "# Make executable", desc: "chmod +x /root/firewall.sh" },
                      { step: "3", cmd: "# Run the script", desc: "bash /root/firewall.sh" },
                      { step: "4", cmd: "# Verify rules", desc: "iptables -L -n -v" },
                      { step: "5", cmd: "# Persist on Ubuntu/Debian", desc: "apt install iptables-persistent && netfilter-persistent save" },
                    ] : [
                      { step: "1", cmd: "# Upload the script", desc: "scp firewall.nft root@yourserver:/etc/nftables.conf" },
                      { step: "2", cmd: "# Apply rules", desc: "nft -f /etc/nftables.conf" },
                      { step: "3", cmd: "# Verify", desc: "nft list ruleset" },
                      { step: "4", cmd: "# Enable on boot", desc: "systemctl enable nftables" },
                    ]).map((item) => (
                      <div key={item.step} className="flex items-start gap-3 p-2 rounded-lg hover:bg-muted/50">
                        <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/10 text-primary text-xs font-bold shrink-0">{item.step}</span>
                        <div>
                          <p className="text-xs text-muted-foreground">{item.cmd}</p>
                          <code className="text-xs font-mono text-foreground">{item.desc}</code>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* ── Dialogs ── */}
      {showAddDialog && (
        <RuleForm
          rule={newRule}
          onChange={setNewRule}
          onSave={addRule}
          onCancel={() => setShowAddDialog(false)}
          title="Add Firewall Rule"
        />
      )}

      {editingRule && (
        <RuleForm
          rule={editingRule}
          onChange={setEditingRule}
          onSave={updateRule}
          onCancel={() => setEditingRule(false as any)}
          title="Edit Firewall Rule"
        />
      )}

      {/* Preview Dialog */}
      <Dialog open={showPreview} onOpenChange={setShowPreview}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Eye className="w-5 h-5 text-primary" />Rule Preview — What Changes</DialogTitle>
            <DialogDescription>Review all active rules before applying to your server.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            {rules.filter((r) => r.enabled).map((rule, i) => (
              <div key={rule.id} className="flex items-start gap-2 p-2.5 rounded-lg bg-muted/50 border border-border">
                <span className="text-xs text-muted-foreground font-mono w-5 shrink-0">{i + 1}.</span>
                <div>
                  <p className="text-sm text-foreground">{ruleToPlainEnglish(rule)}</p>
                  <code className="text-xs font-mono text-muted-foreground mt-1 block">
                    {firewallType === "iptables" ? ruleToIptables(rule) : ruleToNftables(rule)}
                  </code>
                </div>
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowPreview(false)}>Close</Button>
            <Button onClick={() => { setShowPreview(false); setActiveTab("script"); }}>
              <FileText className="w-4 h-4 mr-1" />View Full Script
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Sidebar>
  );
};

export default FirewallGenerator;
