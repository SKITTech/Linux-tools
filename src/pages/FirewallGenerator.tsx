import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Shield, Copy, CheckCircle2, Download, Network, Activity, Wifi, Globe } from "lucide-react";
import { toast } from "sonner";
import { ToolNav } from "@/components/ToolNav";

const FirewallGenerator = () => {
  const [firewallType, setFirewallType] = useState("iptables");
  const [allowSSH, setAllowSSH] = useState(true);
  const [allowHTTP, setAllowHTTP] = useState(false);
  const [allowHTTPS, setAllowHTTPS] = useState(false);
  const [allowDNS, setAllowDNS] = useState(false);
  const [allowMySQL, setAllowMySQL] = useState(false);
  const [allowPostgreSQL, setAllowPostgreSQL] = useState(false);
  const [dropInvalid, setDropInvalid] = useState(true);
  const [logDropped, setLogDropped] = useState(true);
  const [result, setResult] = useState("");
  const [copied, setCopied] = useState(false);

  const generateIPTablesRules = (): string => {
    let rules = `#!/bin/bash
# Generated iptables firewall rules
# Run as root: bash firewall.sh

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
`;

    if (dropInvalid) {
      rules += "\n# Drop invalid packets\niptables -A INPUT -m conntrack --ctstate INVALID -j DROP\n";
    }

    if (allowSSH) {
      rules += "\n# Allow SSH (port 22)\niptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT\n";
    }

    if (allowHTTP) {
      rules += "\n# Allow HTTP (port 80)\niptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT\n";
    }

    if (allowHTTPS) {
      rules += "\n# Allow HTTPS (port 443)\niptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT\n";
    }

    if (allowDNS) {
      rules += "\n# Allow DNS (port 53)\niptables -A INPUT -p udp --dport 53 -j ACCEPT\niptables -A INPUT -p tcp --dport 53 -j ACCEPT\n";
    }

    if (allowMySQL) {
      rules += "\n# Allow MySQL (port 3306)\niptables -A INPUT -p tcp --dport 3306 -m conntrack --ctstate NEW -j ACCEPT\n";
    }

    if (allowPostgreSQL) {
      rules += "\n# Allow PostgreSQL (port 5432)\niptables -A INPUT -p tcp --dport 5432 -m conntrack --ctstate NEW -j ACCEPT\n";
    }

    if (logDropped) {
      rules += "\n# Log dropped packets\niptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix \"iptables_INPUT_denied: \" --log-level 7\n";
    }

    rules += "\n# Save rules\niptables-save > /etc/iptables/rules.v4\n\necho \"Firewall rules applied successfully!\"\n";

    return rules;
  };

  const generateNFTablesRules = (): string => {
    let rules = `#!/usr/sbin/nft -f
# Generated nftables firewall rules
# Run as root: nft -f firewall.nft

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Allow loopback
    iif lo accept

    # Allow established connections
    ct state established,related accept
`;

    if (dropInvalid) {
      rules += "\n    # Drop invalid packets\n    ct state invalid drop\n";
    }

    if (allowSSH) {
      rules += "\n    # Allow SSH\n    tcp dport 22 ct state new accept\n";
    }

    if (allowHTTP) {
      rules += "\n    # Allow HTTP\n    tcp dport 80 ct state new accept\n";
    }

    if (allowHTTPS) {
      rules += "\n    # Allow HTTPS\n    tcp dport 443 ct state new accept\n";
    }

    if (allowDNS) {
      rules += "\n    # Allow DNS\n    udp dport 53 accept\n    tcp dport 53 accept\n";
    }

    if (allowMySQL) {
      rules += "\n    # Allow MySQL\n    tcp dport 3306 ct state new accept\n";
    }

    if (allowPostgreSQL) {
      rules += "\n    # Allow PostgreSQL\n    tcp dport 5432 ct state new accept\n";
    }

    if (logDropped) {
      rules += "\n    # Log dropped packets\n    limit rate 5/minute log prefix \"nftables_INPUT_denied: \"\n";
    }

    rules += `  }

  chain forward {
    type filter hook forward priority 0; policy drop;
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
`;

    return rules;
  };

  const generateFirewallRules = () => {
    const rules = firewallType === "iptables" ? generateIPTablesRules() : generateNFTablesRules();
    setResult(rules);
    toast.success("Firewall rules generated successfully!");
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    setCopied(true);
    toast.success("Copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadRules = () => {
    const blob = new Blob([result], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = firewallType === "iptables" ? "firewall.sh" : "firewall.nft";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Firewall rules downloaded!");
  };

  const navItems = [
    { to: "/", icon: Activity, label: "Bridge Generator" },
    { to: "/subnet-calculator", icon: Network, label: "Subnet Calculator" },
    { to: "/network-diagnostics", icon: Wifi, label: "Network Diagnostics" },
    { to: "/ipv6-converter", icon: Globe, label: "IPv6 Converter" },
    { to: "/firewall-generator", icon: Shield, label: "Firewall Generator" },
    { to: "/log-analyzer", icon: Activity, label: "Log Analyzer" },
    { to: "/security-audit", icon: Activity, label: "Security Audit" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
      <div className="container mx-auto px-4 py-8">
        <ToolNav items={navItems} />

        <div className="text-center my-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-10 h-10 text-primary" />
            <h1 className="text-4xl font-bold text-foreground">Firewall Rule Generator</h1>
          </div>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Generate iptables or nftables firewall rules with common security configurations
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Firewall Configuration
              </CardTitle>
              <CardDescription>Select firewall type and allowed services</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <Label className="text-foreground mb-2 block">
                  Firewall Type <span className="text-destructive">*</span>
                </Label>
                <Select value={firewallType} onValueChange={setFirewallType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="iptables">iptables (Legacy)</SelectItem>
                    <SelectItem value="nftables">nftables (Modern)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-4">
                <Label className="text-foreground">Allowed Services</Label>

                <div className="flex items-center space-x-2">
                  <Checkbox id="ssh" checked={allowSSH} onCheckedChange={(checked) => setAllowSSH(checked as boolean)} />
                  <Label htmlFor="ssh" className="text-sm cursor-pointer">SSH (Port 22)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="http" checked={allowHTTP} onCheckedChange={(checked) => setAllowHTTP(checked as boolean)} />
                  <Label htmlFor="http" className="text-sm cursor-pointer">HTTP (Port 80)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="https" checked={allowHTTPS} onCheckedChange={(checked) => setAllowHTTPS(checked as boolean)} />
                  <Label htmlFor="https" className="text-sm cursor-pointer">HTTPS (Port 443)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="dns" checked={allowDNS} onCheckedChange={(checked) => setAllowDNS(checked as boolean)} />
                  <Label htmlFor="dns" className="text-sm cursor-pointer">DNS (Port 53)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="mysql" checked={allowMySQL} onCheckedChange={(checked) => setAllowMySQL(checked as boolean)} />
                  <Label htmlFor="mysql" className="text-sm cursor-pointer">MySQL (Port 3306)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="postgresql" checked={allowPostgreSQL} onCheckedChange={(checked) => setAllowPostgreSQL(checked as boolean)} />
                  <Label htmlFor="postgresql" className="text-sm cursor-pointer">PostgreSQL (Port 5432)</Label>
                </div>
              </div>

              <div className="space-y-4 pt-4 border-t border-border">
                <Label className="text-foreground">Security Options</Label>

                <div className="flex items-center space-x-2">
                  <Checkbox id="dropInvalid" checked={dropInvalid} onCheckedChange={(checked) => setDropInvalid(checked as boolean)} />
                  <Label htmlFor="dropInvalid" className="text-sm cursor-pointer">Drop invalid packets</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox id="logDropped" checked={logDropped} onCheckedChange={(checked) => setLogDropped(checked as boolean)} />
                  <Label htmlFor="logDropped" className="text-sm cursor-pointer">Log dropped packets</Label>
                </div>
              </div>

              <Button onClick={generateFirewallRules} className="w-full" size="lg">
                Generate Firewall Rules
              </Button>
            </CardContent>
          </Card>

          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5" />
                  Generated Rules
                </CardTitle>
                {result && (
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={copyToClipboard} className="gap-2">
                      {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      Copy
                    </Button>
                    <Button variant="outline" size="sm" onClick={downloadRules} className="gap-2">
                      <Download className="w-4 h-4" />
                      Download
                    </Button>
                  </div>
                )}
              </div>
              <CardDescription>Ready-to-use firewall configuration script</CardDescription>
            </CardHeader>
            <CardContent>
              {!result ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
                  <p>Configure options and generate rules</p>
                </div>
              ) : (
                <Textarea
                  value={result}
                  readOnly
                  className="font-mono text-sm h-96 bg-muted"
                />
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default FirewallGenerator;
