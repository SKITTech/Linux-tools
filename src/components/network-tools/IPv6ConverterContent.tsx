import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Globe, Copy, CheckCircle2, AlertCircle } from "lucide-react";
import { toast } from "sonner";

const IPv6ConverterContent = () => {
  const [ipv6Input, setIpv6Input] = useState("");
  const [expanded, setExpanded] = useState("");
  const [compressed, setCompressed] = useState("");
  const [canonical, setCanonical] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");

  const expandIPv6 = (ip: string): string => {
    const parts = ip.split(":");
    const doubleColonIndex = parts.indexOf("");
    if (doubleColonIndex !== -1) {
      const before = parts.slice(0, doubleColonIndex).filter(p => p !== "");
      const after = parts.slice(doubleColonIndex + 1).filter(p => p !== "");
      const zeros = Array(8 - before.length - after.length).fill("0000");
      return [...before, ...zeros, ...after].map(p => p.padStart(4, "0")).join(":");
    }
    return parts.map(p => p.padStart(4, "0")).join(":");
  };

  const compressIPv6 = (ip: string): string => {
    const groups = ip.split(":").map(g => g.replace(/^0+/, "") || "0");
    let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    groups.forEach((g, i) => {
      if (g === "0") {
        if (curStart === -1) curStart = i;
        curLen++;
        if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
      } else { curStart = -1; curLen = 0; }
    });
    if (bestLen > 1) {
      const before = groups.slice(0, bestStart);
      const after = groups.slice(bestStart + bestLen);
      return (before.length ? before.join(":") : "") + "::" + (after.length ? after.join(":") : "");
    }
    return groups.join(":");
  };

  const handleConvert = () => {
    setError(""); setExpanded(""); setCompressed(""); setCanonical("");
    const input = ipv6Input.trim();
    if (!input) { setError("Please enter an IPv6 address"); return; }
    try {
      const exp = expandIPv6(input);
      const groups = exp.split(":");
      if (groups.length !== 8 || groups.some(g => !/^[0-9a-fA-F]{4}$/.test(g))) {
        setError("Invalid IPv6 address format"); return;
      }
      setExpanded(exp);
      setCompressed(compressIPv6(exp));
      setCanonical(exp.toLowerCase());
    } catch { setError("Failed to parse IPv6 address"); }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`${label} copied!`);
    setTimeout(() => setCopied(""), 2000);
  };

  const CopyButton = ({ text, label }: { text: string; label: string }) => (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(text, label)}>
      {copied === label ? <CheckCircle2 className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
    </Button>
  );

  return (
    <div className="py-4 space-y-6">
      <Card className="border-border/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Globe className="w-5 h-5 text-primary" /> IPv6 Address Converter</CardTitle>
          <CardDescription>Expand, compress, and validate IPv6 addresses</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>IPv6 Address</Label>
            <Input value={ipv6Input} onChange={(e) => setIpv6Input(e.target.value)} placeholder="2001:db8::1" onKeyDown={e => e.key === "Enter" && handleConvert()} />
          </div>
          {error && <Alert variant="destructive"><AlertCircle className="w-4 h-4" /><AlertDescription>{error}</AlertDescription></Alert>}
          <Button onClick={handleConvert} className="w-full gap-2"><Globe className="w-4 h-4" /> Convert</Button>

          {expanded && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
                <div>
                  <p className="text-xs text-muted-foreground">Expanded</p>
                  <p className="text-sm font-mono text-foreground">{expanded}</p>
                </div>
                <CopyButton text={expanded} label="Expanded" />
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
                <div>
                  <p className="text-xs text-muted-foreground">Compressed</p>
                  <p className="text-sm font-mono text-foreground">{compressed}</p>
                </div>
                <CopyButton text={compressed} label="Compressed" />
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
                <div>
                  <p className="text-xs text-muted-foreground">Canonical</p>
                  <p className="text-sm font-mono text-foreground">{canonical}</p>
                </div>
                <CopyButton text={canonical} label="Canonical" />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/40">
        <CardHeader>
          <CardTitle className="text-sm">Quick Reference</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <p>• <span className="font-mono text-foreground">::1</span> — Loopback</p>
          <p>• <span className="font-mono text-foreground">::</span> — Unspecified</p>
          <p>• <span className="font-mono text-foreground">fe80::</span> — Link-local</p>
          <p>• <span className="font-mono text-foreground">2001:db8::</span> — Documentation</p>
          <p>• <span className="font-mono text-foreground">::ffff:0:0/96</span> — IPv4-mapped</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default IPv6ConverterContent;
