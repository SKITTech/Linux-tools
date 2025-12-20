import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Network, AlertCircle, Copy, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";

interface SubnetInfo {
  networkAddress: string;
  broadcastAddress: string;
  firstUsableHost: string;
  lastUsableHost: string;
  totalHosts: string;
  usableHosts: string;
  wildcardMask: string;
  binarySubnet: string;
  ipClass: string;
  cidr: string;
  isPrivate: boolean;
}

const SubnetCalculator = () => {
  const [ipAddress, setIpAddress] = useState("");
  const [cidrOrMask, setCidrOrMask] = useState("");
  const [ipVersion, setIpVersion] = useState<"ipv4" | "ipv6">("ipv4");
  const [result, setResult] = useState<SubnetInfo | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const calculateIPv4Subnet = (ip: string, cidr: number): SubnetInfo | null => {
    const ipParts = ip.split(".").map(Number);
    if (ipParts.length !== 4 || ipParts.some(p => p < 0 || p > 255)) {
      setError("Invalid IPv4 address format");
      return null;
    }

    const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const mask = ((0xffffffff << (32 - cidr)) >>> 0);
    const network = (ipInt & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;

    const networkAddr = [
      (network >>> 24) & 0xff,
      (network >>> 16) & 0xff,
      (network >>> 8) & 0xff,
      network & 0xff,
    ].join(".");

    const broadcastAddr = [
      (broadcast >>> 24) & 0xff,
      (broadcast >>> 16) & 0xff,
      (broadcast >>> 8) & 0xff,
      broadcast & 0xff,
    ].join(".");

    const firstHost = [
      (network >>> 24) & 0xff,
      (network >>> 16) & 0xff,
      (network >>> 8) & 0xff,
      (network & 0xff) + 1,
    ].join(".");

    const lastHost = [
      (broadcast >>> 24) & 0xff,
      (broadcast >>> 16) & 0xff,
      (broadcast >>> 8) & 0xff,
      (broadcast & 0xff) - 1,
    ].join(".");

    const totalHosts = Math.pow(2, 32 - cidr);
    const usableHosts = cidr === 31 ? 2 : cidr === 32 ? 1 : Math.max(0, totalHosts - 2);

    const wildcardMask = [
      ((~mask >>> 0) >>> 24) & 0xff,
      ((~mask >>> 0) >>> 16) & 0xff,
      ((~mask >>> 0) >>> 8) & 0xff,
      (~mask >>> 0) & 0xff,
    ].join(".");

    const binarySubnet = ipParts
      .map(p => p.toString(2).padStart(8, "0"))
      .join(".");

    let ipClass = "Unknown";
    const firstOctet = ipParts[0];
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = "A";
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = "B";
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = "C";
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = "D (Multicast)";
    else if (firstOctet >= 240 && firstOctet <= 255) ipClass = "E (Reserved)";

    const isPrivate =
      (firstOctet === 10) ||
      (firstOctet === 172 && ipParts[1] >= 16 && ipParts[1] <= 31) ||
      (firstOctet === 192 && ipParts[1] === 168);

    return {
      networkAddress: networkAddr,
      broadcastAddress: broadcastAddr,
      firstUsableHost: firstHost,
      lastUsableHost: lastHost,
      totalHosts: totalHosts.toLocaleString(),
      usableHosts: usableHosts.toLocaleString(),
      wildcardMask,
      binarySubnet,
      ipClass,
      cidr: `/${cidr}`,
      isPrivate,
    };
  };

  const calculateIPv6Subnet = (ip: string, prefix: number): SubnetInfo | null => {
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

    const expanded = expandIPv6(ip);
    const parts = expanded.split(":");

    if (parts.length !== 8) {
      setError("Invalid IPv6 address format");
      return null;
    }

    const totalHosts = Math.pow(2, 128 - prefix);
    const displayHosts = totalHosts > Number.MAX_SAFE_INTEGER 
      ? `2^${128 - prefix}` 
      : totalHosts.toLocaleString();

    return {
      networkAddress: expanded,
      broadcastAddress: "N/A (IPv6 uses multicast)",
      firstUsableHost: expanded,
      lastUsableHost: "N/A",
      totalHosts: displayHosts,
      usableHosts: displayHosts,
      wildcardMask: "N/A",
      binarySubnet: parts.map(p => parseInt(p, 16).toString(2).padStart(16, "0")).join(":"),
      ipClass: "N/A (IPv6)",
      cidr: `/${prefix}`,
      isPrivate: ip.startsWith("fc") || ip.startsWith("fd"),
    };
  };

  const handleCalculate = () => {
    setError("");
    setResult(null);

    if (!ipAddress.trim() || !cidrOrMask.trim()) {
      setError("Please enter both IP address and CIDR/Netmask");
      return;
    }

    let cidr = 0;
    if (cidrOrMask.includes(".")) {
      // Convert netmask to CIDR
      const maskParts = cidrOrMask.split(".").map(Number);
      if (maskParts.length !== 4) {
        setError("Invalid netmask format");
        return;
      }
      const maskInt = (maskParts[0] << 24) | (maskParts[1] << 16) | (maskParts[2] << 8) | maskParts[3];
      cidr = 32 - Math.log2((~maskInt >>> 0) + 1);
    } else {
      cidr = parseInt(cidrOrMask.replace("/", ""));
    }

    if (isNaN(cidr) || cidr < 0 || (ipVersion === "ipv4" ? cidr > 32 : cidr > 128)) {
      setError(`Invalid CIDR notation for ${ipVersion.toUpperCase()}`);
      return;
    }

    const calculatedResult = ipVersion === "ipv4" 
      ? calculateIPv4Subnet(ipAddress, cidr)
      : calculateIPv6Subnet(ipAddress, cidr);

    if (calculatedResult) {
      setResult(calculatedResult);
      toast.success("Subnet calculated successfully!");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const copyAllResults = () => {
    if (!result) return;
    
    const text = `
Subnet Calculation Results (${ipVersion.toUpperCase()})
=====================================
Network Address: ${result.networkAddress}
${ipVersion === "ipv4" ? `Broadcast Address: ${result.broadcastAddress}` : ""}
First Usable Host: ${result.firstUsableHost}
Last Usable Host: ${result.lastUsableHost}
Total Hosts: ${result.totalHosts}
Usable Hosts: ${result.usableHosts}
Wildcard Mask: ${result.wildcardMask}
CIDR Notation: ${ipAddress}${result.cidr}
${ipVersion === "ipv4" ? `IP Class: ${result.ipClass}` : ""}
Private Address: ${result.isPrivate ? "Yes" : "No"}
    `.trim();
    
    copyToClipboard(text);
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Network className="w-10 h-10 text-primary" />
              <h1 className="text-4xl font-bold text-foreground">Subnet Calculator</h1>
            </div>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Calculate IPv4 and IPv6 subnet information including network addresses, host ranges, and CIDR notation
            </p>
          </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Input Section */}
          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="w-5 h-5" />
                Subnet Configuration
              </CardTitle>
              <CardDescription>
                Enter an IP address and CIDR notation or netmask
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* IP Version Toggle */}
              <div>
                <Label className="text-foreground mb-2 block">IP Version</Label>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant={ipVersion === "ipv4" ? "default" : "outline"}
                    onClick={() => {
                      setIpVersion("ipv4");
                      setResult(null);
                      setError("");
                    }}
                    className="flex-1"
                  >
                    IPv4
                  </Button>
                  <Button
                    type="button"
                    variant={ipVersion === "ipv6" ? "default" : "outline"}
                    onClick={() => {
                      setIpVersion("ipv6");
                      setResult(null);
                      setError("");
                    }}
                    className="flex-1"
                  >
                    IPv6
                  </Button>
                </div>
              </div>

              <Separator />

              {/* IP Address Input */}
              <div>
                <Label htmlFor="ipAddress" className="text-foreground">
                  IP Address <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="ipAddress"
                  placeholder={ipVersion === "ipv4" ? "192.168.1.0" : "2001:0db8:85a3::8a2e:0370:7334"}
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="mt-1"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {ipVersion === "ipv4" 
                    ? "Enter an IPv4 address (e.g., 192.168.1.0)" 
                    : "Enter an IPv6 address (e.g., 2001:db8::1)"}
                </p>
              </div>

              {/* CIDR/Netmask Input */}
              <div>
                <Label htmlFor="cidrOrMask" className="text-foreground">
                  {ipVersion === "ipv4" ? "CIDR or Netmask" : "Prefix Length"} <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="cidrOrMask"
                  placeholder={ipVersion === "ipv4" ? "24 or 255.255.255.0" : "64"}
                  value={cidrOrMask}
                  onChange={(e) => setCidrOrMask(e.target.value)}
                  className="mt-1"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {ipVersion === "ipv4" 
                    ? "Enter CIDR (e.g., 24) or netmask (e.g., 255.255.255.0)" 
                    : "Enter prefix length (e.g., 64)"}
                </p>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button onClick={handleCalculate} className="w-full" size="lg">
                Calculate Subnet
              </Button>
            </CardContent>
          </Card>

          {/* Results Section */}
          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5" />
                  Calculation Results
                </CardTitle>
                {result && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={copyAllResults}
                    className="gap-2"
                  >
                    {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    Copy All
                  </Button>
                )}
              </div>
              <CardDescription>
                Detailed subnet information and network breakdown
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!result ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Network className="w-16 h-16 mx-auto mb-4 opacity-20" />
                  <p>Enter IP address and CIDR to see results</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-4">
                    <ResultRow label="Network Address" value={result.networkAddress} />
                    {ipVersion === "ipv4" && (
                      <ResultRow label="Broadcast Address" value={result.broadcastAddress} />
                    )}
                    <ResultRow label="First Usable Host" value={result.firstUsableHost} />
                    <ResultRow label="Last Usable Host" value={result.lastUsableHost} />
                    <ResultRow label="Total Hosts" value={result.totalHosts} />
                    <ResultRow label="Usable Hosts" value={result.usableHosts} />
                    {ipVersion === "ipv4" && (
                      <>
                        <ResultRow label="Wildcard Mask" value={result.wildcardMask} />
                        <ResultRow label="IP Class" value={result.ipClass} />
                      </>
                    )}
                    <ResultRow label="CIDR Notation" value={`${ipAddress}${result.cidr}`} />
                    <ResultRow 
                      label="Private Address" 
                      value={result.isPrivate ? "Yes" : "No"}
                      highlight={result.isPrivate}
                    />
                  </div>

                  <Separator />

                  <div className="bg-muted/30 p-4 rounded-lg">
                    <Label className="text-sm font-semibold mb-2 block">Binary Representation</Label>
                    <p className="text-xs font-mono break-all text-muted-foreground">
                      {result.binarySubnet}
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Quick Reference */}
        <Card className="mt-8 border-border/40 shadow-lg">
          <CardHeader>
            <CardTitle>Common CIDR Notations (IPv4)</CardTitle>
            <CardDescription>Quick reference for common subnet masks</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { cidr: "/8", mask: "255.0.0.0", hosts: "16,777,214" },
                { cidr: "/16", mask: "255.255.0.0", hosts: "65,534" },
                { cidr: "/22", mask: "255.255.252.0", hosts: "1,022" },
                { cidr: "/23", mask: "255.255.254.0", hosts: "510" },
                { cidr: "/24", mask: "255.255.255.0", hosts: "254" },
                { cidr: "/25", mask: "255.255.255.128", hosts: "126" },
                { cidr: "/26", mask: "255.255.255.192", hosts: "62" },
                { cidr: "/27", mask: "255.255.255.224", hosts: "30" },
              ].map((item) => (
                <div key={item.cidr} className="bg-muted/30 p-3 rounded-lg">
                  <div className="font-semibold text-primary">{item.cidr}</div>
                  <div className="text-xs text-muted-foreground">{item.mask}</div>
                  <div className="text-xs text-muted-foreground">{item.hosts} hosts</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        </div>
      </div>
    </Sidebar>
  );
};

interface ResultRowProps {
  label: string;
  value: string;
  highlight?: boolean;
}

const ResultRow = ({ label, value, highlight }: ResultRowProps) => (
  <div className="flex justify-between items-center py-2 border-b border-border/40 last:border-0">
    <span className="text-sm font-medium text-muted-foreground">{label}</span>
    <span className={`text-sm font-mono ${highlight ? "text-primary font-semibold" : "text-foreground"}`}>
      {value}
    </span>
  </div>
);

export default SubnetCalculator;
