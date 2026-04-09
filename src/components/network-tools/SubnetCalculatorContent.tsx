import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Network, AlertCircle, Copy, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { NETMASK_OPTIONS } from "@/types/networkConfig";

const IPV6_PREFIX_OPTIONS = [
  { value: "128", label: "/128 - Single address" },
  { value: "127", label: "/127 - Point-to-point link" },
  { value: "126", label: "/126 - Point-to-point link" },
  { value: "124", label: "/124 - 16 addresses" },
  { value: "120", label: "/120 - 256 addresses" },
  { value: "112", label: "/112 - 65,536 addresses" },
  { value: "64", label: "/64 - Standard subnet" },
  { value: "56", label: "/56 - Typical end-site" },
  { value: "48", label: "/48 - Typical assignment" },
  { value: "32", label: "/32 - ISP allocation" },
  { value: "16", label: "/16 - Large ISP" },
];

interface SubnetInfo {
  networkAddress: string;
  broadcastAddress: string;
  subnetMask: string;
  wildcardMask: string;
  totalHosts: number;
  usableHosts: number;
  firstUsable: string;
  lastUsable: string;
  cidr: string;
  ipClass: string;
  binarySubnetMask: string;
  isPrivate: boolean;
}

interface IPv6SubnetInfo {
  networkAddress: string;
  prefixLength: number;
  totalAddresses: string;
  firstAddress: string;
  lastAddress: string;
}

const ipToNumber = (ip: string): number => {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
};

const numberToIp = (num: number): string => {
  return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join(".");
};

const calculateSubnet = (ip: string, cidr: number): SubnetInfo => {
  const ipNum = ipToNumber(ip);
  const mask = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const totalHosts = Math.pow(2, 32 - cidr);
  const usableHosts = cidr >= 31 ? totalHosts : totalHosts - 2;

  const firstOctet = (ipNum >>> 24) & 255;
  let ipClass = "A";
  if (firstOctet >= 128 && firstOctet <= 191) ipClass = "B";
  else if (firstOctet >= 192 && firstOctet <= 223) ipClass = "C";
  else if (firstOctet >= 224 && firstOctet <= 239) ipClass = "D";
  else if (firstOctet >= 240) ipClass = "E";

  const isPrivate =
    (firstOctet === 10) ||
    (firstOctet === 172 && ((ipNum >>> 16) & 255) >= 16 && ((ipNum >>> 16) & 255) <= 31) ||
    (firstOctet === 192 && ((ipNum >>> 16) & 255) === 168);

  return {
    networkAddress: numberToIp(network),
    broadcastAddress: numberToIp(broadcast),
    subnetMask: numberToIp(mask),
    wildcardMask: numberToIp(~mask >>> 0),
    totalHosts,
    usableHosts,
    firstUsable: cidr >= 31 ? numberToIp(network) : numberToIp(network + 1),
    lastUsable: cidr >= 31 ? numberToIp(broadcast) : numberToIp(broadcast - 1),
    cidr: `/${cidr}`,
    ipClass,
    binarySubnetMask: mask.toString(2).padStart(32, "0").replace(/(.{8})/g, "$1.").slice(0, -1),
    isPrivate,
  };
};

const SubnetCalculatorContent = () => {
  const [ipAddress, setIpAddress] = useState("");
  const [netmask, setNetmask] = useState("24");
  const [subnetInfo, setSubnetInfo] = useState<SubnetInfo | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState("");
  const [ipv6Address, setIpv6Address] = useState("");
  const [ipv6Prefix, setIpv6Prefix] = useState("64");
  const [ipv6Info, setIpv6Info] = useState<IPv6SubnetInfo | null>(null);
  const [ipv6Error, setIpv6Error] = useState("");
  const [activeCalc, setActiveCalc] = useState<"ipv4" | "ipv6">("ipv4");

  const validateIP = (ip: string): boolean => {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every((part) => { const num = parseInt(part, 10); return !isNaN(num) && num >= 0 && num <= 255 && part === String(num); });
  };

  const handleCalculate = () => {
    setError("");
    if (!validateIP(ipAddress)) { setError("Please enter a valid IPv4 address"); return; }
    const cidr = parseInt(netmask);
    if (isNaN(cidr) || cidr < 0 || cidr > 32) { setError("Invalid CIDR notation"); return; }
    setSubnetInfo(calculateSubnet(ipAddress, cidr));
  };

  const handleIPv6Calculate = () => {
    setIpv6Error("");
    if (!ipv6Address.match(/^[0-9a-fA-F:]+$/)) { setIpv6Error("Invalid IPv6 address format"); return; }
    const prefix = parseInt(ipv6Prefix);
    const totalAddresses = BigInt(2) ** BigInt(128 - prefix);
    setIpv6Info({
      networkAddress: ipv6Address,
      prefixLength: prefix,
      totalAddresses: totalAddresses.toString(),
      firstAddress: ipv6Address,
      lastAddress: "Calculated based on prefix",
    });
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

  const ResultRow = ({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) => (
    <div className="flex justify-between items-center py-2 border-b border-border/40 last:border-0">
      <span className="text-sm font-medium text-muted-foreground">{label}</span>
      <span className={`text-sm font-mono ${highlight ? "text-primary font-semibold" : "text-foreground"}`}>{value}</span>
    </div>
  );

  return (
    <div className="py-4 space-y-6">
      {/* Calculator Type Toggle */}
      <div className="flex gap-2">
        <Button variant={activeCalc === "ipv4" ? "default" : "outline"} onClick={() => setActiveCalc("ipv4")} className="flex-1">IPv4 Subnet</Button>
        <Button variant={activeCalc === "ipv6" ? "default" : "outline"} onClick={() => setActiveCalc("ipv6")} className="flex-1">IPv6 Subnet</Button>
      </div>

      {activeCalc === "ipv4" ? (
        <Card className="border-border/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Network className="w-5 h-5 text-primary" /> IPv4 Subnet Calculator</CardTitle>
            <CardDescription>Calculate network details from IP and CIDR</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label>IP Address</Label>
                <Input value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="192.168.1.0" onKeyDown={e => e.key === "Enter" && handleCalculate()} />
              </div>
              <div>
                <Label>CIDR / Netmask</Label>
                <Select value={netmask} onValueChange={setNetmask}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{NETMASK_OPTIONS.map(o => <SelectItem key={o.cidr} value={String(o.cidr)}>/{o.cidr} — {o.mask}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
            {error && <Alert variant="destructive"><AlertCircle className="w-4 h-4" /><AlertDescription>{error}</AlertDescription></Alert>}
            <Button onClick={handleCalculate} className="w-full gap-2"><Network className="w-4 h-4" /> Calculate</Button>

            {subnetInfo && (
              <div className="mt-4 space-y-4">
                <Separator />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-2">Network Details</h3>
                    <ResultRow label="Network Address" value={subnetInfo.networkAddress} highlight />
                    <ResultRow label="Broadcast Address" value={subnetInfo.broadcastAddress} />
                    <ResultRow label="Subnet Mask" value={subnetInfo.subnetMask} />
                    <ResultRow label="Wildcard Mask" value={subnetInfo.wildcardMask} />
                    <ResultRow label="CIDR" value={subnetInfo.cidr} highlight />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground mb-2">Host Information</h3>
                    <ResultRow label="Total Hosts" value={subnetInfo.totalHosts.toLocaleString()} />
                    <ResultRow label="Usable Hosts" value={subnetInfo.usableHosts.toLocaleString()} highlight />
                    <ResultRow label="First Usable" value={subnetInfo.firstUsable} />
                    <ResultRow label="Last Usable" value={subnetInfo.lastUsable} />
                    <ResultRow label="IP Class" value={`Class ${subnetInfo.ipClass}`} />
                    <ResultRow label="Type" value={subnetInfo.isPrivate ? "Private" : "Public"} />
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Network className="w-5 h-5 text-primary" /> IPv6 Subnet Calculator</CardTitle>
            <CardDescription>Calculate IPv6 network details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label>IPv6 Address</Label>
                <Input value={ipv6Address} onChange={(e) => setIpv6Address(e.target.value)} placeholder="2001:db8::1" onKeyDown={e => e.key === "Enter" && handleIPv6Calculate()} />
              </div>
              <div>
                <Label>Prefix Length</Label>
                <Select value={ipv6Prefix} onValueChange={setIpv6Prefix}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{IPV6_PREFIX_OPTIONS.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
            {ipv6Error && <Alert variant="destructive"><AlertCircle className="w-4 h-4" /><AlertDescription>{ipv6Error}</AlertDescription></Alert>}
            <Button onClick={handleIPv6Calculate} className="w-full gap-2"><Network className="w-4 h-4" /> Calculate</Button>

            {ipv6Info && (
              <div className="mt-4 space-y-2">
                <Separator />
                <ResultRow label="Network Address" value={ipv6Info.networkAddress} highlight />
                <ResultRow label="Prefix Length" value={`/${ipv6Info.prefixLength}`} />
                <ResultRow label="Total Addresses" value={ipv6Info.totalAddresses} highlight />
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default SubnetCalculatorContent;
