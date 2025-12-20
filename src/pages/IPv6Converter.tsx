import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Globe, Copy, CheckCircle2, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";

const IPv6Converter = () => {
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
    const expanded = expandIPv6(ip);
    const parts = expanded.split(":");

    // Find longest sequence of zeros
    let maxZeroStart = -1;
    let maxZeroLength = 0;
    let currentZeroStart = -1;
    let currentZeroLength = 0;

    parts.forEach((part, index) => {
      if (part === "0000") {
        if (currentZeroStart === -1) {
          currentZeroStart = index;
          currentZeroLength = 1;
        } else {
          currentZeroLength++;
        }
      } else {
        if (currentZeroLength > maxZeroLength) {
          maxZeroStart = currentZeroStart;
          maxZeroLength = currentZeroLength;
        }
        currentZeroStart = -1;
        currentZeroLength = 0;
      }
    });

    if (currentZeroLength > maxZeroLength) {
      maxZeroStart = currentZeroStart;
      maxZeroLength = currentZeroLength;
    }

    // Build compressed version
    let result = parts.map(p => p.replace(/^0+/, "") || "0");
    
    if (maxZeroLength > 1) {
      const before = result.slice(0, maxZeroStart);
      const after = result.slice(maxZeroStart + maxZeroLength);
      result = [...before, "", ...after];
      
      if (before.length === 0) result.unshift("");
      if (after.length === 0) result.push("");
    }

    return result.join(":");
  };

  const validateAndConvert = () => {
    setError("");
    setExpanded("");
    setCompressed("");
    setCanonical("");

    if (!ipv6Input.trim()) {
      setError("Please enter an IPv6 address");
      return;
    }

    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

    if (!ipv6Regex.test(ipv6Input)) {
      setError("Invalid IPv6 address format");
      return;
    }

    try {
      const expandedAddr = expandIPv6(ipv6Input);
      const compressedAddr = compressIPv6(ipv6Input);
      const canonicalAddr = expandedAddr.split(":").map(p => p.replace(/^0+/, "") || "0").join(":");

      setExpanded(expandedAddr);
      setCompressed(compressedAddr);
      setCanonical(canonicalAddr);
      toast.success("IPv6 address converted successfully!");
    } catch (err) {
      setError("Error processing IPv6 address");
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`${label} copied to clipboard!`);
    setTimeout(() => setCopied(""), 2000);
  };

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-8">
          <div className="text-center my-8">
            <div className="flex items-center justify-center gap-3 mb-4">
              <Globe className="w-10 h-10 text-primary" />
              <h1 className="text-4xl font-bold text-foreground">IPv6 Address Converter</h1>
            </div>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Expand, compress, and normalize IPv6 addresses between different formats
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            <Card className="border-border/40 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="w-5 h-5" />
                  IPv6 Input
                </CardTitle>
                <CardDescription>Enter an IPv6 address in any format</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <Label htmlFor="ipv6Input" className="text-foreground">
                    IPv6 Address <span className="text-destructive">*</span>
                  </Label>
                <Input
                  id="ipv6Input"
                  placeholder="2001:db8::1 or 2001:0db8:0000:0000:0000:0000:0000:0001"
                  value={ipv6Input}
                  onChange={(e) => setIpv6Input(e.target.value)}
                  className="mt-1 font-mono"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Enter IPv6 in compressed or full format
                </p>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button onClick={validateAndConvert} className="w-full" size="lg">
                Convert IPv6 Address
              </Button>

              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  <div className="space-y-2">
                    <p className="font-semibold">Example IPv6 formats:</p>
                    <ul className="text-xs space-y-1 list-disc list-inside">
                      <li>Compressed: 2001:db8::1</li>
                      <li>Full: 2001:0db8:0000:0000:0000:0000:0000:0001</li>
                      <li>Mixed: 2001:db8:0:0::1</li>
                    </ul>
                  </div>
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>

          <Card className="border-border/40 shadow-lg">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5" />
                Conversion Results
              </CardTitle>
              <CardDescription>Different representations of the IPv6 address</CardDescription>
            </CardHeader>
            <CardContent>
              {!expanded ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Globe className="w-16 h-16 mx-auto mb-4 opacity-20" />
                  <p>Enter an IPv6 address to see conversions</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="bg-muted/30 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <Label className="text-sm font-semibold">Full Expanded</Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(expanded, "Expanded format")}
                        className="h-8 gap-2"
                      >
                        {copied === "Expanded format" ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                    <p className="font-mono text-sm break-all text-primary">{expanded}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      All groups shown with leading zeros (64 characters)
                    </p>
                  </div>

                  <div className="bg-muted/30 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <Label className="text-sm font-semibold">Compressed</Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(compressed, "Compressed format")}
                        className="h-8 gap-2"
                      >
                        {copied === "Compressed format" ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                    <p className="font-mono text-sm break-all text-primary">{compressed}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      Shortest valid representation with :: notation
                    </p>
                  </div>

                  <div className="bg-muted/30 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <Label className="text-sm font-semibold">Canonical</Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(canonical, "Canonical format")}
                        className="h-8 gap-2"
                      >
                        {copied === "Canonical format" ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </Button>
                    </div>
                    <p className="font-mono text-sm break-all text-primary">{canonical}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      All groups without leading zeros (RFC 5952)
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="mt-8 border-border/40 shadow-lg">
          <CardHeader>
            <CardTitle>IPv6 Address Information</CardTitle>
            <CardDescription>Understanding IPv6 address formats</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h3 className="font-semibold mb-2 text-foreground">Compression Rules</h3>
                <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                  <li>Leading zeros in groups can be omitted</li>
                  <li>Consecutive groups of zeros replaced with ::</li>
                  <li>:: can only appear once in an address</li>
                  <li>Groups with all zeros become single 0</li>
                </ul>
              </div>
              <div>
                <h3 className="font-semibold mb-2 text-foreground">Common Prefixes</h3>
                <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                  <li>2001::/16 - Global unicast</li>
                  <li>fc00::/7 - Unique local addresses</li>
                  <li>fe80::/10 - Link-local addresses</li>
                  <li>::1/128 - Loopback address</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
        </div>
      </div>
    </Sidebar>
  );
};

export default IPv6Converter;
