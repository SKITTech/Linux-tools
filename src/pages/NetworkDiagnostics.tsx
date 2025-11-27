import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Textarea } from "@/components/ui/textarea";
import { Activity, Network, Wifi, Globe, AlertCircle, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { ToolNav } from "@/components/ToolNav";
import { supabase } from "@/integrations/supabase/client";

const NetworkDiagnostics = () => {
  const [pingHost, setPingHost] = useState("");
  const [pingResult, setPingResult] = useState("");
  const [portHost, setPortHost] = useState("");
  const [portNumber, setPortNumber] = useState("");
  const [portResult, setPortResult] = useState("");
  const [dnsQuery, setDnsQuery] = useState("");
  const [dnsType, setDnsType] = useState("A");
  const [dnsResult, setDnsResult] = useState("");
  const [loading, setLoading] = useState(false);

  const simulatePing = async () => {
    if (!pingHost.trim()) {
      toast.error("Please enter a hostname or IP address");
      return;
    }

    setLoading(true);
    setPingResult("Simulating ping...\n");

    // Simulate ping with random latency
    const packets = 4;
    let output = `PING ${pingHost} (simulated)\n\n`;

    for (let i = 0; i < packets; i++) {
      await new Promise(resolve => setTimeout(resolve, 300));
      const latency = (Math.random() * 50 + 10).toFixed(1);
      const ttl = Math.floor(Math.random() * 10) + 54;
      output += `64 bytes from ${pingHost}: icmp_seq=${i + 1} ttl=${ttl} time=${latency} ms\n`;
      setPingResult(output);
    }

    const avgLatency = (Math.random() * 50 + 10).toFixed(1);
    output += `\n--- ${pingHost} ping statistics ---\n`;
    output += `${packets} packets transmitted, ${packets} received, 0% packet loss\n`;
    output += `rtt min/avg/max = ${(parseFloat(avgLatency) - 5).toFixed(1)}/${avgLatency}/${(parseFloat(avgLatency) + 5).toFixed(1)} ms\n`;

    setPingResult(output);
    setLoading(false);
    toast.success("Ping simulation completed");
  };

  const checkPort = async () => {
    if (!portHost.trim() || !portNumber.trim()) {
      toast.error("Please enter both hostname and port number");
      return;
    }

    const port = parseInt(portNumber);
    if (isNaN(port) || port < 1 || port > 65535) {
      toast.error("Port must be between 1 and 65535");
      return;
    }

    setLoading(true);
    setPortResult(`Checking ${portHost}:${port}...\n`);

    try {
      const { data, error } = await supabase.functions.invoke('check-port', {
        body: {
          host: portHost.trim(),
          port: port,
          timeout: 5000
        }
      });

      if (error) {
        throw error;
      }

      let output = `Port Scan Results for ${data.host}:${data.port}\n\n`;
      
      if (data.status === 'open') {
        output += `Status: OPEN ✓\n`;
        output += `Service: ${data.service}\n`;
        output += `Response Time: ${data.responseTime}ms\n`;
        if (data.ipVersion) {
          output += `IP Version: ${data.ipVersion}\n`;
        }
        toast.success("Port is open and reachable");
      } else if (data.status === 'closed') {
        output += `Status: CLOSED/FILTERED ✗\n`;
        output += `Response Time: ${data.responseTime}ms\n`;
        output += `Error: ${data.error}\n`;
        toast.error("Port is closed or filtered");
      } else if (data.status === 'timeout') {
        output += `Status: TIMEOUT ⏱\n`;
        output += `Response Time: ${data.responseTime}ms\n`;
        output += `Error: ${data.error}\n`;
        toast.error("Connection timeout");
      } else {
        output += `Status: ERROR ✗\n`;
        output += `Error: ${data.error}\n`;
        toast.error("Error checking port");
      }

      setPortResult(output);
    } catch (error) {
      console.error('Port check error:', error);
      setPortResult(`Error checking port: ${error.message}\n`);
      toast.error("Failed to check port");
    } finally {
      setLoading(false);
    }
  };

  const lookupDNS = async () => {
    if (!dnsQuery.trim()) {
      toast.error("Please enter a domain name");
      return;
    }

    setLoading(true);
    setDnsResult(`Querying DNS records for ${dnsQuery}...\n`);

    await new Promise(resolve => setTimeout(resolve, 800));

    let output = `DNS Lookup Results for ${dnsQuery}\n`;
    output += `Query Type: ${dnsType}\n\n`;

    // Simulate DNS responses
    if (dnsType === "A") {
      output += `${dnsQuery}. 300 IN A 93.184.216.34\n`;
      output += `${dnsQuery}. 300 IN A 93.184.216.35\n`;
    } else if (dnsType === "AAAA") {
      output += `${dnsQuery}. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946\n`;
    } else if (dnsType === "MX") {
      output += `${dnsQuery}. 300 IN MX 10 mail.${dnsQuery}.\n`;
      output += `${dnsQuery}. 300 IN MX 20 mail2.${dnsQuery}.\n`;
    } else if (dnsType === "TXT") {
      output += `${dnsQuery}. 300 IN TXT "v=spf1 include:_spf.${dnsQuery} ~all"\n`;
      output += `${dnsQuery}. 300 IN TXT "google-site-verification=abc123"\n`;
    } else if (dnsType === "NS") {
      output += `${dnsQuery}. 300 IN NS ns1.${dnsQuery}.\n`;
      output += `${dnsQuery}. 300 IN NS ns2.${dnsQuery}.\n`;
    }

    output += `\nQuery time: ${Math.floor(Math.random() * 50 + 10)} msec\n`;
    output += `Server: 8.8.8.8#53\n`;

    setDnsResult(output);
    setLoading(false);
    toast.success("DNS lookup completed");
  };

  const navItems = [
    { to: "/", icon: Activity, label: "Bridge Generator" },
    { to: "/subnet-calculator", icon: Network, label: "Subnet Calculator" },
    { to: "/network-diagnostics", icon: Wifi, label: "Network Diagnostics" },
    { to: "/ipv6-converter", icon: Globe, label: "IPv6 Converter" },
    { to: "/firewall-generator", icon: Activity, label: "Firewall Generator" },
    { to: "/log-analyzer", icon: Activity, label: "Log Analyzer" },
    { to: "/security-audit", icon: Activity, label: "Security Audit" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
      <div className="container mx-auto px-4 py-8">
        <ToolNav items={navItems} />

        <div className="text-center my-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Wifi className="w-10 h-10 text-primary" />
            <h1 className="text-4xl font-bold text-foreground">Network Diagnostics</h1>
          </div>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Test network connectivity, check open ports, and perform DNS lookups
          </p>
        </div>

        <Card className="border-border/40 shadow-lg">
          <CardHeader>
            <CardTitle>Diagnostic Tools</CardTitle>
            <CardDescription>Simulate network diagnostic commands in your browser</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="ping" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="ping">Ping Test</TabsTrigger>
                <TabsTrigger value="port">Port Checker</TabsTrigger>
                <TabsTrigger value="dns">DNS Lookup</TabsTrigger>
              </TabsList>

              <TabsContent value="ping" className="space-y-4 mt-4">
                <div>
                  <Label htmlFor="pingHost" className="text-foreground">
                    Hostname or IP Address <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="pingHost"
                    placeholder="example.com or 8.8.8.8"
                    value={pingHost}
                    onChange={(e) => setPingHost(e.target.value)}
                    className="mt-1"
                  />
                </div>

                <Button onClick={simulatePing} disabled={loading} className="w-full">
                  {loading ? "Running..." : "Run Ping Test"}
                </Button>

                {pingResult && (
                  <div>
                    <Label className="text-foreground mb-2 block">Results</Label>
                    <Textarea
                      value={pingResult}
                      readOnly
                      className="font-mono text-sm h-64 bg-muted"
                    />
                  </div>
                )}

                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    This is a simulated ping test. Real ICMP ping requires server-side implementation.
                  </AlertDescription>
                </Alert>
              </TabsContent>

              <TabsContent value="port" className="space-y-4 mt-4">
                <div>
                  <Label htmlFor="portHost" className="text-foreground">
                    Hostname or IP Address <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="portHost"
                    placeholder="example.com or 192.168.1.1"
                    value={portHost}
                    onChange={(e) => setPortHost(e.target.value)}
                    className="mt-1"
                  />
                </div>

                <div>
                  <Label htmlFor="portNumber" className="text-foreground">
                    Port Number <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="portNumber"
                    type="number"
                    placeholder="80, 443, 22, etc."
                    value={portNumber}
                    onChange={(e) => setPortNumber(e.target.value)}
                    className="mt-1"
                    min="1"
                    max="65535"
                  />
                </div>

                <Button onClick={checkPort} disabled={loading} className="w-full">
                  {loading ? "Checking..." : "Check Port"}
                </Button>

                {portResult && (
                  <div>
                    <Label className="text-foreground mb-2 block">Results</Label>
                    <Textarea
                      value={portResult}
                      readOnly
                      className="font-mono text-sm h-48 bg-muted"
                    />
                  </div>
                )}

                <Alert>
                  <CheckCircle2 className="h-4 w-4" />
                  <AlertDescription>
                    Real-time port checking with backend support. Supports both IPv4 and IPv6 addresses.
                  </AlertDescription>
                </Alert>
              </TabsContent>

              <TabsContent value="dns" className="space-y-4 mt-4">
                <div>
                  <Label htmlFor="dnsQuery" className="text-foreground">
                    Domain Name <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="dnsQuery"
                    placeholder="example.com"
                    value={dnsQuery}
                    onChange={(e) => setDnsQuery(e.target.value)}
                    className="mt-1"
                  />
                </div>

                <div>
                  <Label htmlFor="dnsType" className="text-foreground">
                    Record Type <span className="text-destructive">*</span>
                  </Label>
                  <select
                    id="dnsType"
                    value={dnsType}
                    onChange={(e) => setDnsType(e.target.value)}
                    className="w-full mt-1 flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
                  >
                    <option value="A">A (IPv4 Address)</option>
                    <option value="AAAA">AAAA (IPv6 Address)</option>
                    <option value="MX">MX (Mail Exchange)</option>
                    <option value="TXT">TXT (Text Records)</option>
                    <option value="NS">NS (Name Servers)</option>
                  </select>
                </div>

                <Button onClick={lookupDNS} disabled={loading} className="w-full">
                  {loading ? "Looking up..." : "Lookup DNS"}
                </Button>

                {dnsResult && (
                  <div>
                    <Label className="text-foreground mb-2 block">Results</Label>
                    <Textarea
                      value={dnsResult}
                      readOnly
                      className="font-mono text-sm h-64 bg-muted"
                    />
                  </div>
                )}

                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    This is a simulated DNS lookup. Real DNS queries require backend implementation.
                  </AlertDescription>
                </Alert>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default NetworkDiagnostics;
