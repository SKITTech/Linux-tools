import { useState } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Copy, Download, Terminal, Check } from "lucide-react";
import { toast } from "sonner";

interface BridgeConfig {
  ipAddress: string;
  netmask: string;
  bridgeName: string;
  interfaces: string;
  gateway: string;
  dns: string;
}

export const BridgeConfigForm = () => {
  const [config, setConfig] = useState<BridgeConfig>({
    ipAddress: "",
    netmask: "",
    bridgeName: "br0",
    interfaces: "",
    gateway: "",
    dns: "",
  });

  const [copied, setCopied] = useState(false);

  const validateIP = (ip: string): boolean => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipv4Regex.test(ip);
  };

  const generateCommands = (): string => {
    if (!config.ipAddress || !config.netmask || !config.bridgeName || !config.interfaces) {
      return "# Please fill in all required fields";
    }

    const interfaceList = config.interfaces.split(",").map(i => i.trim()).filter(i => i);
    const cidr = netmaskToCIDR(config.netmask);

    let commands = `# Bridge Configuration Commands\n`;
    commands += `# Generated for ${config.bridgeName}\n\n`;
    
    commands += `# Create bridge\n`;
    commands += `ip link add name ${config.bridgeName} type bridge\n`;
    commands += `ip link set ${config.bridgeName} up\n\n`;
    
    commands += `# Add interfaces to bridge\n`;
    interfaceList.forEach(iface => {
      commands += `ip link set ${iface} master ${config.bridgeName}\n`;
      commands += `ip link set ${iface} up\n`;
    });
    
    commands += `\n# Configure IP address\n`;
    commands += `ip addr add ${config.ipAddress}/${cidr} dev ${config.bridgeName}\n`;
    
    if (config.gateway) {
      commands += `\n# Set default gateway\n`;
      commands += `ip route add default via ${config.gateway} dev ${config.bridgeName}\n`;
    }
    
    if (config.dns) {
      commands += `\n# Configure DNS (add to /etc/resolv.conf)\n`;
      config.dns.split(",").forEach(dns => {
        commands += `echo "nameserver ${dns.trim()}" >> /etc/resolv.conf\n`;
      });
    }

    return commands;
  };

  const netmaskToCIDR = (netmask: string): number => {
    const maskNodes = netmask.split('.').map(Number);
    let cidr = 0;
    for (const node of maskNodes) {
      cidr += (node >>> 0).toString(2).split('1').length - 1;
    }
    return cidr;
  };

  const handleCopy = async () => {
    const commands = generateCommands();
    await navigator.clipboard.writeText(commands);
    setCopied(true);
    toast.success("Commands copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const commands = generateCommands();
    const blob = new Blob([commands], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bridge-${config.bridgeName}.sh`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Script downloaded!");
  };

  return (
    <div className="grid lg:grid-cols-2 gap-6">
      <Card className="p-6 bg-card border-border">
        <div className="flex items-center gap-2 mb-6">
          <Terminal className="w-5 h-5 text-primary" />
          <h2 className="text-xl font-semibold text-foreground">Bridge Configuration</h2>
        </div>
        
        <div className="space-y-4">
          <div>
            <Label htmlFor="ipAddress" className="text-foreground">
              IP Address <span className="text-destructive">*</span>
            </Label>
            <Input
              id="ipAddress"
              placeholder="192.168.10.10"
              value={config.ipAddress}
              onChange={(e) => setConfig({ ...config, ipAddress: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">IPv4 address for the bridge</p>
          </div>

          <div>
            <Label htmlFor="netmask" className="text-foreground">
              Netmask <span className="text-destructive">*</span>
            </Label>
            <Input
              id="netmask"
              placeholder="255.255.255.0"
              value={config.netmask}
              onChange={(e) => setConfig({ ...config, netmask: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">Network mask (e.g., 255.255.255.0)</p>
          </div>

          <div>
            <Label htmlFor="bridgeName" className="text-foreground">
              Bridge Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="bridgeName"
              placeholder="br0"
              value={config.bridgeName}
              onChange={(e) => setConfig({ ...config, bridgeName: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">Name for the bridge interface</p>
          </div>

          <div>
            <Label htmlFor="interfaces" className="text-foreground">
              Physical Interfaces <span className="text-destructive">*</span>
            </Label>
            <Input
              id="interfaces"
              placeholder="eth0, eth1"
              value={config.interfaces}
              onChange={(e) => setConfig({ ...config, interfaces: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">Comma-separated list of interfaces</p>
          </div>

          <div>
            <Label htmlFor="gateway" className="text-foreground">
              Gateway
            </Label>
            <Input
              id="gateway"
              placeholder="192.168.10.1"
              value={config.gateway}
              onChange={(e) => setConfig({ ...config, gateway: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">Default gateway (optional)</p>
          </div>

          <div>
            <Label htmlFor="dns" className="text-foreground">
              DNS Servers
            </Label>
            <Input
              id="dns"
              placeholder="8.8.8.8, 8.8.4.4"
              value={config.dns}
              onChange={(e) => setConfig({ ...config, dns: e.target.value })}
              className="mt-1.5 bg-background border-input"
            />
            <p className="text-xs text-muted-foreground mt-1">Comma-separated DNS servers (optional)</p>
          </div>
        </div>
      </Card>

      <Card className="p-6 bg-terminal-bg border-terminal-border h-fit sticky top-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-terminal-text">Generated Commands</h2>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={handleCopy}
              className="bg-terminal-bg hover:bg-terminal-border border-terminal-border text-terminal-text"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleDownload}
              className="bg-terminal-bg hover:bg-terminal-border border-terminal-border text-terminal-text"
            >
              <Download className="w-4 h-4" />
            </Button>
          </div>
        </div>
        
        <Textarea
          value={generateCommands()}
          readOnly
          className="font-mono text-sm bg-terminal-bg text-terminal-text border-terminal-border min-h-[500px] resize-none"
        />
      </Card>
    </div>
  );
};
