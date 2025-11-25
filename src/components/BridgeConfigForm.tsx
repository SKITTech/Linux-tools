import { useState } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Copy, Download, Terminal, Check, AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { NetworkConfig, OS_OPTIONS, NETMASK_OPTIONS, ParsedConfig } from "@/types/networkConfig";
import { generateCommands } from "@/utils/commandGenerators";
import { validateIPAddress, validateNetmask, cidrToNetmask } from "@/utils/configParser";
import { NetworkConfigParser } from "./NetworkConfigParser";

export const BridgeConfigForm = () => {
  const [config, setConfig] = useState<NetworkConfig>({
    ipAddress: "",
    netmask: "255.255.255.0",
    bridgeName: "viifbr0",
    interfaces: "",
    gateway: "",
    dns: "8.8.8.8,8.8.4.4",
    os: "ubuntu-18.04-hetzner",
    macAddress: "",
    enableIPv6: false,
    ipv6Address: "",
    ipv6Gateway: "",
    ipv6Prefix: "64",
    enableBonding: false,
    bondName: "bond0",
    bondMode: "mode-1",
    bondSlaves: "",
  });

  const [copied, setCopied] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  const validateForm = () => {
    const errors: Record<string, string> = {};

    if (config.ipAddress && !validateIPAddress(config.ipAddress)) {
      errors.ipAddress = "Invalid IP address format";
    }

    if (config.netmask && !validateNetmask(config.netmask)) {
      errors.netmask = "Invalid netmask format";
    }

    if (!config.gateway.trim()) {
      errors.gateway = "Gateway is required";
    } else if (!validateIPAddress(config.gateway)) {
      errors.gateway = "Invalid gateway IP address";
    }

    if (!config.enableBonding && !config.interfaces.trim()) {
      errors.interfaces = "At least one interface is required";
    }

    if (config.enableBonding && !config.bondSlaves.trim()) {
      errors.bondSlaves = "At least two slave interfaces are required for bonding";
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleParsedConfig = (parsed: ParsedConfig) => {
    const updates: Partial<NetworkConfig> = {};

    if (parsed.ipAddress) updates.ipAddress = parsed.ipAddress;
    if (parsed.gateway) updates.gateway = parsed.gateway;
    if (parsed.netmask) updates.netmask = parsed.netmask;
    if (parsed.prefix) updates.netmask = cidrToNetmask(parseInt(parsed.prefix));
    if (parsed.interfaceName) updates.interfaces = parsed.interfaceName;
    if (parsed.bridgeName) updates.bridgeName = parsed.bridgeName;
    if (parsed.bondSlaves && parsed.bondSlaves.length > 0) {
      updates.enableBonding = true;
      updates.bondSlaves = parsed.bondSlaves.join(", ");
    }

    setConfig({ ...config, ...updates });
  };

  const handleCopy = async () => {
    if (!validateForm()) {
      toast.error("Please fix validation errors first");
      return;
    }

    const commands = generateCommands(config);
    await navigator.clipboard.writeText(commands);
    setCopied(true);
    toast.success("Commands copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!validateForm()) {
      toast.error("Please fix validation errors first");
      return;
    }

    const commands = generateCommands(config);
    const blob = new Blob([commands], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bridge-${config.bridgeName}-${config.os}.sh`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Script downloaded!");
  };

  return (
    <div className="space-y-6">
      {/* Smart Config Parser */}
      <NetworkConfigParser onParsed={handleParsedConfig} />

      {/* Main Configuration */}
      <div className="grid lg:grid-cols-2 gap-6">
        <Card className="p-6 bg-card border-border">
          <div className="flex items-center gap-2 mb-6">
            <Terminal className="w-5 h-5 text-primary" />
            <h2 className="text-xl font-semibold text-foreground">Bridge Configuration</h2>
          </div>
          
          <div className="space-y-4">
            {/* OS Selection */}
            <div>
              <Label htmlFor="os" className="text-foreground">
                Operating System <span className="text-destructive">*</span>
              </Label>
              <Select value={config.os} onValueChange={(value: any) => setConfig({ ...config, os: value })}>
                <SelectTrigger className="mt-1.5 bg-background border-input">
                  <SelectValue placeholder="Select OS" />
                </SelectTrigger>
                <SelectContent className="bg-popover border-border z-50">
                  {OS_OPTIONS.map(opt => (
                    <SelectItem key={opt.value} value={opt.value} className="hover:bg-accent">
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">Choose your server's operating system</p>
            </div>

            {/* IP Address */}
            <div>
              <Label htmlFor="ipAddress" className="text-foreground">
                IP Address <span className="text-destructive">*</span>
              </Label>
              <Input
                id="ipAddress"
                placeholder="192.168.10.10"
                value={config.ipAddress}
                onChange={(e) => {
                  setConfig({ ...config, ipAddress: e.target.value });
                  validateForm();
                }}
                className={`mt-1.5 bg-background border-input ${validationErrors.ipAddress ? 'border-destructive' : ''}`}
              />
              {validationErrors.ipAddress && (
                <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                  <AlertCircle className="w-3 h-3" />
                  {validationErrors.ipAddress}
                </div>
              )}
              <p className="text-xs text-muted-foreground mt-1">IPv4 address for the bridge</p>
            </div>

            {/* Netmask Dropdown */}
            <div>
              <Label htmlFor="netmask" className="text-foreground">
                Netmask <span className="text-destructive">*</span>
              </Label>
              <Select value={config.netmask} onValueChange={(value) => setConfig({ ...config, netmask: value })}>
                <SelectTrigger className="mt-1.5 bg-background border-input">
                  <SelectValue placeholder="Select netmask" />
                </SelectTrigger>
                <SelectContent className="bg-popover border-border z-50">
                  {NETMASK_OPTIONS.map(opt => (
                    <SelectItem key={opt.value} value={opt.value} className="hover:bg-accent">
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">Network mask for your subnet</p>
            </div>

            {/* Bridge Name */}
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

            {/* MAC Address */}
            <div>
              <Label htmlFor="macAddress" className="text-foreground">
                MAC Address
              </Label>
              <Input
                id="macAddress"
                placeholder="00:16:3e:7f:ae:93"
                value={config.macAddress}
                onChange={(e) => setConfig({ ...config, macAddress: e.target.value })}
                className="mt-1.5 bg-background border-input"
              />
              <p className="text-xs text-muted-foreground mt-1">Optional MAC address for the bridge</p>
            </div>

            {/* IPv6 Toggle */}
            <div className="flex items-center justify-between p-4 bg-accent/10 rounded-lg border border-accent/20">
              <div>
                <Label htmlFor="enableIPv6" className="text-foreground font-medium">
                  Enable IPv6
                </Label>
                <p className="text-xs text-muted-foreground mt-1">
                  Configure IPv6 address for the bridge
                </p>
              </div>
              <Switch
                id="enableIPv6"
                checked={config.enableIPv6}
                onCheckedChange={(checked) =>
                  setConfig({
                    ...config,
                    enableIPv6: checked,
                    dns: checked
                      ? "8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844"
                      : "8.8.8.8,8.8.4.4"
                  })
                }
              />
            </div>

            {/* IPv6 Configuration */}
            {config.enableIPv6 && (
              <>
                <div>
                  <Label htmlFor="ipv6Address" className="text-foreground">
                    IPv6 Address <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="ipv6Address"
                    placeholder="2001:db8::1"
                    value={config.ipv6Address}
                    onChange={(e) => setConfig({ ...config, ipv6Address: e.target.value })}
                    className="mt-1.5 bg-background border-input"
                  />
                  <p className="text-xs text-muted-foreground mt-1">IPv6 address for the bridge</p>
                </div>

                <div>
                  <Label htmlFor="ipv6Prefix" className="text-foreground">
                    IPv6 Prefix Length <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="ipv6Prefix"
                    placeholder="64"
                    value={config.ipv6Prefix}
                    onChange={(e) => setConfig({ ...config, ipv6Prefix: e.target.value })}
                    className="mt-1.5 bg-background border-input"
                  />
                  <p className="text-xs text-muted-foreground mt-1">Typically 64 for most networks</p>
                </div>

                <div>
                  <Label htmlFor="ipv6Gateway" className="text-foreground">
                    IPv6 Gateway <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="ipv6Gateway"
                    placeholder="2001:db8::1"
                    value={config.ipv6Gateway}
                    onChange={(e) => setConfig({ ...config, ipv6Gateway: e.target.value })}
                    className="mt-1.5 bg-background border-input"
                  />
                  <p className="text-xs text-muted-foreground mt-1">Default IPv6 gateway</p>
                </div>
              </>
            )}

            {/* Bonding Toggle */}
            <div className="flex items-center justify-between p-4 bg-accent/10 rounded-lg border border-accent/20">
              <div>
                <Label htmlFor="enableBonding" className="text-foreground font-medium">
                  Enable Network Bonding
                </Label>
                <p className="text-xs text-muted-foreground mt-1">
                  Bond multiple interfaces for redundancy and increased throughput
                </p>
              </div>
              <Switch
                id="enableBonding"
                checked={config.enableBonding}
                onCheckedChange={(checked) => setConfig({ ...config, enableBonding: checked })}
              />
            </div>

            {/* Bonding Configuration */}
            {config.enableBonding ? (
              <>
                <div>
                  <Label htmlFor="bondName" className="text-foreground">
                    Bond Name <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="bondName"
                    placeholder="bond0"
                    value={config.bondName}
                    onChange={(e) => setConfig({ ...config, bondName: e.target.value })}
                    className="mt-1.5 bg-background border-input"
                  />
                </div>

                <div>
                  <Label htmlFor="bondMode" className="text-foreground">
                    Bond Mode <span className="text-destructive">*</span>
                  </Label>
                  <Select value={config.bondMode} onValueChange={(value: any) => setConfig({ ...config, bondMode: value })}>
                    <SelectTrigger className="mt-1.5 bg-background border-input">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border-border z-50">
                      <SelectItem value="mode-1" className="hover:bg-accent">Mode 1 (Active-Backup)</SelectItem>
                      <SelectItem value="mode-4" className="hover:bg-accent">Mode 4 (802.3ad LACP)</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground mt-1">
                    Mode 1 for failover, Mode 4 for load balancing
                  </p>
                </div>

                <div>
                  <Label htmlFor="bondSlaves" className="text-foreground">
                    Bond Slave Interfaces <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="bondSlaves"
                    placeholder="eth0, eth1"
                    value={config.bondSlaves}
                    onChange={(e) => {
                      setConfig({ ...config, bondSlaves: e.target.value });
                      validateForm();
                    }}
                    className={`mt-1.5 bg-background border-input ${validationErrors.bondSlaves ? 'border-destructive' : ''}`}
                  />
                  {validationErrors.bondSlaves && (
                    <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                      <AlertCircle className="w-3 h-3" />
                      {validationErrors.bondSlaves}
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">Comma-separated physical interfaces</p>
                </div>
              </>
            ) : (
              <div>
                <Label htmlFor="interfaces" className="text-foreground">
                  Physical Interfaces <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="interfaces"
                  placeholder="eth0, eth1"
                  value={config.interfaces}
                  onChange={(e) => {
                    setConfig({ ...config, interfaces: e.target.value });
                    validateForm();
                  }}
                  className={`mt-1.5 bg-background border-input ${validationErrors.interfaces ? 'border-destructive' : ''}`}
                />
                {validationErrors.interfaces && (
                  <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                    <AlertCircle className="w-3 h-3" />
                    {validationErrors.interfaces}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">Comma-separated list of interfaces</p>
              </div>
            )}

            {/* Gateway */}
            <div>
            <Label htmlFor="gateway" className="text-foreground">
                Gateway <span className="text-destructive">*</span>
              </Label>
              <Input
                id="gateway"
                placeholder="192.168.10.1"
                value={config.gateway}
                onChange={(e) => {
                  setConfig({ ...config, gateway: e.target.value });
                  validateForm();
                }}
                className={`mt-1.5 bg-background border-input ${validationErrors.gateway ? 'border-destructive' : ''}`}
              />
              {validationErrors.gateway && (
                <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                  <AlertCircle className="w-3 h-3" />
                  {validationErrors.gateway}
                </div>
              )}
              <p className="text-xs text-muted-foreground mt-1">Default gateway for network routing</p>
            </div>

            {/* DNS */}
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

        {/* Output Panel */}
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
            value={generateCommands(config)}
            readOnly
            className="font-mono text-sm bg-terminal-bg text-terminal-text border-terminal-border min-h-[600px] resize-none"
          />
        </Card>
      </div>
    </div>
  );
};
