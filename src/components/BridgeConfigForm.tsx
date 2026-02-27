import { useState } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Copy, Download, Terminal, Check, AlertCircle, Plus, Lightbulb } from "lucide-react";
import { toast } from "sonner";
import { NetworkConfig, OS_OPTIONS, NETMASK_OPTIONS, ParsedConfig } from "@/types/networkConfig";
import { generateCommands } from "@/utils/commandGenerators";
import { validateIPAddress, validateNetmask, cidrToNetmask, validateIPv6Address, validateMACAddress, validateInterfaceName, validateIPv6Prefix, validateDNSServers } from "@/utils/configParser";
import { NetworkConfigParser } from "./NetworkConfigParser";
import { CommandOutput } from "./CommandOutput";

const BASE_EXAMPLE = {
  netmask: "255.255.255.0",
  bridgeName: "viifbr0",
  dns: "8.8.8.8, 8.8.4.4",
  macAddress: "00:16:3e:7f:ae:93",
  enableIPv6: true,
  ipv6Address: "2001:db8::100",
  ipv6Gateway: "2001:db8::1",
  ipv6Prefix: "64",
  enableBonding: false,
  bondName: "bond0",
  bondMode: "mode-1" as const,
  bondSlaves: "",
  useGoogleDNSv4: true,
  useGoogleDNSv6: false,
  useCloudflareDNSv4: false,
  useCloudflareDNSv6: false,
  useOpenDNSv4: false,
  useOpenDNSv6: false,
  useQuad9DNSv4: false,
  useQuad9DNSv6: false,
  extraRoute: "",
};

const EXAMPLE_CONFIGS: Record<string, Partial<NetworkConfig>> = {
  "centos-7": {
    ipAddress: "192.168.1.100",
    interfaces: "eth0",
    gateway: "192.168.1.1",
    bondSlaves: "eth0, eth1",
  },
  "almalinux": {
    ipAddress: "192.168.1.100",
    interfaces: "eno1",
    gateway: "192.168.1.1",
    bondSlaves: "eno1, eno2",
  },
  "ubuntu-16.04": {
    ipAddress: "192.168.1.100",
    interfaces: "eth0",
    gateway: "192.168.1.1",
    bondSlaves: "eth0, eth1",
  },
  "ubuntu-18.04-hetzner": {
    ipAddress: "192.168.1.100",
    interfaces: "enp0s31f6",
    gateway: "192.168.1.1",
    bondSlaves: "enp0s31f6, enp0s31f7",
  },
  "ubuntu-18.04-other": {
    ipAddress: "10.1.3.43",
    interfaces: "ens3",
    gateway: "10.1.3.1",
    bondSlaves: "ens3, ens4",
  },
};

const getExampleConfig = (os: string): NetworkConfig => ({
  ...BASE_EXAMPLE,
  ...EXAMPLE_CONFIGS[os] || EXAMPLE_CONFIGS["ubuntu-18.04-hetzner"],
  os: os as NetworkConfig["os"],
} as NetworkConfig);

export const BridgeConfigForm = () => {
  const [config, setConfig] = useState<NetworkConfig>({
    ipAddress: "",
    netmask: "255.255.255.0",
    bridgeName: "viifbr0",
    interfaces: "",
    gateway: "",
    dns: "8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844",
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
     useGoogleDNSv4: true,
     useGoogleDNSv6: false,
    useCloudflareDNSv4: false,
    useCloudflareDNSv6: false,
    useOpenDNSv4: false,
    useOpenDNSv6: false,
    useQuad9DNSv4: false,
    useQuad9DNSv6: false,
    extraRoute: "",
  });

  const [copied, setCopied] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [showExtraRoute, setShowExtraRoute] = useState(false);

  const validateForm = () => {
    const errors: Record<string, string> = {};

    // IP Address validation
    if (!config.ipAddress.trim()) {
      errors.ipAddress = "IP address is required";
    } else if (!validateIPAddress(config.ipAddress)) {
      errors.ipAddress = "Invalid IP address format";
    }

    // Netmask validation
    if (!config.netmask.trim()) {
      errors.netmask = "Netmask is required";
    } else if (!validateNetmask(config.netmask)) {
      errors.netmask = "Invalid netmask format";
    }

    // Bridge name validation
    if (!config.bridgeName.trim()) {
      errors.bridgeName = "Bridge name is required";
    } else if (!validateInterfaceName(config.bridgeName)) {
      errors.bridgeName = "Invalid bridge name (max 15 chars, alphanumeric, -, _)";
    }

    // MAC Address validation (optional but must be valid if provided)
    if (config.macAddress && !validateMACAddress(config.macAddress)) {
      errors.macAddress = "Invalid MAC address format (e.g., 00:16:3e:7f:ae:93)";
    }

    // Gateway validation
    if (!config.gateway.trim()) {
      errors.gateway = "Gateway is required";
    } else if (!validateIPAddress(config.gateway)) {
      errors.gateway = "Invalid gateway IP address";
    }

    // DNS validation
    if (config.dns && !validateDNSServers(config.dns)) {
      errors.dns = "Invalid DNS server addresses";
    }

    // IPv6 validation when enabled
    if (config.enableIPv6) {
      if (!config.ipv6Address.trim()) {
        errors.ipv6Address = "IPv6 address is required when IPv6 is enabled";
      } else if (!validateIPv6Address(config.ipv6Address)) {
        errors.ipv6Address = "Invalid IPv6 address format";
      }

      if (!config.ipv6Prefix.trim()) {
        errors.ipv6Prefix = "IPv6 prefix is required when IPv6 is enabled";
      } else if (!validateIPv6Prefix(config.ipv6Prefix)) {
        errors.ipv6Prefix = "Invalid IPv6 prefix (must be 1-128)";
      }

      if (!config.ipv6Gateway.trim()) {
        errors.ipv6Gateway = "IPv6 gateway is required when IPv6 is enabled";
      } else if (!validateIPv6Address(config.ipv6Gateway)) {
        errors.ipv6Gateway = "Invalid IPv6 gateway address";
      }
    }

    // Bonding validation
    if (config.enableBonding) {
      if (!config.bondName.trim()) {
        errors.bondName = "Bond name is required when bonding is enabled";
      } else if (!validateInterfaceName(config.bondName)) {
        errors.bondName = "Invalid bond name (max 15 chars, alphanumeric, -, _)";
      }

      if (!config.bondSlaves.trim()) {
        errors.bondSlaves = "At least two slave interfaces are required for bonding";
      } else {
        const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
        if (slaves.length < 2) {
          errors.bondSlaves = "At least two slave interfaces are required";
        } else if (!slaves.every(validateInterfaceName)) {
          errors.bondSlaves = "Invalid interface names in bond slaves";
        }
      }
    } else {
      // Interface validation when not bonding
      if (!config.interfaces.trim()) {
        errors.interfaces = "At least one interface is required";
      } else {
        const ifaces = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
        if (ifaces.length === 0) {
          errors.interfaces = "At least one interface is required";
        } else if (!ifaces.every(validateInterfaceName)) {
          errors.interfaces = "Invalid interface names";
        }
      }
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

  const getCommandSections = () => {
    const commands = generateCommands(config);
    const marker = '---DNS_SECTION---';
    if (commands.includes(marker)) {
      const [bridge, dns] = commands.split(marker);
      return { bridge: bridge.trimEnd(), dns: dns.trim() };
    }
    return { bridge: commands, dns: '' };
  };

  const handleCopy = async () => {
    if (!validateForm()) {
      toast.error("Please fix validation errors first");
      return;
    }

    const { bridge } = getCommandSections();
    const commandsWithoutComments = bridge
      .split('\n')
      .filter(line => !line.trim().startsWith('#'))
      .join('\n')
      .trim();
    
    await navigator.clipboard.writeText(commandsWithoutComments);
    setCopied(true);
    toast.success("Bridge commands copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const [dnsCopied, setDnsCopied] = useState(false);
  const handleCopyDns = async () => {
    if (!validateForm()) {
      toast.error("Please fix validation errors first");
      return;
    }

    const { dns } = getCommandSections();
    const commandsWithoutComments = dns
      .split('\n')
      .filter(line => !line.trim().startsWith('#'))
      .join('\n')
      .trim();
    
    await navigator.clipboard.writeText(commandsWithoutComments);
    setDnsCopied(true);
    toast.success("DNS commands copied to clipboard!");
    setTimeout(() => setDnsCopied(false), 2000);
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
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold text-foreground">Bridge Configuration</h2>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setConfig(getExampleConfig(config.os));
                setValidationErrors({});
                toast.success("Example configuration loaded — edit values as needed");
              }}
              className="gap-1.5 text-xs"
            >
              <Lightbulb className="w-3.5 h-3.5" />
              Load Example
            </Button>
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
              <p className="text-xs text-muted-foreground mt-1">Choose your server&apos;s operating system</p>
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
                placeholder="viifbr0"
                value={config.bridgeName}
                onChange={(e) => {
                  setConfig({ ...config, bridgeName: e.target.value });
                  validateForm();
                }}
                className={`mt-1.5 bg-background border-input ${validationErrors.bridgeName ? 'border-destructive' : ''}`}
              />
              {validationErrors.bridgeName && (
                <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                  <AlertCircle className="w-3 h-3" />
                  {validationErrors.bridgeName}
                </div>
              )}
              <p className="text-xs text-muted-foreground mt-1">Name for the bridge interface</p>
            </div>

            {/* MAC Address - Hidden for AlmaLinux */}
            {config.os !== 'almalinux' && (
              <div>
                <Label htmlFor="macAddress" className="text-foreground">
                  MAC Address
                </Label>
                <Input
                  id="macAddress"
                  placeholder="00:16:3e:7f:ae:93"
                  value={config.macAddress}
                  onChange={(e) => {
                    setConfig({ ...config, macAddress: e.target.value });
                    validateForm();
                  }}
                  className={`mt-1.5 bg-background border-input ${validationErrors.macAddress ? 'border-destructive' : ''}`}
                />
                {validationErrors.macAddress && (
                  <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                    <AlertCircle className="w-3 h-3" />
                    {validationErrors.macAddress}
                  </div>
                )}
                <p className="text-xs text-muted-foreground mt-1">Optional MAC address for the bridge</p>
              </div>
            )}

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
                    onChange={(e) => {
                      setConfig({ ...config, ipv6Address: e.target.value });
                      validateForm();
                    }}
                    className={`mt-1.5 bg-background border-input ${validationErrors.ipv6Address ? 'border-destructive' : ''}`}
                  />
                  {validationErrors.ipv6Address && (
                    <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                      <AlertCircle className="w-3 h-3" />
                      {validationErrors.ipv6Address}
                    </div>
                  )}
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
                    onChange={(e) => {
                      setConfig({ ...config, ipv6Prefix: e.target.value });
                      validateForm();
                    }}
                    className={`mt-1.5 bg-background border-input ${validationErrors.ipv6Prefix ? 'border-destructive' : ''}`}
                  />
                  {validationErrors.ipv6Prefix && (
                    <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                      <AlertCircle className="w-3 h-3" />
                      {validationErrors.ipv6Prefix}
                    </div>
                  )}
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
                    onChange={(e) => {
                      setConfig({ ...config, ipv6Gateway: e.target.value });
                      validateForm();
                    }}
                    className={`mt-1.5 bg-background border-input ${validationErrors.ipv6Gateway ? 'border-destructive' : ''}`}
                  />
                  {validationErrors.ipv6Gateway && (
                    <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                      <AlertCircle className="w-3 h-3" />
                      {validationErrors.ipv6Gateway}
                    </div>
                  )}
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
                    onChange={(e) => {
                      setConfig({ ...config, bondName: e.target.value });
                      validateForm();
                    }}
                    className={`mt-1.5 bg-background border-input ${validationErrors.bondName ? 'border-destructive' : ''}`}
                  />
                  {validationErrors.bondName && (
                    <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                      <AlertCircle className="w-3 h-3" />
                      {validationErrors.bondName}
                    </div>
                  )}
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

            {/* Extra Route - Only for AlmaLinux */}
            {config.os === 'almalinux' && (
              <div className="p-4 bg-accent/10 rounded-lg border border-accent/20">
                {!showExtraRoute ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowExtraRoute(true)}
                    className="w-full gap-2"
                  >
                    <Plus className="w-4 h-4" />
                    Add Extra Route (Gateway of separate range)
                  </Button>
                ) : (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <Label htmlFor="extraRoute" className="text-foreground font-medium">
                        Extra Route
                      </Label>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setShowExtraRoute(false);
                          setConfig({ ...config, extraRoute: "" });
                        }}
                        className="text-xs text-muted-foreground hover:text-foreground"
                      >
                        Remove
                      </Button>
                    </div>
                    <Input
                      id="extraRoute"
                      placeholder="192.168.10.10/24 192.168.1.1"
                      value={config.extraRoute || ""}
                      onChange={(e) => setConfig({ ...config, extraRoute: e.target.value })}
                      className="mt-1.5 bg-background border-input"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Use when gateway is of separate range (e.g., OVH DC). Format: destination/CIDR gateway
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* DNS */}
            <div>
              <Label htmlFor="dns" className="text-foreground">
                DNS Servers
              </Label>
              <Input
                id="dns"
                placeholder="8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844"
                value={config.dns}
                onChange={(e) => {
                  setConfig({ ...config, dns: e.target.value });
                  validateForm();
                }}
                className={`mt-1.5 bg-background border-input ${validationErrors.dns ? 'border-destructive' : ''}`}
              />
              {validationErrors.dns && (
                <div className="flex items-center gap-1 mt-1 text-destructive text-xs">
                  <AlertCircle className="w-3 h-3" />
                  {validationErrors.dns}
                </div>
              )}
              <p className="text-xs text-muted-foreground mt-1">Comma-separated DNS servers (optional)</p>
              
              {/* DNS Checkboxes */}
              <div className="flex flex-col gap-3 mt-3">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="useGoogleDNSv4" 
                    checked={config.useGoogleDNSv4}
                    onCheckedChange={(checked) => {
                      const dnsArray = config.dns.split(',').map(s => s.trim()).filter(s => s);
                      if (checked) {
                        if (!dnsArray.includes('8.8.8.8')) dnsArray.push('8.8.8.8');
                        if (!dnsArray.includes('8.8.4.4')) dnsArray.push('8.8.4.4');
                      } else {
                        const filtered = dnsArray.filter(d => d !== '8.8.8.8' && d !== '8.8.4.4');
                        setConfig({ ...config, dns: filtered.join(', '), useGoogleDNSv4: false });
                        return;
                      }
                      setConfig({ ...config, dns: dnsArray.join(', '), useGoogleDNSv4: checked as boolean });
                    }}
                  />
                  <Label 
                    htmlFor="useGoogleDNSv4" 
                    className="text-sm font-normal cursor-pointer text-foreground"
                  >
                    Use Google Public DNS (IPv4)
                  </Label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="useGoogleDNSv6" 
                    checked={config.useGoogleDNSv6}
                    onCheckedChange={(checked) => {
                      const dnsArray = config.dns.split(',').map(s => s.trim()).filter(s => s);
                      if (checked) {
                        if (!dnsArray.includes('2001:4860:4860::8888')) dnsArray.push('2001:4860:4860::8888');
                        if (!dnsArray.includes('2001:4860:4860::8844')) dnsArray.push('2001:4860:4860::8844');
                      } else {
                        const filtered = dnsArray.filter(d => d !== '2001:4860:4860::8888' && d !== '2001:4860:4860::8844');
                        setConfig({ ...config, dns: filtered.join(', '), useGoogleDNSv6: false });
                        return;
                      }
                      setConfig({ ...config, dns: dnsArray.join(', '), useGoogleDNSv6: checked as boolean });
                    }}
                  />
                  <Label 
                    htmlFor="useGoogleDNSv6" 
                    className="text-sm font-normal cursor-pointer text-foreground"
                  >
                    Use Google Public DNS (IPv6)
                  </Label>
                </div>

              </div>
            </div>
          </div>
        </Card>

        {/* Output Panel */}
        <Card className="p-6 bg-terminal-bg border-terminal-border h-fit sticky top-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-terminal-text">Bridge Commands</h2>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={handleCopy}
                className="bg-terminal-bg hover:bg-terminal-border border-terminal-border text-terminal-text"
                title="Copy bridge commands"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                <span className="ml-1 text-xs">All</span>
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
          
          <div className="bg-terminal-bg border border-terminal-border rounded-md p-4 min-h-[400px] max-h-[600px] overflow-y-auto">
            <CommandOutput commands={getCommandSections().bridge} />
          </div>

          {getCommandSections().dns && (
            <>
              <div className="flex items-center justify-between mt-6 mb-4">
                <h2 className="text-lg font-semibold text-terminal-text">Preserve DNS Settings</h2>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleCopyDns}
                  className="bg-terminal-bg hover:bg-terminal-border border-terminal-border text-terminal-text"
                  title="Copy DNS commands"
                >
                  {dnsCopied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  <span className="ml-1 text-xs">Copy</span>
                </Button>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded-md p-4 overflow-y-auto">
                <CommandOutput commands={getCommandSections().dns} />
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
};
