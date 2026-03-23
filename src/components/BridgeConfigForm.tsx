import { useState } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Copy, Download, Terminal, Check, AlertCircle, Plus, Lightbulb, Globe, Router, Waypoints } from "lucide-react";
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

/* ─── Reusable field wrapper ─── */
const Field = ({
  label,
  required,
  error,
  hint,
  children,
}: {
  label: string;
  required?: boolean;
  error?: string;
  hint?: string;
  children: React.ReactNode;
}) => (
  <div className="space-y-1.5">
    <Label className="text-foreground text-sm">
      {label} {required && <span className="text-destructive">*</span>}
    </Label>
    {children}
    {error && (
      <div className="flex items-center gap-1 text-destructive text-xs">
        <AlertCircle className="w-3 h-3" />
        {error}
      </div>
    )}
    {hint && !error && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
);

/* ─── Section header inside cards ─── */
const SectionHeader = ({ icon: Icon, title, action }: { icon: any; title: string; action?: React.ReactNode }) => (
  <div className="flex items-center justify-between">
    <div className="flex items-center gap-2.5">
      <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
        <Icon className="w-4 h-4 text-primary" />
      </div>
      <h2 className="text-lg font-semibold text-foreground">{title}</h2>
    </div>
    {action}
  </div>
);

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
  const [dnsCopied, setDnsCopied] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [showExtraRoute, setShowExtraRoute] = useState(false);

  const validateForm = () => {
    const errors: Record<string, string> = {};
    if (!config.ipAddress.trim()) errors.ipAddress = "IP address is required";
    else if (!validateIPAddress(config.ipAddress)) errors.ipAddress = "Invalid IP address format";
    if (!config.netmask.trim()) errors.netmask = "Netmask is required";
    else if (!validateNetmask(config.netmask)) errors.netmask = "Invalid netmask format";
    if (!config.bridgeName.trim()) errors.bridgeName = "Bridge name is required";
    else if (!validateInterfaceName(config.bridgeName)) errors.bridgeName = "Invalid bridge name (max 15 chars, alphanumeric, -, _)";
    if (config.macAddress && !validateMACAddress(config.macAddress)) errors.macAddress = "Invalid MAC address format (e.g., 00:16:3e:7f:ae:93)";
    if (!config.gateway.trim()) errors.gateway = "Gateway is required";
    else if (!validateIPAddress(config.gateway)) errors.gateway = "Invalid gateway IP address";
    if (config.dns && !validateDNSServers(config.dns)) errors.dns = "Invalid DNS server addresses";
    if (config.enableIPv6) {
      if (!config.ipv6Address.trim()) errors.ipv6Address = "IPv6 address is required when IPv6 is enabled";
      else if (!validateIPv6Address(config.ipv6Address)) errors.ipv6Address = "Invalid IPv6 address format";
      if (!config.ipv6Prefix.trim()) errors.ipv6Prefix = "IPv6 prefix is required when IPv6 is enabled";
      else if (!validateIPv6Prefix(config.ipv6Prefix)) errors.ipv6Prefix = "Invalid IPv6 prefix (must be 1-128)";
      if (!config.ipv6Gateway.trim()) errors.ipv6Gateway = "IPv6 gateway is required when IPv6 is enabled";
      else if (!validateIPv6Address(config.ipv6Gateway)) errors.ipv6Gateway = "Invalid IPv6 gateway address";
    }
    if (config.enableBonding) {
      if (!config.bondName.trim()) errors.bondName = "Bond name is required when bonding is enabled";
      else if (!validateInterfaceName(config.bondName)) errors.bondName = "Invalid bond name (max 15 chars, alphanumeric, -, _)";
      if (!config.bondSlaves.trim()) errors.bondSlaves = "At least two slave interfaces are required for bonding";
      else {
        const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
        if (slaves.length < 2) errors.bondSlaves = "At least two slave interfaces are required";
        else if (!slaves.every(validateInterfaceName)) errors.bondSlaves = "Invalid interface names in bond slaves";
      }
    } else {
      if (!config.interfaces.trim()) errors.interfaces = "At least one interface is required";
      else {
        const ifaces = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
        if (ifaces.length === 0) errors.interfaces = "At least one interface is required";
        else if (!ifaces.every(validateInterfaceName)) errors.interfaces = "Invalid interface names";
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
    if (!validateForm()) { toast.error("Please fix validation errors first"); return; }
    const { bridge } = getCommandSections();
    const commandsOnly = bridge.split('\n').filter(l => !l.trim().startsWith('#')).join('\n').trim();
    await navigator.clipboard.writeText(commandsOnly);
    setCopied(true);
    toast.success("Bridge commands copied to clipboard!");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyDns = async () => {
    if (!validateForm()) { toast.error("Please fix validation errors first"); return; }
    const { dns } = getCommandSections();
    const commandsOnly = dns.split('\n').filter(l => !l.trim().startsWith('#')).join('\n').trim();
    await navigator.clipboard.writeText(commandsOnly);
    setDnsCopied(true);
    toast.success("DNS commands copied to clipboard!");
    setTimeout(() => setDnsCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!validateForm()) { toast.error("Please fix validation errors first"); return; }
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

  const updateDns = (checked: boolean | string, v4Addrs: string[], v6Addrs: string[], key: keyof NetworkConfig) => {
    const dnsArray = config.dns.split(',').map(s => s.trim()).filter(s => s);
    const addrs = [...v4Addrs, ...v6Addrs];
    if (checked) {
      addrs.forEach(a => { if (!dnsArray.includes(a)) dnsArray.push(a); });
    } else {
      const filtered = dnsArray.filter(d => !addrs.includes(d));
      setConfig({ ...config, dns: filtered.join(', '), [key]: false });
      return;
    }
    setConfig({ ...config, dns: dnsArray.join(', '), [key]: checked as boolean });
  };

  return (
    <div className="space-y-6">
      {/* Config Parser - Collapsible */}
      <NetworkConfigParser onParsed={handleParsedConfig} />

      <div className="grid lg:grid-cols-5 gap-6">
        {/* ─── Left: Configuration Panel (3 cols) ─── */}
        <div className="lg:col-span-3 space-y-5">
          <Card className="overflow-hidden border-border">
            <CardHeader className="bg-card pb-4">
              <SectionHeader
                icon={Terminal}
                title="Bridge Configuration"
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setConfig(getExampleConfig(config.os));
                      setValidationErrors({});
                      toast.success("Example loaded — edit values as needed");
                    }}
                    className="gap-1.5 text-xs"
                  >
                    <Lightbulb className="w-3.5 h-3.5" />
                    Load Example
                  </Button>
                }
              />
            </CardHeader>
            <CardContent className="pt-2">
              <Tabs defaultValue="network" className="w-full">
                <TabsList className="grid w-full grid-cols-3 mb-6">
                  <TabsTrigger value="network" className="text-xs sm:text-sm gap-1.5">
                    <Globe className="w-3.5 h-3.5 hidden sm:block" /> Network
                  </TabsTrigger>
                  <TabsTrigger value="advanced" className="text-xs sm:text-sm gap-1.5">
                    <Waypoints className="w-3.5 h-3.5 hidden sm:block" /> Advanced
                  </TabsTrigger>
                  <TabsTrigger value="dns" className="text-xs sm:text-sm gap-1.5">
                    <Router className="w-3.5 h-3.5 hidden sm:block" /> DNS
                  </TabsTrigger>
                </TabsList>

                {/* ── Tab: Network ── */}
                <TabsContent value="network" className="space-y-5 mt-0">
                  {/* OS Selection */}
                  <Field label="Operating System" required hint="Choose your server's distribution">
                    <Select value={config.os} onValueChange={(value: any) => setConfig({ ...config, os: value })}>
                      <SelectTrigger className="bg-background border-input">
                        <SelectValue placeholder="Select OS" />
                      </SelectTrigger>
                      <SelectContent className="bg-popover border-border z-50">
                        {OS_OPTIONS.map(opt => (
                          <SelectItem key={opt.value} value={opt.value} className="hover:bg-accent">{opt.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>

                  <div className="grid sm:grid-cols-2 gap-4">
                    <Field label="IP Address" required error={validationErrors.ipAddress} hint="IPv4 address for the bridge">
                      <Input
                        placeholder="192.168.10.10"
                        value={config.ipAddress}
                        onChange={(e) => { setConfig({ ...config, ipAddress: e.target.value }); validateForm(); }}
                        className={`bg-background border-input ${validationErrors.ipAddress ? 'border-destructive' : ''}`}
                      />
                    </Field>
                    <Field label="Gateway" required error={validationErrors.gateway} hint="Default gateway for routing">
                      <Input
                        placeholder="192.168.10.1"
                        value={config.gateway}
                        onChange={(e) => { setConfig({ ...config, gateway: e.target.value }); validateForm(); }}
                        className={`bg-background border-input ${validationErrors.gateway ? 'border-destructive' : ''}`}
                      />
                    </Field>
                  </div>

                  <div className="grid sm:grid-cols-2 gap-4">
                    <Field label="Netmask" required error={validationErrors.netmask} hint="Network mask for your subnet">
                      <Select value={config.netmask} onValueChange={(v) => setConfig({ ...config, netmask: v })}>
                        <SelectTrigger className="bg-background border-input">
                          <SelectValue placeholder="Select netmask" />
                        </SelectTrigger>
                        <SelectContent className="bg-popover border-border z-50">
                          {NETMASK_OPTIONS.map(opt => (
                            <SelectItem key={opt.value} value={opt.value} className="hover:bg-accent">{opt.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field label="Bridge Name" required error={validationErrors.bridgeName} hint="Name for the bridge interface">
                      <Input
                        placeholder="viifbr0"
                        value={config.bridgeName}
                        onChange={(e) => { setConfig({ ...config, bridgeName: e.target.value }); validateForm(); }}
                        className={`bg-background border-input ${validationErrors.bridgeName ? 'border-destructive' : ''}`}
                      />
                    </Field>
                  </div>

                  {config.os !== 'almalinux' && (
                    <Field label="MAC Address" error={validationErrors.macAddress} hint="Optional MAC address for the bridge">
                      <Input
                        placeholder="00:16:3e:7f:ae:93"
                        value={config.macAddress}
                        onChange={(e) => { setConfig({ ...config, macAddress: e.target.value }); validateForm(); }}
                        className={`bg-background border-input ${validationErrors.macAddress ? 'border-destructive' : ''}`}
                      />
                    </Field>
                  )}

                  {/* Interfaces / Bonding */}
                  {config.enableBonding ? (
                    <div className="space-y-4">
                      <div className="grid sm:grid-cols-2 gap-4">
                        <Field label="Bond Name" required error={validationErrors.bondName}>
                          <Input
                            placeholder="bond0"
                            value={config.bondName}
                            onChange={(e) => { setConfig({ ...config, bondName: e.target.value }); validateForm(); }}
                            className={`bg-background border-input ${validationErrors.bondName ? 'border-destructive' : ''}`}
                          />
                        </Field>
                        <Field label="Bond Mode" required>
                          <Select value={config.bondMode} onValueChange={(v: any) => setConfig({ ...config, bondMode: v })}>
                            <SelectTrigger className="bg-background border-input"><SelectValue /></SelectTrigger>
                            <SelectContent className="bg-popover border-border z-50">
                              <SelectItem value="mode-1" className="hover:bg-accent">Mode 1 (Active-Backup)</SelectItem>
                              <SelectItem value="mode-4" className="hover:bg-accent">Mode 4 (802.3ad LACP)</SelectItem>
                            </SelectContent>
                          </Select>
                        </Field>
                      </div>
                      <Field label="Bond Slave Interfaces" required error={validationErrors.bondSlaves} hint="Comma-separated physical interfaces">
                        <Input
                          placeholder="eth0, eth1"
                          value={config.bondSlaves}
                          onChange={(e) => { setConfig({ ...config, bondSlaves: e.target.value }); validateForm(); }}
                          className={`bg-background border-input ${validationErrors.bondSlaves ? 'border-destructive' : ''}`}
                        />
                      </Field>
                    </div>
                  ) : (
                    <Field label="Physical Interfaces" required error={validationErrors.interfaces} hint="Comma-separated list of interfaces">
                      <Input
                        placeholder="eth0, eth1"
                        value={config.interfaces}
                        onChange={(e) => { setConfig({ ...config, interfaces: e.target.value }); validateForm(); }}
                        className={`bg-background border-input ${validationErrors.interfaces ? 'border-destructive' : ''}`}
                      />
                    </Field>
                  )}

                  {/* Extra Route - AlmaLinux only */}
                  {config.os === 'almalinux' && (
                    <div className="p-4 rounded-xl bg-accent/5 border border-accent/15">
                      {!showExtraRoute ? (
                        <Button variant="outline" size="sm" onClick={() => setShowExtraRoute(true)} className="w-full gap-2">
                          <Plus className="w-4 h-4" /> Add Extra Route (Gateway of separate range)
                        </Button>
                      ) : (
                        <Field label="Extra Route" hint="Use when gateway is of separate range (e.g., OVH DC). Format: destination/CIDR gateway">
                          <div className="flex gap-2">
                            <Input
                              placeholder="192.168.10.10/24 192.168.1.1"
                              value={config.extraRoute || ""}
                              onChange={(e) => setConfig({ ...config, extraRoute: e.target.value })}
                              className="bg-background border-input flex-1"
                            />
                            <Button variant="ghost" size="sm" onClick={() => { setShowExtraRoute(false); setConfig({ ...config, extraRoute: "" }); }} className="text-muted-foreground hover:text-foreground shrink-0">Remove</Button>
                          </div>
                        </Field>
                      )}
                    </div>
                  )}
                </TabsContent>

                {/* ── Tab: Advanced ── */}
                <TabsContent value="advanced" className="space-y-5 mt-0">
                  {/* IPv6 Toggle */}
                  <div className="flex items-center justify-between p-4 rounded-xl bg-accent/5 border border-accent/15">
                    <div>
                      <Label className="text-foreground font-medium">Enable IPv6</Label>
                      <p className="text-xs text-muted-foreground mt-0.5">Configure dual-stack networking</p>
                    </div>
                    <Switch
                      checked={config.enableIPv6}
                      onCheckedChange={(checked) =>
                        setConfig({
                          ...config,
                          enableIPv6: checked,
                          dns: checked ? "8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844" : "8.8.8.8,8.8.4.4",
                        })
                      }
                    />
                  </div>

                  {config.enableIPv6 && (
                    <div className="space-y-4 pl-4 border-l-2 border-accent/30">
                      <Field label="IPv6 Address" required error={validationErrors.ipv6Address} hint="IPv6 address for the bridge">
                        <Input
                          placeholder="2001:db8::1"
                          value={config.ipv6Address}
                          onChange={(e) => { setConfig({ ...config, ipv6Address: e.target.value }); validateForm(); }}
                          className={`bg-background border-input ${validationErrors.ipv6Address ? 'border-destructive' : ''}`}
                        />
                      </Field>
                      <div className="grid sm:grid-cols-2 gap-4">
                        <Field label="IPv6 Prefix Length" required error={validationErrors.ipv6Prefix} hint="Typically 64 for most networks">
                          <Input
                            placeholder="64"
                            value={config.ipv6Prefix}
                            onChange={(e) => { setConfig({ ...config, ipv6Prefix: e.target.value }); validateForm(); }}
                            className={`bg-background border-input ${validationErrors.ipv6Prefix ? 'border-destructive' : ''}`}
                          />
                        </Field>
                        <Field label="IPv6 Gateway" required error={validationErrors.ipv6Gateway} hint="Default IPv6 gateway">
                          <Input
                            placeholder="2001:db8::1"
                            value={config.ipv6Gateway}
                            onChange={(e) => { setConfig({ ...config, ipv6Gateway: e.target.value }); validateForm(); }}
                            className={`bg-background border-input ${validationErrors.ipv6Gateway ? 'border-destructive' : ''}`}
                          />
                        </Field>
                      </div>
                    </div>
                  )}

                  {/* Bonding Toggle */}
                  <div className="flex items-center justify-between p-4 rounded-xl bg-accent/5 border border-accent/15">
                    <div>
                      <Label className="text-foreground font-medium">Enable Network Bonding</Label>
                      <p className="text-xs text-muted-foreground mt-0.5">Bond multiple interfaces for redundancy</p>
                    </div>
                    <Switch
                      checked={config.enableBonding}
                      onCheckedChange={(checked) => setConfig({ ...config, enableBonding: checked })}
                    />
                  </div>
                </TabsContent>

                {/* ── Tab: DNS ── */}
                <TabsContent value="dns" className="space-y-5 mt-0">
                  <Field label="DNS Servers" error={validationErrors.dns} hint="Comma-separated DNS servers (optional)">
                    <Input
                      placeholder="8.8.8.8, 8.8.4.4"
                      value={config.dns}
                      onChange={(e) => { setConfig({ ...config, dns: e.target.value }); validateForm(); }}
                      className={`bg-background border-input ${validationErrors.dns ? 'border-destructive' : ''}`}
                    />
                  </Field>

                  <div className="grid sm:grid-cols-2 gap-3">
                    {[
                      { id: "useGoogleDNSv4", label: "Google DNS (IPv4)", addrs: ['8.8.8.8', '8.8.4.4'], v6: false },
                      { id: "useGoogleDNSv6", label: "Google DNS (IPv6)", addrs: ['2001:4860:4860::8888', '2001:4860:4860::8844'], v6: true },
                      { id: "useCloudflareDNSv4", label: "Cloudflare DNS (IPv4)", addrs: ['1.1.1.1', '1.0.0.1'], v6: false },
                      { id: "useCloudflareDNSv6", label: "Cloudflare DNS (IPv6)", addrs: ['2606:4700:4700::1111', '2606:4700:4700::1001'], v6: true },
                      { id: "useOpenDNSv4", label: "OpenDNS (IPv4)", addrs: ['208.67.222.222', '208.67.220.220'], v6: false },
                      { id: "useOpenDNSv6", label: "OpenDNS (IPv6)", addrs: ['2620:119:35::35', '2620:119:53::53'], v6: true },
                      { id: "useQuad9DNSv4", label: "Quad9 DNS (IPv4)", addrs: ['9.9.9.9', '149.112.112.112'], v6: false },
                      { id: "useQuad9DNSv6", label: "Quad9 DNS (IPv6)", addrs: ['2620:fe::fe', '2620:fe::9'], v6: true },
                    ].map(({ id, label, addrs, v6 }) => (
                      <div key={id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/40 border border-border/50 hover:bg-muted/60 transition-colors">
                        <Checkbox
                          id={id}
                          checked={config[id as keyof NetworkConfig] as boolean}
                          onCheckedChange={(checked) =>
                            updateDns(checked, v6 ? [] : addrs, v6 ? addrs : [], id as keyof NetworkConfig)
                          }
                        />
                        <Label htmlFor={id} className="text-sm font-normal cursor-pointer text-foreground flex-1">
                          {label}
                        </Label>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>

        {/* ─── Right: Output Panel (2 cols) ─── */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="border-terminal-border bg-terminal-bg sticky top-6 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-terminal-border">
              <div className="flex items-center gap-2.5">
                {/* Fake traffic lights */}
                <div className="flex gap-1.5">
                  <span className="w-3 h-3 rounded-full bg-destructive/70" />
                  <span className="w-3 h-3 rounded-full bg-[hsl(45,90%,50%)]/70" />
                  <span className="w-3 h-3 rounded-full bg-[hsl(var(--success))]/70" />
                </div>
                <h2 className="text-sm font-semibold text-terminal-text font-mono">bridge-commands.sh</h2>
              </div>
              <div className="flex gap-1.5">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={handleCopy}
                  className="h-7 px-2 text-terminal-text hover:bg-terminal-border/50"
                  title="Copy bridge commands"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span className="ml-1 text-[10px] font-mono">COPY</span>
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={handleDownload}
                  className="h-7 px-2 text-terminal-text hover:bg-terminal-border/50"
                  title="Download script"
                >
                  <Download className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>

            <div className="p-4 min-h-[400px] max-h-[600px] overflow-y-auto">
              <CommandOutput commands={getCommandSections().bridge} />
            </div>

            {getCommandSections().dns && (
              <>
                <div className="flex items-center justify-between px-5 py-3 border-t border-terminal-border">
                  <h2 className="text-sm font-semibold text-terminal-text font-mono">dns-config.sh</h2>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={handleCopyDns}
                    className="h-7 px-2 text-terminal-text hover:bg-terminal-border/50"
                  >
                    {dnsCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span className="ml-1 text-[10px] font-mono">COPY</span>
                  </Button>
                </div>
                <div className="p-4 border-t border-terminal-border/50 overflow-y-auto">
                  <CommandOutput commands={getCommandSections().dns} />
                </div>
              </>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};
