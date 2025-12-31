import { useMemo } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Copy, Check, FileCode } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { toast } from "sonner";
import { NetworkConfig, OSType } from "@/types/networkConfig";
import { netmaskToCIDR } from "@/utils/configParser";

interface BridgeSampleCodeProps {
  config: NetworkConfig;
}

const getOSLabel = (os: OSType): string => {
  const labels: Record<OSType, string> = {
    "centos-7": "CentOS 7",
    "almalinux": "AlmaLinux 8.x+",
    "ubuntu-16.04": "Ubuntu 16.04",
    "ubuntu-18.04-hetzner": "Ubuntu 18.04+ (Hetzner)",
    "ubuntu-18.04-other": "Ubuntu 18.04+ (Other)",
  };
  return labels[os] || os;
};

const getConfigPath = (os: OSType, bridgeName: string): string => {
  switch (os) {
    case "ubuntu-16.04":
      return "/etc/network/interfaces";
    case "ubuntu-18.04-hetzner":
    case "ubuntu-18.04-other":
      return "/etc/netplan/01-netcfg.yaml";
    case "centos-7":
      return `/etc/sysconfig/network-scripts/ifcfg-${bridgeName || "viifbr0"}`;
    case "almalinux":
      return "NetworkManager (nmcli commands)";
    default:
      return "/etc/network/interfaces";
  }
};

export const BridgeSampleCode = ({ config }: BridgeSampleCodeProps) => {
  const [copied, setCopied] = useState(false);

  const sampleCode = useMemo(() => {
    const cidr = netmaskToCIDR(config.netmask);
    const interfaces = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
    const interfaceDisplay = interfaces.length > 0 ? interfaces.join(', ') : 'eth0';
    const dnsServers = config.dns ? config.dns.split(',').map(d => d.trim()).filter(d => d) : [];
    
    switch (config.os) {
      case "ubuntu-16.04":
        return generateUbuntu1604Sample(config, interfaceDisplay, dnsServers);
      case "ubuntu-18.04-hetzner":
        return generateNetplanHetznerSample(config, cidr, interfaces, dnsServers);
      case "ubuntu-18.04-other":
        return generateNetplanOtherSample(config, cidr, interfaces, dnsServers);
      case "centos-7":
        return generateCentOS7Sample(config, dnsServers);
      case "almalinux":
        return generateAlmaLinuxSample(config, cidr, interfaces, dnsServers);
      default:
        return generateNetplanHetznerSample(config, cidr, interfaces, dnsServers);
    }
  }, [config]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(sampleCode);
    setCopied(true);
    toast.success("Sample code copied!");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="p-4 bg-accent/5 border-accent/20">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-foreground">
            Live Sample Configuration
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs">
            {getOSLabel(config.os)}
          </Badge>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleCopy}
            className="h-7 px-2"
          >
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          </Button>
        </div>
      </div>
      
      <div className="text-xs text-muted-foreground mb-2">
        Path: <code className="bg-muted px-1 rounded">{getConfigPath(config.os, config.bridgeName)}</code>
      </div>
      
      <div className="bg-terminal-bg border border-terminal-border rounded-md p-3 overflow-x-auto">
        <pre className="text-xs text-terminal-text font-mono whitespace-pre-wrap">
          {sampleCode}
        </pre>
      </div>
    </Card>
  );
};

// Ubuntu 16.04 Sample (/etc/network/interfaces format)
const generateUbuntu1604Sample = (
  config: NetworkConfig,
  interfaceDisplay: string,
  dnsServers: string[]
): string => {
  let code = `# Bridge configuration\n`;
  code += `auto ${config.bridgeName || "viifbr0"}\n`;
  code += `iface ${config.bridgeName || "viifbr0"} inet static\n`;
  code += `    bridge_ports ${interfaceDisplay}\n`;
  
  if (config.ipAddress) {
    code += `    address ${config.ipAddress}\n`;
  }
  if (config.netmask) {
    code += `    netmask ${config.netmask}\n`;
  }
  if (config.gateway) {
    code += `    gateway ${config.gateway}\n`;
  }
  
  code += `    bridge_stp off\n`;
  code += `    bridge_fd 0\n`;
  
  if (dnsServers.length > 0) {
    code += `    dns-nameservers ${dnsServers.join(' ')}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Address) {
    code += `\n# IPv6 configuration\n`;
    code += `iface ${config.bridgeName || "viifbr0"} inet6 static\n`;
    code += `    address ${config.ipv6Address}\n`;
    code += `    netmask ${config.ipv6Prefix || "64"}\n`;
    if (config.ipv6Gateway) {
      code += `    gateway ${config.ipv6Gateway}\n`;
    }
  }
  
  return code;
};

// Netplan Hetzner Sample
const generateNetplanHetznerSample = (
  config: NetworkConfig,
  cidr: number,
  interfaces: string[],
  dnsServers: string[]
): string => {
  const interfaceDisplay = interfaces.length > 0 ? interfaces : ['eth0'];
  
  let code = `network:\n`;
  code += `  version: 2\n`;
  code += `  renderer: networkd\n`;
  code += `  ethernets:\n`;
  
  interfaceDisplay.forEach(iface => {
    code += `    ${iface}:\n`;
    code += `      dhcp4: no\n`;
  });
  
  code += `  bridges:\n`;
  code += `    ${config.bridgeName || "viifbr0"}:\n`;
  
  if (config.ipAddress) {
    code += `      addresses:\n`;
    code += `        - ${config.ipAddress}/${cidr}\n`;
    
    if (config.enableIPv6 && config.ipv6Address) {
      const ipv6WithPrefix = config.ipv6Address.includes('/') 
        ? config.ipv6Address 
        : `${config.ipv6Address}/${config.ipv6Prefix || "64"}`;
      code += `        - "${ipv6WithPrefix}"\n`;
    }
  }
  
  code += `      interfaces: [ ${interfaceDisplay.join(', ')} ]\n`;
  
  if (config.gateway) {
    code += `      routes:\n`;
    code += `        - on-link: true\n`;
    code += `          to: 0.0.0.0/0\n`;
    code += `          via: ${config.gateway}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Gateway) {
    code += `      gateway6: ${config.ipv6Gateway}\n`;
  }
  
  if (config.macAddress) {
    code += `      macaddress: ${config.macAddress}\n`;
  }
  
  if (dnsServers.length > 0) {
    code += `      nameservers:\n`;
    code += `         addresses:\n`;
    dnsServers.forEach(dns => {
      code += `           - ${dns}\n`;
    });
  }
  
  return code;
};

// Netplan Other Providers Sample
const generateNetplanOtherSample = (
  config: NetworkConfig,
  cidr: number,
  interfaces: string[],
  dnsServers: string[]
): string => {
  const interfaceDisplay = interfaces.length > 0 ? interfaces : ['eth0'];
  
  let code = `network:\n`;
  code += `  version: 2\n`;
  code += `  ethernets:\n`;
  
  interfaceDisplay.forEach(iface => {
    code += `    ${iface}:\n`;
    code += `      dhcp4: false\n`;
    code += `      dhcp6: false\n`;
  });
  
  code += `  bridges:\n`;
  code += `    ${config.bridgeName || "viifbr0"}:\n`;
  
  if (config.ipAddress) {
    code += `      addresses:\n`;
    code += `        - ${config.ipAddress}/${cidr}\n`;
    
    if (config.enableIPv6 && config.ipv6Address) {
      const ipv6WithPrefix = config.ipv6Address.includes('/') 
        ? config.ipv6Address 
        : `${config.ipv6Address}/${config.ipv6Prefix || "64"}`;
      code += `        - "${ipv6WithPrefix}"\n`;
    }
  }
  
  code += `      interfaces: [ ${interfaceDisplay.join(', ')} ]\n`;
  
  if (config.gateway) {
    code += `      routes:\n`;
    code += `        - to: 0.0.0.0/0\n`;
    code += `          via: ${config.gateway}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Gateway) {
    if (!config.gateway) {
      code += `      routes:\n`;
    }
    code += `        - to: ::/0\n`;
    code += `          via: ${config.ipv6Gateway}\n`;
  }
  
  if (config.macAddress) {
    code += `      macaddress: ${config.macAddress}\n`;
  }
  
  if (dnsServers.length > 0) {
    code += `      nameservers:\n`;
    code += `        addresses:\n`;
    dnsServers.forEach(dns => {
      code += `          - ${dns}\n`;
    });
  }
  
  return code;
};

// CentOS 7 Sample (ifcfg format)
const generateCentOS7Sample = (
  config: NetworkConfig,
  dnsServers: string[]
): string => {
  let code = `DEVICE=${config.bridgeName || "viifbr0"}\n`;
  code += `TYPE=Bridge\n`;
  code += `BOOTPROTO=static\n`;
  
  if (config.ipAddress) {
    code += `IPADDR=${config.ipAddress}\n`;
  }
  if (config.netmask) {
    code += `NETMASK=${config.netmask}\n`;
  }
  if (config.gateway) {
    code += `GATEWAY=${config.gateway}\n`;
  }
  
  dnsServers.forEach((dns, idx) => {
    code += `DNS${idx + 1}=${dns}\n`;
  });
  
  code += `ONBOOT=yes\n`;
  code += `DELAY=0\n`;
  
  if (config.enableIPv6 && config.ipv6Address) {
    code += `IPV6INIT=yes\n`;
    code += `IPV6ADDR=${config.ipv6Address}/${config.ipv6Prefix || "64"}\n`;
    if (config.ipv6Gateway) {
      code += `IPV6_DEFAULTGW=${config.ipv6Gateway}\n`;
    }
  }
  
  return code;
};

// AlmaLinux Sample (nmcli commands)
const generateAlmaLinuxSample = (
  config: NetworkConfig,
  cidr: number,
  interfaces: string[],
  dnsServers: string[]
): string => {
  const dnsString = dnsServers.length > 0 ? dnsServers.join(' ') : '8.8.8.8';
  
  let code = `# Create bridge\n`;
  code += `nmcli connection add type bridge con-name ${config.bridgeName || "viifbr0"} ifname ${config.bridgeName || "viifbr0"}\n\n`;
  
  code += `# Disable STP\n`;
  code += `nmcli connection modify ${config.bridgeName || "viifbr0"} bridge.stp no\n\n`;
  
  code += `# Configure IPv4\n`;
  code += `nmcli connection modify ${config.bridgeName || "viifbr0"} ipv4.addresses '${config.ipAddress || "192.168.1.1"}/${cidr}'`;
  
  if (config.gateway) {
    code += ` ipv4.gateway '${config.gateway}'`;
  }
  
  code += ` ipv4.dns '${dnsString}' ipv4.method manual\n`;
  
  if (config.extraRoute) {
    code += `\n# Extra route\n`;
    code += `nmcli connection modify ${config.bridgeName || "viifbr0"} +ipv4.routes "${config.extraRoute}"\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Address) {
    code += `\n# Configure IPv6\n`;
    code += `nmcli connection modify ${config.bridgeName || "viifbr0"} ipv6.addresses '${config.ipv6Address}/${config.ipv6Prefix || "64"}'`;
    if (config.ipv6Gateway) {
      code += ` ipv6.gateway '${config.ipv6Gateway}'`;
    }
    code += ` ipv6.method manual\n`;
  }
  
  if (interfaces.length > 0) {
    code += `\n# Add interfaces to bridge\n`;
    interfaces.forEach(iface => {
      code += `nmcli connection modify ${iface} master ${config.bridgeName || "viifbr0"}\n`;
    });
  }
  
  code += `\n# Bring up connection\n`;
  code += `nmcli connection up ${config.bridgeName || "viifbr0"}\n`;
  
  return code;
};
