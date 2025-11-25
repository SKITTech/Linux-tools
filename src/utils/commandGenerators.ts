import { NetworkConfig, OSType } from "@/types/networkConfig";
import { netmaskToCIDR } from "./configParser";

export const generateCommands = (config: NetworkConfig): string => {
  const { os } = config;
  
  if (!config.ipAddress || !config.netmask || !config.bridgeName) {
    return "# Please fill in all required fields (IP Address, Netmask, Bridge Name)";
  }
  
  switch (os) {
    case "ubuntu-16.04":
      return generateUbuntu1604(config);
    case "ubuntu-18.04-hetzner":
      return generateUbuntu1804Hetzner(config);
    case "ubuntu-18.04-other":
      return generateUbuntu1804Other(config);
    case "centos-7":
      return generateCentOS7(config);
    case "almalinux":
      return generateAlmaLinux(config);
    default:
      return generateGenericLinux(config);
  }
};

const generateUbuntu1604 = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  const interfaceList = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
  
  let commands = `# Ubuntu 16.04 - Bridge Configuration (/etc/network/interfaces)\n\n`;
  commands += `# Backup current configuration\n`;
  commands += `sudo cp /etc/network/interfaces /etc/network/interfaces.backup\n\n`;
  commands += `# Install bridge utilities\n`;
  commands += `sudo apt-get update\n`;
  commands += `sudo apt-get install -y bridge-utils\n\n`;
  
  commands += `cat << 'EOF' >> /etc/network/interfaces\n\n`;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `# Bond configuration\n`;
    commands += `auto ${config.bondName}\n`;
    commands += `iface ${config.bondName} inet manual\n`;
    commands += `    bond-mode ${config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad'}\n`;
    commands += `    bond-miimon 100\n`;
    commands += `    bond-slaves ${slaves.join(' ')}\n\n`;
    
    commands += `# Bridge configuration\n`;
    commands += `auto ${config.bridgeName}\n`;
    commands += `iface ${config.bridgeName} inet static\n`;
    commands += `    bridge_ports ${config.bondName}\n`;
  } else {
    commands += `# Bridge configuration\n`;
    commands += `auto ${config.bridgeName}\n`;
    commands += `iface ${config.bridgeName} inet static\n`;
    commands += `    bridge_ports ${interfaceList.join(' ')}\n`;
  }
  
  commands += `    address ${config.ipAddress}\n`;
  commands += `    netmask ${config.netmask}\n`;
  if (config.gateway) {
    commands += `    gateway ${config.gateway}\n`;
  }
  commands += `    bridge_stp off\n`;
  commands += `    bridge_fd 0\n`;
  if (config.dns) {
    const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d);
    commands += `    dns-nameservers ${dnsServers.join(' ')}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Address) {
    commands += `\n# IPv6 configuration\n`;
    commands += `iface ${config.bridgeName} inet6 static\n`;
    commands += `    address ${config.ipv6Address}\n`;
    commands += `    netmask ${config.ipv6Prefix}\n`;
    if (config.ipv6Gateway) {
      commands += `    gateway ${config.ipv6Gateway}\n`;
    }
  }
  
  commands += `EOF\n\n`;
  commands += `# Restart networking\n`;
  commands += `sudo systemctl restart networking\n`;
  
  return commands;
};

const generateUbuntu1804Hetzner = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  let commands = ``;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  renderer: networkd\n`;
    commands += `  ethernets:\n`;
    slaves.forEach(slave => {
      commands += `    ${slave}:\n`;
      commands += `      dhcp4: no\n`;
    });
    commands += `  bonds:\n`;
    commands += `    ${config.bondName}:\n`;
    commands += `      interfaces: [${slaves.join(', ')}]\n`;
    commands += `      parameters:\n`;
    commands += `        mode: ${config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad'}\n`;
    commands += `        mii-monitor-interval: 100\n`;
    if (config.bondMode === 'mode-4') {
      commands += `        lacp-rate: fast\n`;
    }
    commands += `  bridges:\n`;
    commands += `    ${config.bridgeName}:\n`;
    commands += `      interfaces: [${config.bondName}]\n`;
  } else {
    const interfaces = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  renderer: networkd\n`;
    commands += `  ethernets:\n`;
    interfaces.forEach(iface => {
      commands += `    ${iface}:\n`;
      commands += `      dhcp4: no\n`;
    });
    commands += `  bridges:\n`;
    commands += `    ${config.bridgeName}:\n`;
    commands += `      interfaces: [${interfaces.join(', ')}]\n`;
  }
  
  commands += `      addresses:\n`;
  commands += `        - ${config.ipAddress}/${cidr}\n`;
  if (config.enableIPv6 && config.ipv6Address) {
    commands += `        - "${config.ipv6Address}/${config.ipv6Prefix}"\n`;
  }
  
  if (config.gateway) {
    commands += `      routes:\n`;
    commands += `        - on-link: true\n`;
    commands += `          to: 0.0.0.0/0\n`;
    commands += `          via: ${config.gateway}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Gateway) {
    commands += `      gateway6: ${config.ipv6Gateway}\n`;
  }
  
  if (config.macAddress) {
    commands += `      macaddress: ${config.macAddress}\n`;
  }
  
  if (config.dns) {
    const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d);
    commands += `      nameservers:\n`;
    commands += `         addresses:\n`;
    dnsServers.forEach(dns => {
      commands += `           - ${dns}\n`;
    });
  }
  
  return commands;
};

const generateUbuntu1804Other = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  let commands = ``;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  ethernets:\n`;
    slaves.forEach(slave => {
      commands += `    ${slave}:\n`;
      commands += `      dhcp4: false\n`;
      commands += `      dhcp6: false\n`;
    });
    commands += `  bonds:\n`;
    commands += `    ${config.bondName}:\n`;
    commands += `      interfaces: [${slaves.join(', ')}]\n`;
    commands += `      parameters:\n`;
    commands += `        mode: ${config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad'}\n`;
    commands += `        mii-monitor-interval: 100\n`;
    if (config.bondMode === 'mode-4') {
      commands += `        lacp-rate: fast\n`;
    }
    commands += `  bridges:\n`;
    commands += `    ${config.bridgeName}:\n`;
    commands += `      interfaces: [${config.bondName}]\n`;
  } else {
    const interfaces = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  ethernets:\n`;
    interfaces.forEach(iface => {
      commands += `    ${iface}:\n`;
      commands += `      dhcp4: false\n`;
      commands += `      dhcp6: false\n`;
    });
    commands += `  bridges:\n`;
    commands += `    ${config.bridgeName}:\n`;
    commands += `      interfaces: [${interfaces.join(', ')}]\n`;
  }
  
  commands += `      addresses:\n`;
  commands += `        - ${config.ipAddress}/${cidr}\n`;
  if (config.enableIPv6 && config.ipv6Address) {
    commands += `        - "${config.ipv6Address}/${config.ipv6Prefix}"\n`;
  }
  
  if (config.gateway) {
    commands += `      routes:\n`;
    commands += `        - to: 0.0.0.0/0\n`;
    commands += `          via: ${config.gateway}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Gateway) {
    if (!config.gateway) {
      commands += `      routes:\n`;
    }
    commands += `        - to: ::/0\n`;
    commands += `          via: ${config.ipv6Gateway}\n`;
  }
  
  if (config.macAddress) {
    commands += `      macaddress: ${config.macAddress}\n`;
  }
  
  if (config.dns) {
    const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d);
    commands += `      nameservers:\n`;
    commands += `        addresses:\n`;
    dnsServers.forEach(dns => {
      commands += `          - ${dns}\n`;
    });
  }
  
  return commands;
};



const generateCentOS7 = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  const interfaceList = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
  
  let commands = `# CentOS 7 - Bridge Configuration\n\n`;
  commands += `# Install bridge utilities\n`;
  commands += `sudo yum install -y bridge-utils\n\n`;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `# Create bonding configuration\n`;
    commands += `cat << 'EOF' > /etc/sysconfig/network-scripts/ifcfg-${config.bondName}\n`;
    commands += `DEVICE=${config.bondName}\n`;
    commands += `TYPE=Bond\n`;
    commands += `BONDING_MASTER=yes\n`;
    commands += `BONDING_OPTS="mode=${config.bondMode === 'mode-1' ? '1' : '4'} miimon=100"\n`;
    commands += `BRIDGE=${config.bridgeName}\n`;
    commands += `ONBOOT=yes\n`;
    commands += `EOF\n\n`;
    
    slaves.forEach((slave, idx) => {
      commands += `# Configure slave ${idx + 1}\n`;
      commands += `cat << 'EOF' > /etc/sysconfig/network-scripts/ifcfg-${slave}\n`;
      commands += `DEVICE=${slave}\n`;
      commands += `TYPE=Ethernet\n`;
      commands += `BOOTPROTO=none\n`;
      commands += `ONBOOT=yes\n`;
      commands += `MASTER=${config.bondName}\n`;
      commands += `SLAVE=yes\n`;
      commands += `EOF\n\n`;
    });
  }
  
  commands += `# Create bridge configuration\n`;
  commands += `cat << 'EOF' > /etc/sysconfig/network-scripts/ifcfg-${config.bridgeName}\n`;
  commands += `DEVICE=${config.bridgeName}\n`;
  commands += `TYPE=Bridge\n`;
  commands += `BOOTPROTO=static\n`;
  commands += `IPADDR=${config.ipAddress}\n`;
  commands += `NETMASK=${config.netmask}\n`;
  if (config.gateway) {
    commands += `GATEWAY=${config.gateway}\n`;
  }
  if (config.dns) {
    const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d);
    dnsServers.forEach((dns, idx) => {
      commands += `DNS${idx + 1}=${dns}\n`;
    });
  }
  commands += `ONBOOT=yes\n`;
  commands += `DELAY=0\n`;
  if (config.enableIPv6 && config.ipv6Address) {
    commands += `IPV6INIT=yes\n`;
    commands += `IPV6ADDR=${config.ipv6Address}/${config.ipv6Prefix}\n`;
    if (config.ipv6Gateway) {
      commands += `IPV6_DEFAULTGW=${config.ipv6Gateway}\n`;
    }
  }
  commands += `EOF\n\n`;
  
  if (!config.enableBonding && interfaceList.length > 0) {
    interfaceList.forEach(iface => {
      commands += `# Configure ${iface}\n`;
      commands += `cat << 'EOF' > /etc/sysconfig/network-scripts/ifcfg-${iface}\n`;
      commands += `DEVICE=${iface}\n`;
      commands += `TYPE=Ethernet\n`;
      commands += `BOOTPROTO=none\n`;
      commands += `ONBOOT=yes\n`;
      commands += `BRIDGE=${config.bridgeName}\n`;
      commands += `EOF\n\n`;
    });
  }
  
  commands += `# Restart network\n`;
  commands += `sudo systemctl restart network\n`;
  
  return commands;
};

const generateAlmaLinux = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  const interfaceList = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
  
  let commands = `# AlmaLinux - Bridge Configuration using NetworkManager\n\n`;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    const bondMode = config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad';
    
    commands += `# Create bond interface\n`;
    commands += `sudo nmcli connection add type bond con-name ${config.bondName} ifname ${config.bondName} mode ${bondMode}\n\n`;
    
    commands += `# Add slave interfaces to bond\n`;
    slaves.forEach((slave, idx) => {
      commands += `sudo nmcli connection add type ethernet slave-type bond con-name ${config.bondName}-slave${idx + 1} ifname ${slave} master ${config.bondName}\n`;
    });
    
    commands += `\n# Create bridge\n`;
    commands += `sudo nmcli connection add type bridge con-name ${config.bridgeName} ifname ${config.bridgeName}\n\n`;
    
    commands += `# Disable STP (if your server provider blocks ports on switch due to BPDU flooding)\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} bridge.stp no\n\n`;
    
    // IPv4 configuration
    const dnsServers = config.dns ? config.dns.split(',').map(d => d.trim()).filter(d => d).join(' ') : '8.8.8.8';
    commands += `# Configure IPv4\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.addresses '${config.ipAddress}/${cidr}'`;
    if (config.gateway) {
      commands += ` ipv4.gateway '${config.gateway}'`;
    }
    commands += ` ipv4.dns '${dnsServers}' ipv4.method manual\n\n`;
    
    commands += `# Use this only when gateway is of separate range (example, OVH DC)\n`;
    commands += `# sudo nmcli connection modify ${config.bridgeName} +ipv4.routes "${config.ipAddress}/${cidr} ${config.gateway}"\n\n`;
    
    // IPv6 configuration
    if (config.enableIPv6 && config.ipv6Address) {
      const ipv6Dns = '2001:4860:4860::8888';
      commands += `# Configure IPv6\n`;
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv6.addresses '${config.ipv6Address}/${config.ipv6Prefix}'`;
      if (config.ipv6Gateway) {
        commands += ` ipv6.gateway '${config.ipv6Gateway}'`;
      }
      commands += ` ipv6.dns '${ipv6Dns}' ipv6.method manual\n\n`;
    }
    
    commands += `# Add bond to bridge\n`;
    commands += `sudo nmcli connection modify ${config.bondName} master ${config.bridgeName}\n\n`;
    
    commands += `# Set autoconnect for slaves\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} connection.autoconnect-slaves 1\n\n`;
    
    commands += `# Bring up connections\n`;
    commands += `sudo nmcli connection up ${config.bridgeName}\n`;
    commands += `sudo nmcli connection up ${config.bondName}\n\n`;
  } else {
    commands += `# Create bridge\n`;
    commands += `sudo nmcli connection add type bridge con-name ${config.bridgeName} ifname ${config.bridgeName}\n\n`;
    
    commands += `# Disable STP (if your server provider blocks ports on switch due to BPDU flooding)\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} bridge.stp no\n\n`;
    
    // IPv4 configuration
    const dnsServers = config.dns ? config.dns.split(',').map(d => d.trim()).filter(d => d).join(' ') : '8.8.8.8';
    commands += `# Configure IPv4\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.addresses '${config.ipAddress}/${cidr}'`;
    if (config.gateway) {
      commands += ` ipv4.gateway '${config.gateway}'`;
    }
    commands += ` ipv4.dns '${dnsServers}' ipv4.method manual\n\n`;
    
    commands += `# Use this only when gateway is of separate range (example, OVH DC)\n`;
    commands += `# sudo nmcli connection modify ${config.bridgeName} +ipv4.routes "${config.ipAddress}/${cidr} ${config.gateway}"\n\n`;
    
    // IPv6 configuration
    if (config.enableIPv6 && config.ipv6Address) {
      const ipv6Dns = '2001:4860:4860::8888';
      commands += `# Configure IPv6\n`;
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv6.addresses '${config.ipv6Address}/${config.ipv6Prefix}'`;
      if (config.ipv6Gateway) {
        commands += ` ipv6.gateway '${config.ipv6Gateway}'`;
      }
      commands += ` ipv6.dns '${ipv6Dns}' ipv6.method manual\n\n`;
    }
    
    commands += `# Add interfaces to bridge\n`;
    interfaceList.forEach(iface => {
      commands += `sudo nmcli connection modify ${iface} master ${config.bridgeName}\n`;
    });
    
    commands += `\n# Set autoconnect for slaves\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} connection.autoconnect-slaves 1\n\n`;
    
    commands += `# Bring up connections\n`;
    commands += `sudo nmcli connection up ${config.bridgeName}\n`;
    interfaceList.forEach(iface => {
      commands += `sudo nmcli connection up ${iface}\n`;
    });
    commands += `\nw\n`;
  }
  
  return commands;
};

const generateGenericLinux = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  const interfaceList = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
  
  let commands = `# Generic Linux - Bridge Configuration Commands\n\n`;
  commands += `# Create bridge\n`;
  commands += `ip link add name ${config.bridgeName} type bridge\n`;
  commands += `ip link set ${config.bridgeName} up\n\n`;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `# Create bond\n`;
    commands += `ip link add ${config.bondName} type bond mode ${config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad'}\n`;
    slaves.forEach(slave => {
      commands += `ip link set ${slave} master ${config.bondName}\n`;
      commands += `ip link set ${slave} up\n`;
    });
    commands += `ip link set ${config.bondName} master ${config.bridgeName}\n`;
    commands += `ip link set ${config.bondName} up\n\n`;
  } else {
    commands += `# Add interfaces to bridge\n`;
    interfaceList.forEach(iface => {
      commands += `ip link set ${iface} master ${config.bridgeName}\n`;
      commands += `ip link set ${iface} up\n`;
    });
  }
  
  commands += `\n# Configure IP address\n`;
  commands += `ip addr add ${config.ipAddress}/${cidr} dev ${config.bridgeName}\n`;
  
  if (config.enableIPv6 && config.ipv6Address) {
    commands += `ip -6 addr add ${config.ipv6Address}/${config.ipv6Prefix} dev ${config.bridgeName}\n`;
  }
  
  if (config.gateway) {
    commands += `\n# Set default gateway\n`;
    commands += `ip route add default via ${config.gateway} dev ${config.bridgeName}\n`;
  }
  
  if (config.enableIPv6 && config.ipv6Gateway) {
    commands += `ip -6 route add default via ${config.ipv6Gateway} dev ${config.bridgeName}\n`;
  }
  
  if (config.dns) {
    commands += `\n# Configure DNS\n`;
    config.dns.split(',').forEach(dns => {
      commands += `echo "nameserver ${dns.trim()}" >> /etc/resolv.conf\n`;
    });
  }
  
  return commands;
};
