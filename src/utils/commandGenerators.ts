import { NetworkConfig, OSType } from "@/types/networkConfig";
import { netmaskToCIDR } from "./configParser";

export const generateCommands = (config: NetworkConfig): string => {
  const { os } = config;
  
  if (!config.ipAddress || !config.netmask || !config.bridgeName) {
    return "# Please fill in all required fields (IP Address, Netmask, Bridge Name)";
  }
  
  switch (os) {
    case "ubuntu-18.04-hetzner":
      return generateUbuntu1804Hetzner(config);
    case "ubuntu-18.04-generic":
      return generateUbuntu1804Generic(config);
    case "ubuntu-20.04":
      return generateUbuntu2004(config);
    case "ubuntu-22.04":
      return generateUbuntu2204(config);
    case "centos-7":
      return generateCentOS7(config);
    case "almalinux":
      return generateAlmaLinux(config);
    default:
      return generateGenericLinux(config);
  }
};

const generateUbuntu1804Hetzner = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  let commands = `# Ubuntu 18.04 (Hetzner Method) - /etc/netplan/01-netcfg.yaml\n\n`;
  
  if (config.enableBonding) {
    commands += `# WARNING: Backup your current network config before applying!\n`;
    commands += `# sudo cp /etc/netplan/01-netcfg.yaml /etc/netplan/01-netcfg.yaml.backup\n\n`;
    
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `cat << 'EOF' > /etc/netplan/01-netcfg.yaml\n`;
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  renderer: networkd\n`;
    commands += `  ethernets:\n`;
    slaves.forEach(slave => {
      commands += `    ${slave}:\n`;
      commands += `      dhcp4: no\n`;
      commands += `      dhcp6: no\n`;
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
    commands += `cat << 'EOF' > /etc/netplan/01-netcfg.yaml\n`;
    commands += `network:\n`;
    commands += `  version: 2\n`;
    commands += `  renderer: networkd\n`;
    commands += `  ethernets:\n`;
    interfaces.forEach(iface => {
      commands += `    ${iface}:\n`;
      commands += `      dhcp4: no\n`;
      commands += `      dhcp6: no\n`;
    });
    commands += `  bridges:\n`;
    commands += `    ${config.bridgeName}:\n`;
    commands += `      interfaces: [${interfaces.join(', ')}]\n`;
  }
  
  commands += `      addresses: [${config.ipAddress}/${cidr}]\n`;
  if (config.gateway) {
    commands += `      gateway4: ${config.gateway}\n`;
  }
  if (config.dns) {
    const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d);
    commands += `      nameservers:\n`;
    commands += `        addresses: [${dnsServers.join(', ')}]\n`;
  }
  commands += `EOF\n\n`;
  commands += `# Apply the configuration\n`;
  commands += `sudo netplan apply\n`;
  
  return commands;
};

const generateUbuntu1804Generic = (config: NetworkConfig): string => {
  const cidr = netmaskToCIDR(config.netmask);
  const interfaceList = config.interfaces.split(',').map(s => s.trim()).filter(s => s);
  
  let commands = `# Ubuntu 18.04 (Generic Method) - Bridge Configuration\n\n`;
  commands += `# Install bridge utilities\n`;
  commands += `sudo apt-get update\n`;
  commands += `sudo apt-get install -y bridge-utils\n\n`;
  
  if (config.enableBonding) {
    const slaves = config.bondSlaves.split(',').map(s => s.trim()).filter(s => s);
    commands += `# Create bond interface\n`;
    commands += `sudo modprobe bonding\n`;
    commands += `sudo ip link add ${config.bondName} type bond mode ${config.bondMode === 'mode-1' ? 'active-backup' : '802.3ad'}\n`;
    slaves.forEach(slave => {
      commands += `sudo ip link set ${slave} down\n`;
      commands += `sudo ip link set ${slave} master ${config.bondName}\n`;
      commands += `sudo ip link set ${slave} up\n`;
    });
    commands += `sudo ip link set ${config.bondName} up\n\n`;
    
    commands += `# Create bridge with bond\n`;
    commands += `sudo ip link add name ${config.bridgeName} type bridge\n`;
    commands += `sudo ip link set ${config.bondName} master ${config.bridgeName}\n`;
  } else {
    commands += `# Create bridge\n`;
    commands += `sudo ip link add name ${config.bridgeName} type bridge\n`;
    commands += `sudo ip link set ${config.bridgeName} up\n\n`;
    
    commands += `# Add interfaces to bridge\n`;
    interfaceList.forEach(iface => {
      commands += `sudo ip link set ${iface} master ${config.bridgeName}\n`;
      commands += `sudo ip link set ${iface} up\n`;
    });
  }
  
  commands += `\n# Configure IP address\n`;
  commands += `sudo ip addr add ${config.ipAddress}/${cidr} dev ${config.bridgeName}\n`;
  commands += `sudo ip link set ${config.bridgeName} up\n`;
  
  if (config.gateway) {
    commands += `\n# Set default gateway\n`;
    commands += `sudo ip route add default via ${config.gateway} dev ${config.bridgeName}\n`;
  }
  
  if (config.dns) {
    commands += `\n# Configure DNS\n`;
    config.dns.split(',').forEach(dns => {
      commands += `echo "nameserver ${dns.trim()}" | sudo tee -a /etc/resolv.conf\n`;
    });
  }
  
  return commands;
};

const generateUbuntu2004 = (config: NetworkConfig): string => {
  return generateUbuntu1804Hetzner(config).replace("Ubuntu 18.04", "Ubuntu 20.04");
};

const generateUbuntu2204 = (config: NetworkConfig): string => {
  return generateUbuntu1804Hetzner(config).replace("Ubuntu 18.04", "Ubuntu 22.04");
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
    commands += `sudo nmcli connection add type bridge con-name ${config.bridgeName} ifname ${config.bridgeName}\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.addresses ${config.ipAddress}/${cidr}\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.method manual\n`;
    
    if (config.gateway) {
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.gateway ${config.gateway}\n`;
    }
    
    if (config.dns) {
      const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d).join(' ');
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.dns "${dnsServers}"\n`;
    }
    
    // CRITICAL FIX: Add the missing STP line for AlmaLinux
    commands += `sudo nmcli connection modify ${config.bridgeName} bridge.stp no\n`;
    
    commands += `\n# Add bond to bridge\n`;
    commands += `sudo nmcli connection add type bridge-slave con-name bridge-${config.bondName} ifname ${config.bondName} master ${config.bridgeName}\n`;
  } else {
    commands += `# Create bridge\n`;
    commands += `sudo nmcli connection add type bridge con-name ${config.bridgeName} ifname ${config.bridgeName}\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.addresses ${config.ipAddress}/${cidr}\n`;
    commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.method manual\n`;
    
    if (config.gateway) {
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.gateway ${config.gateway}\n`;
    }
    
    if (config.dns) {
      const dnsServers = config.dns.split(',').map(d => d.trim()).filter(d => d).join(' ');
      commands += `sudo nmcli connection modify ${config.bridgeName} ipv4.dns "${dnsServers}"\n`;
    }
    
    // CRITICAL FIX: Add the missing STP line for AlmaLinux
    commands += `sudo nmcli connection modify ${config.bridgeName} bridge.stp no\n`;
    
    commands += `\n# Add interfaces to bridge\n`;
    interfaceList.forEach(iface => {
      commands += `sudo nmcli connection add type bridge-slave con-name bridge-${iface} ifname ${iface} master ${config.bridgeName}\n`;
    });
  }
  
  commands += `\n# Bring up the bridge\n`;
  commands += `sudo nmcli connection up ${config.bridgeName}\n`;
  
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
  
  if (config.gateway) {
    commands += `\n# Set default gateway\n`;
    commands += `ip route add default via ${config.gateway} dev ${config.bridgeName}\n`;
  }
  
  if (config.dns) {
    commands += `\n# Configure DNS\n`;
    config.dns.split(',').forEach(dns => {
      commands += `echo "nameserver ${dns.trim()}" >> /etc/resolv.conf\n`;
    });
  }
  
  return commands;
};
