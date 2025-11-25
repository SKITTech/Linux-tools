export type OSType = 
  | "centos-7"
  | "almalinux"
  | "ubuntu-16.04"
  | "ubuntu-18.04-hetzner"
  | "ubuntu-18.04-other";

export type BondMode = "mode-1" | "mode-4";

export interface NetworkConfig {
  ipAddress: string;
  netmask: string;
  bridgeName: string;
  interfaces: string;
  gateway: string;
  dns: string;
  os: OSType;
  macAddress: string;
  
  // IPv6 options
  enableIPv6: boolean;
  ipv6Address: string;
  ipv6Gateway: string;
  ipv6Prefix: string;
  
  // Bonding options
  enableBonding: boolean;
  bondName: string;
  bondMode: BondMode;
  bondSlaves: string;
}

export interface ParsedConfig {
  ipAddress?: string;
  gateway?: string;
  netmask?: string;
  prefix?: string;
  interfaceName?: string;
  bridgeName?: string;
  bondSlaves?: string[];
}

export const NETMASK_OPTIONS = [
  { value: "255.255.255.255", label: "255.255.255.255 ( /32 )", cidr: 32 },
  { value: "255.255.255.254", label: "255.255.255.254 ( /31 )", cidr: 31 },
  { value: "255.255.255.252", label: "255.255.255.252 ( /30 )", cidr: 30 },
  { value: "255.255.255.248", label: "255.255.255.248 ( /29 )", cidr: 29 },
  { value: "255.255.255.240", label: "255.255.255.240 ( /28 )", cidr: 28 },
  { value: "255.255.255.224", label: "255.255.255.224 ( /27 )", cidr: 27 },
  { value: "255.255.255.192", label: "255.255.255.192 ( /26 )", cidr: 26 },
  { value: "255.255.255.128", label: "255.255.255.128 ( /25 )", cidr: 25 },
  { value: "255.255.255.0", label: "255.255.255.0 ( /24 )", cidr: 24 },
  { value: "255.255.254.0", label: "255.255.254.0 ( /23 )", cidr: 23 },
  { value: "255.255.252.0", label: "255.255.252.0 ( /22 )", cidr: 22 },
  { value: "255.255.248.0", label: "255.255.248.0 ( /21 )", cidr: 21 },
  { value: "255.255.240.0", label: "255.255.240.0 ( /20 )", cidr: 20 },
  { value: "255.255.224.0", label: "255.255.224.0 ( /19 )", cidr: 19 },
  { value: "255.255.192.0", label: "255.255.192.0 ( /18 )", cidr: 18 },
  { value: "255.255.128.0", label: "255.255.128.0 ( /17 )", cidr: 17 },
  { value: "255.255.0.0", label: "255.255.0.0 ( /16 )", cidr: 16 },
  { value: "255.254.0.0", label: "255.254.0.0 ( /15 )", cidr: 15 },
  { value: "255.252.0.0", label: "255.252.0.0 ( /14 )", cidr: 14 },
  { value: "255.248.0.0", label: "255.248.0.0 ( /13 )", cidr: 13 },
  { value: "255.240.0.0", label: "255.240.0.0 ( /12 )", cidr: 12 },
  { value: "255.224.0.0", label: "255.224.0.0 ( /11 )", cidr: 11 },
  { value: "255.192.0.0", label: "255.192.0.0 ( /10 )", cidr: 10 },
  { value: "255.128.0.0", label: "255.128.0.0 ( /9 )", cidr: 9 },
  { value: "255.0.0.0", label: "255.0.0.0 ( /8 )", cidr: 8 },
];

export const OS_OPTIONS = [
  { value: "centos-7" as OSType, label: "CentOS 7 (Without NetworkManager)" },
  { value: "almalinux" as OSType, label: "AlmaLinux 8.x and above" },
  { value: "ubuntu-16.04" as OSType, label: "Ubuntu 16.04" },
  { value: "ubuntu-18.04-hetzner" as OSType, label: "Ubuntu 18.04 and higher (Hetzner)" },
  { value: "ubuntu-18.04-other" as OSType, label: "Ubuntu 18.04 and higher (Other Providers)" },
];
