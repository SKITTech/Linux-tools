export type OSType = 
  | "ubuntu-18.04-hetzner"
  | "ubuntu-18.04-generic"
  | "ubuntu-20.04"
  | "ubuntu-22.04"
  | "centos-7"
  | "almalinux";

export type BondMode = "mode-1" | "mode-4";

export interface NetworkConfig {
  ipAddress: string;
  netmask: string;
  bridgeName: string;
  interfaces: string;
  gateway: string;
  dns: string;
  os: OSType;
  
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
  { value: "255.255.255.0", label: "255.255.255.0 ( /24 )", cidr: 24 },
  { value: "255.255.254.0", label: "255.255.254.0 ( /23 )", cidr: 23 },
  { value: "255.255.252.0", label: "255.255.252.0 ( /22 )", cidr: 22 },
  { value: "255.255.0.0", label: "255.255.0.0 ( /16 )", cidr: 16 },
  { value: "255.0.0.0", label: "255.0.0.0 ( /8 )", cidr: 8 },
];

export const OS_OPTIONS = [
  { value: "ubuntu-18.04-hetzner" as OSType, label: "Ubuntu 18.04 (Hetzner Method)" },
  { value: "ubuntu-18.04-generic" as OSType, label: "Ubuntu 18.04 (Generic)" },
  { value: "ubuntu-20.04" as OSType, label: "Ubuntu 20.04" },
  { value: "ubuntu-22.04" as OSType, label: "Ubuntu 22.04" },
  { value: "centos-7" as OSType, label: "CentOS 7" },
  { value: "almalinux" as OSType, label: "AlmaLinux" },
];
