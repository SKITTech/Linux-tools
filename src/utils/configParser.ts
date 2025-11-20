import { ParsedConfig } from "@/types/networkConfig";

export const parseNetworkConfig = (configText: string): ParsedConfig => {
  const parsed: ParsedConfig = {};
  
  // Common patterns for IP address
  const ipPattern = /(?:address|IPADDR)[:\s=]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i;
  const ipMatch = configText.match(ipPattern);
  if (ipMatch) parsed.ipAddress = ipMatch[1];
  
  // Gateway patterns
  const gatewayPattern = /(?:gateway|GATEWAY)[:\s=]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i;
  const gatewayMatch = configText.match(gatewayPattern);
  if (gatewayMatch) parsed.gateway = gatewayMatch[1];
  
  // Netmask patterns
  const netmaskPattern = /(?:netmask|NETMASK)[:\s=]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i;
  const netmaskMatch = configText.match(netmaskPattern);
  if (netmaskMatch) parsed.netmask = netmaskMatch[1];
  
  // CIDR prefix pattern (e.g., /24)
  const prefixPattern = /\/(\d{1,2})/;
  const prefixMatch = configText.match(prefixPattern);
  if (prefixMatch) parsed.prefix = prefixMatch[1];
  
  // Interface name patterns
  const ifacePattern = /(?:DEVICE|interface)[:\s=]+(\w+)/i;
  const ifaceMatch = configText.match(ifacePattern);
  if (ifaceMatch) parsed.interfaceName = ifaceMatch[1];
  
  // Bridge name patterns
  const bridgePattern = /(?:bridge|BRIDGE)[:\s=]+(\w+)/i;
  const bridgeMatch = configText.match(bridgePattern);
  if (bridgeMatch) parsed.bridgeName = bridgeMatch[1];
  
  // Bond slaves patterns
  const bondSlavePattern = /(?:bond[-_]slaves|BONDING_SLAVE\d*)[:\s=]+(\w+(?:\s+\w+)*)/gi;
  const bondMatches = [...configText.matchAll(bondSlavePattern)];
  if (bondMatches.length > 0) {
    parsed.bondSlaves = bondMatches.map(m => m[1].trim()).filter(s => s);
  }
  
  return parsed;
};

export const validateIPAddress = (ip: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  
  const parts = ip.split('.').map(Number);
  return parts.every(part => part >= 0 && part <= 255);
};

export const validateNetmask = (netmask: string): boolean => {
  const parts = netmask.split('.').map(Number);
  if (parts.length !== 4) return false;
  if (parts.some(part => part < 0 || part > 255)) return false;
  
  // Verify it's a valid netmask (contiguous 1s followed by contiguous 0s)
  const binary = parts.map(p => p.toString(2).padStart(8, '0')).join('');
  return /^1*0*$/.test(binary);
};

export const netmaskToCIDR = (netmask: string): number => {
  const maskNodes = netmask.split('.').map(Number);
  let cidr = 0;
  for (const node of maskNodes) {
    cidr += (node >>> 0).toString(2).split('1').length - 1;
  }
  return cidr;
};

export const cidrToNetmask = (cidr: number): string => {
  const mask = (0xffffffff << (32 - cidr)) >>> 0;
  return [
    (mask >>> 24) & 0xff,
    (mask >>> 16) & 0xff,
    (mask >>> 8) & 0xff,
    mask & 0xff
  ].join('.');
};
