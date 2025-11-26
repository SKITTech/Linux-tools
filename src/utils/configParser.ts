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

export const validateIPv6Address = (ip: string): boolean => {
  // Remove CIDR prefix if present
  const ipWithoutPrefix = ip.includes('/') ? ip.split('/')[0] : ip;
  
  // IPv6 regex pattern
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  
  return ipv6Regex.test(ipWithoutPrefix);
};

export const validateMACAddress = (mac: string): boolean => {
  if (!mac.trim()) return true; // Empty is valid (optional field)
  
  // MAC address patterns: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
  const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return macRegex.test(mac);
};

export const validateInterfaceName = (name: string): boolean => {
  if (!name.trim()) return false;
  
  // Valid Linux interface names: alphanumeric, hyphens, underscores, max 15 chars
  const ifaceRegex = /^[a-zA-Z0-9_-]{1,15}$/;
  return ifaceRegex.test(name.trim());
};

export const validateIPv6Prefix = (prefix: string): boolean => {
  const num = parseInt(prefix);
  return !isNaN(num) && num >= 1 && num <= 128;
};

export const validateDNSServers = (dns: string): boolean => {
  if (!dns.trim()) return true; // Empty is valid (optional)
  
  const servers = dns.split(',').map(s => s.trim()).filter(s => s);
  
  return servers.every(server => {
    // Check if it's IPv4 or IPv6
    return validateIPAddress(server) || validateIPv6Address(server);
  });
};
