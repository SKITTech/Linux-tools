import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface PortCheckRequest {
  host: string;
  port: number;
  timeout?: number;
}

interface PortCheckResponse {
  host: string;
  port: number;
  status: 'open' | 'closed' | 'timeout' | 'error';
  responseTime?: number;
  service?: string;
  error?: string;
  ipVersion?: 'IPv4' | 'IPv6';
}

// Common service names for ports
const serviceNames: { [key: number]: string } = {
  20: "FTP Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  465: "SMTPS",
  587: "SMTP (Submission)",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  27017: "MongoDB",
};

// Validate hostname/IP
function validateHost(host: string): { valid: boolean; error?: string; isIPv6: boolean } {
  // Check if IPv6
  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))$/;
  
  // Check if IPv4
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  
  // Check if domain name
  const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  
  if (ipv6Pattern.test(host)) {
    return { valid: true, isIPv6: true };
  }
  
  if (ipv4Pattern.test(host)) {
    // Validate IPv4 octets
    const octets = host.split('.').map(Number);
    if (octets.some(octet => octet < 0 || octet > 255)) {
      return { valid: false, error: 'Invalid IPv4 address', isIPv6: false };
    }
    return { valid: true, isIPv6: false };
  }
  
  if (domainPattern.test(host)) {
    return { valid: true, isIPv6: false };
  }
  
  return { valid: false, error: 'Invalid hostname or IP address', isIPv6: false };
}

async function checkPort(host: string, port: number, timeout: number = 5000): Promise<PortCheckResponse> {
  const startTime = Date.now();
  
  try {
    const hostValidation = validateHost(host);
    if (!hostValidation.valid) {
      return {
        host,
        port,
        status: 'error',
        error: hostValidation.error,
      };
    }
    
    // Create a timeout promise
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), timeout);
    });
    
    // Try to connect to the port
    const connectPromise = (async () => {
      const conn = await Deno.connect({
        hostname: host,
        port: port,
        transport: 'tcp',
      });
      conn.close();
      return conn;
    })();
    
    // Race between connection and timeout
    await Promise.race([connectPromise, timeoutPromise]);
    
    const responseTime = Date.now() - startTime;
    
    return {
      host,
      port,
      status: 'open',
      responseTime,
      service: serviceNames[port] || 'Unknown',
      ipVersion: hostValidation.isIPv6 ? 'IPv6' : 'IPv4',
    };
  } catch (err) {
    const responseTime = Date.now() - startTime;
    const error = err as Error;
    const errorMessage = error.message.toLowerCase();
    
    // Determine if it's a timeout or connection refused
    if (errorMessage.includes('timeout')) {
      return {
        host,
        port,
        status: 'timeout',
        responseTime,
        error: 'Connection timeout',
      };
    } else if (errorMessage.includes('refused') || errorMessage.includes('connect')) {
      return {
        host,
        port,
        status: 'closed',
        responseTime,
        error: 'Connection refused',
      };
    } else {
      return {
        host,
        port,
        status: 'error',
        responseTime,
        error: error.message,
      };
    }
  }
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }
  
  try {
    const { host, port, timeout }: PortCheckRequest = await req.json();
    
    // Validate input
    if (!host || typeof host !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Host is required and must be a string' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    
    if (!port || typeof port !== 'number' || port < 1 || port > 65535) {
      return new Response(
        JSON.stringify({ error: 'Port must be a number between 1 and 65535' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    
    // Rate limiting check (simple per-request validation)
    const sanitizedHost = host.trim();
    if (sanitizedHost.length > 253) {
      return new Response(
        JSON.stringify({ error: 'Hostname too long' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
    
    console.log(`Port check requested for ${sanitizedHost}:${port}`);
    
    const result = await checkPort(sanitizedHost, port, timeout || 5000);
    
    console.log(`Port check result:`, result);
    
    return new Response(
      JSON.stringify(result),
      { 
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  } catch (err) {
    const error = err as Error;
    console.error('Error in check-port function:', error);
    return new Response(
      JSON.stringify({ 
        error: 'Internal server error',
        details: error.message 
      }),
      { 
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  }
});
