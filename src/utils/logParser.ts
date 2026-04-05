export interface ParsedLogEntry {
  id: number;
  raw: string;
  timestamp: string | null;
  severity: "emergency" | "alert" | "critical" | "error" | "warning" | "notice" | "info" | "debug" | "unknown";
  host: string | null;
  service: string | null;
  message: string;
  ip: string | null;
  fields: Record<string, string>;
}

export type LogFormat = "auto" | "syslog" | "json" | "nginx" | "apache" | "systemd" | "application";

const SEVERITY_MAP: Record<string, ParsedLogEntry["severity"]> = {
  emerg: "emergency", emergency: "emergency",
  alert: "alert",
  crit: "critical", critical: "critical",
  err: "error", error: "error", fatal: "error",
  warn: "warning", warning: "warning",
  notice: "notice",
  info: "info", information: "info",
  debug: "debug", trace: "debug",
};

const SEVERITY_PRIORITY: Record<ParsedLogEntry["severity"], number> = {
  emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, info: 6, debug: 7, unknown: 8,
};

export function getSeverityColor(severity: ParsedLogEntry["severity"]): string {
  switch (severity) {
    case "emergency":
    case "alert":
    case "critical":
      return "text-red-600 dark:text-red-400 bg-red-500/10";
    case "error":
      return "text-destructive bg-destructive/10";
    case "warning":
      return "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10";
    case "notice":
    case "info":
      return "text-blue-600 dark:text-blue-400 bg-blue-500/10";
    case "debug":
      return "text-muted-foreground bg-muted/50";
    default:
      return "text-muted-foreground bg-muted/30";
  }
}

export function getSeverityBadgeColor(severity: ParsedLogEntry["severity"]): string {
  switch (severity) {
    case "emergency":
    case "alert":
    case "critical":
      return "bg-red-600 text-white";
    case "error":
      return "bg-destructive text-destructive-foreground";
    case "warning":
      return "bg-yellow-500 text-white";
    case "notice":
    case "info":
      return "bg-blue-500 text-white";
    case "debug":
      return "bg-muted text-muted-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function detectSeverity(text: string): ParsedLogEntry["severity"] {
  const lower = text.toLowerCase();
  for (const [key, val] of Object.entries(SEVERITY_MAP)) {
    if (lower.includes(key)) return val;
  }
  return "unknown";
}

function extractIPs(text: string): string | null {
  const match = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : null;
}

function parseSyslog(line: string, id: number): ParsedLogEntry {
  // Format: Jan 20 10:15:32 hostname service[pid]: message
  const match = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$/);
  if (match) {
    return {
      id, raw: line, timestamp: match[1], host: match[2], service: match[3],
      message: match[4], severity: detectSeverity(match[4]), ip: extractIPs(line), fields: {},
    };
  }
  return parseGeneric(line, id);
}

function parseJSON(line: string, id: number): ParsedLogEntry {
  try {
    const obj = JSON.parse(line);
    const ts = obj.timestamp || obj.time || obj["@timestamp"] || obj.ts || obj.date || null;
    const sev = obj.level || obj.severity || obj.loglevel || obj.priority || "";
    const msg = obj.message || obj.msg || obj.text || JSON.stringify(obj);
    const host = obj.host || obj.hostname || obj.server || null;
    const svc = obj.service || obj.app || obj.application || obj.logger || null;
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(obj)) {
      if (!["timestamp", "time", "@timestamp", "level", "severity", "message", "msg", "host", "hostname", "service"].includes(k)) {
        fields[k] = String(v);
      }
    }
    return {
      id, raw: line, timestamp: ts ? String(ts) : null, host, service: svc,
      message: String(msg), severity: SEVERITY_MAP[String(sev).toLowerCase()] || detectSeverity(msg),
      ip: extractIPs(line), fields,
    };
  } catch {
    return parseGeneric(line, id);
  }
}

function parseNginx(line: string, id: number): ParsedLogEntry {
  // Combined log format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "UA"
  const match = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/);
  if (match) {
    const status = parseInt(match[4]);
    let severity: ParsedLogEntry["severity"] = "info";
    if (status >= 500) severity = "error";
    else if (status >= 400) severity = "warning";
    return {
      id, raw: line, timestamp: match[2], host: null, service: "nginx",
      message: `${match[3]} → ${match[4]} (${match[5]} bytes)`,
      severity, ip: match[1],
      fields: { method: match[3].split(" ")[0], path: match[3].split(" ")[1] || "", status: match[4], size: match[5], referer: match[6], user_agent: match[7] },
    };
  }
  return parseGeneric(line, id);
}

function parseSystemd(line: string, id: number): ParsedLogEntry {
  // Format: Mon 2025-01-20 10:15:32 UTC hostname unit[pid]: message
  const match = line.match(/^(\w+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$/);
  if (match) {
    return {
      id, raw: line, timestamp: match[1], host: match[2], service: match[3],
      message: match[4], severity: detectSeverity(match[4]), ip: extractIPs(line), fields: {},
    };
  }
  return parseGeneric(line, id);
}

function parseGeneric(line: string, id: number): ParsedLogEntry {
  // Try: 2025-01-20 10:15:32 LEVEL [service] message
  const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+\[(\w+)\]\s+(.*)$/);
  if (match) {
    return {
      id, raw: line, timestamp: match[1], host: null, service: match[3],
      message: match[4], severity: SEVERITY_MAP[match[2].toLowerCase()] || detectSeverity(match[4]),
      ip: extractIPs(line), fields: {},
    };
  }
  // Fallback: try to extract timestamp
  const tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})/);
  return {
    id, raw: line, timestamp: tsMatch ? tsMatch[1] : null, host: null, service: null,
    message: line, severity: detectSeverity(line), ip: extractIPs(line), fields: {},
  };
}

function detectFormat(lines: string[]): LogFormat {
  const sample = lines.slice(0, 10);
  let jsonCount = 0, syslogCount = 0, nginxCount = 0, systemdCount = 0, appCount = 0;
  for (const line of sample) {
    if (line.trim().startsWith("{")) jsonCount++;
    if (/^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(line)) syslogCount++;
    if (/^\S+\s+\S+\s+\S+\s+\[/.test(line) && /"\s+\d{3}\s+\d+/.test(line)) nginxCount++;
    if (/^\w+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(line)) systemdCount++;
    if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+\s+\[/.test(line)) appCount++;
  }
  const max = Math.max(jsonCount, syslogCount, nginxCount, systemdCount, appCount);
  if (max === 0) return "application";
  if (jsonCount === max) return "json";
  if (nginxCount === max) return "nginx";
  if (syslogCount === max) return "syslog";
  if (systemdCount === max) return "systemd";
  return "application";
}

export function parseLogs(input: string, format: LogFormat = "auto"): { entries: ParsedLogEntry[]; detectedFormat: LogFormat } {
  const lines = input.split("\n").filter(l => l.trim());
  const detected = format === "auto" ? detectFormat(lines) : format;
  const parser = {
    syslog: parseSyslog, json: parseJSON, nginx: parseNginx,
    apache: parseNginx, systemd: parseSystemd, application: parseGeneric, auto: parseGeneric,
  }[detected];

  const entries = lines.map((line, i) => parser(line, i + 1));
  return { entries, detectedFormat: detected };
}

export interface LogStats {
  total: number;
  bySeverity: Record<ParsedLogEntry["severity"], number>;
  byService: { name: string; count: number }[];
  byHost: { name: string; count: number }[];
  topIPs: { ip: string; count: number }[];
  topErrors: { message: string; count: number }[];
  timeRange: { start: string | null; end: string | null };
  eventsPerMinute: { time: string; count: number }[];
  patterns: { pattern: string; count: number; severity: ParsedLogEntry["severity"] }[];
}

export function computeStats(entries: ParsedLogEntry[]): LogStats {
  const bySeverity: Record<ParsedLogEntry["severity"], number> = {
    emergency: 0, alert: 0, critical: 0, error: 0, warning: 0, notice: 0, info: 0, debug: 0, unknown: 0,
  };
  const serviceMap = new Map<string, number>();
  const hostMap = new Map<string, number>();
  const ipMap = new Map<string, number>();
  const errorMap = new Map<string, number>();
  const timeMap = new Map<string, number>();
  const patternMap = new Map<string, { count: number; severity: ParsedLogEntry["severity"] }>();

  for (const e of entries) {
    bySeverity[e.severity]++;
    if (e.service) serviceMap.set(e.service, (serviceMap.get(e.service) || 0) + 1);
    if (e.host) hostMap.set(e.host, (hostMap.get(e.host) || 0) + 1);
    if (e.ip) ipMap.set(e.ip, (ipMap.get(e.ip) || 0) + 1);
    if (SEVERITY_PRIORITY[e.severity] <= 3) {
      const short = e.message.substring(0, 80);
      errorMap.set(short, (errorMap.get(short) || 0) + 1);
    }
    if (e.timestamp) {
      const min = e.timestamp.substring(0, 16);
      timeMap.set(min, (timeMap.get(min) || 0) + 1);
    }
    // Simple pattern detection: group by message template
    const template = e.message.replace(/\d+\.\d+\.\d+\.\d+/g, "<IP>")
      .replace(/\d{4}-\d{2}-\d{2}/g, "<DATE>")
      .replace(/\d{2}:\d{2}:\d{2}/g, "<TIME>")
      .replace(/\b\d+\b/g, "<N>")
      .substring(0, 60);
    const existing = patternMap.get(template);
    if (existing) {
      existing.count++;
    } else {
      patternMap.set(template, { count: 1, severity: e.severity });
    }
  }

  const sortMap = <T extends { count: number }>(map: Map<string, number | T>, limit = 10) => {
    return Array.from(map.entries())
      .map(([k, v]) => typeof v === "number" ? { name: k, count: v } : { name: k, ...v })
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  };

  const timestamps = entries.map(e => e.timestamp).filter(Boolean) as string[];

  return {
    total: entries.length,
    bySeverity,
    byService: sortMap(serviceMap) as { name: string; count: number }[],
    byHost: sortMap(hostMap) as { name: string; count: number }[],
    topIPs: sortMap(ipMap).map(i => ({ ip: i.name, count: i.count })),
    topErrors: sortMap(errorMap).map(i => ({ message: i.name, count: i.count })),
    timeRange: { start: timestamps[0] || null, end: timestamps[timestamps.length - 1] || null },
    eventsPerMinute: Array.from(timeMap.entries()).map(([time, count]) => ({ time, count })),
    patterns: Array.from(patternMap.entries())
      .map(([pattern, data]) => ({ pattern, count: data.count, severity: data.severity }))
      .filter(p => p.count > 1)
      .sort((a, b) => b.count - a.count)
      .slice(0, 15),
  };
}

export function filterEntries(
  entries: ParsedLogEntry[],
  filters: {
    severity?: ParsedLogEntry["severity"][];
    search?: string;
    host?: string;
    service?: string;
    ip?: string;
  }
): ParsedLogEntry[] {
  return entries.filter(e => {
    if (filters.severity?.length && !filters.severity.includes(e.severity)) return false;
    if (filters.host && e.host !== filters.host) return false;
    if (filters.service && e.service !== filters.service) return false;
    if (filters.ip && e.ip !== filters.ip) return false;
    if (filters.search) {
      const term = filters.search.toLowerCase();
      if (!e.raw.toLowerCase().includes(term)) return false;
    }
    return true;
  });
}

export function exportToCSV(entries: ParsedLogEntry[]): string {
  const header = "ID,Timestamp,Severity,Host,Service,IP,Message";
  const rows = entries.map(e =>
    `${e.id},"${e.timestamp || ""}","${e.severity}","${e.host || ""}","${e.service || ""}","${e.ip || ""}","${e.message.replace(/"/g, '""')}"`
  );
  return [header, ...rows].join("\n");
}

export function exportToJSON(entries: ParsedLogEntry[]): string {
  return JSON.stringify(entries.map(({ id, timestamp, severity, host, service, ip, message, fields }) => ({
    id, timestamp, severity, host, service, ip, message, fields,
  })), null, 2);
}
