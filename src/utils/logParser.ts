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
    case "emergency": case "alert": case "critical": return "text-red-600 dark:text-red-400 bg-red-500/10";
    case "error": return "text-destructive bg-destructive/10";
    case "warning": return "text-yellow-600 dark:text-yellow-400 bg-yellow-500/10";
    case "notice": case "info": return "text-blue-600 dark:text-blue-400 bg-blue-500/10";
    case "debug": return "text-muted-foreground bg-muted/50";
    default: return "text-muted-foreground bg-muted/30";
  }
}

export function getSeverityBadgeColor(severity: ParsedLogEntry["severity"]): string {
  switch (severity) {
    case "emergency": case "alert": case "critical": return "bg-red-600 text-white";
    case "error": return "bg-destructive text-destructive-foreground";
    case "warning": return "bg-yellow-500 text-white";
    case "notice": case "info": return "bg-blue-500 text-white";
    case "debug": return "bg-muted text-muted-foreground";
    default: return "bg-muted text-muted-foreground";
  }
}

function detectSeverity(text: string): ParsedLogEntry["severity"] {
  const lower = text.toLowerCase();
  // Check in priority order
  const ordered = ["emergency", "emerg", "alert", "critical", "crit", "fatal", "error", "err", "warning", "warn", "notice", "info", "debug", "trace"];
  for (const key of ordered) {
    if (lower.includes(key)) return SEVERITY_MAP[key];
  }
  return "unknown";
}

function extractIPs(text: string): string | null {
  const match = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : null;
}

function parseSyslog(line: string, id: number): ParsedLogEntry {
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
    const skipKeys = new Set(["timestamp", "time", "@timestamp", "level", "severity", "message", "msg", "host", "hostname", "service"]);
    for (const [k, v] of Object.entries(obj)) {
      if (!skipKeys.has(k)) fields[k] = String(v);
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
  const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+\[(\w+)\]\s+(.*)$/);
  if (match) {
    return {
      id, raw: line, timestamp: match[1], host: null, service: match[3],
      message: match[4], severity: SEVERITY_MAP[match[2].toLowerCase()] || detectSeverity(match[4]),
      ip: extractIPs(line), fields: {},
    };
  }
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

export interface CorrelatedEvent {
  primary: ParsedLogEntry;
  related: ParsedLogEntry[];
  correlation: string;
}

export interface SecurityFinding {
  type: "brute_force" | "access_denied" | "privilege_escalation" | "suspicious_ip" | "data_exfiltration" | "service_scan" | "critical_event";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  entries: ParsedLogEntry[];
  recommendation: string;
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
    const template = e.message.replace(/\d+\.\d+\.\d+\.\d+/g, "<IP>")
      .replace(/\d{4}-\d{2}-\d{2}/g, "<DATE>")
      .replace(/\d{2}:\d{2}:\d{2}/g, "<TIME>")
      .replace(/\b\d+\b/g, "<N>")
      .substring(0, 60);
    const existing = patternMap.get(template);
    if (existing) existing.count++;
    else patternMap.set(template, { count: 1, severity: e.severity });
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

export function correlateEvents(entries: ParsedLogEntry[]): CorrelatedEvent[] {
  const correlations: CorrelatedEvent[] = [];
  const errors = entries.filter(e => SEVERITY_PRIORITY[e.severity] <= 3);

  for (const err of errors.slice(0, 20)) {
    const related: ParsedLogEntry[] = [];
    const errIdx = entries.indexOf(err);
    // Find related entries within ±5 lines
    for (let i = Math.max(0, errIdx - 5); i <= Math.min(entries.length - 1, errIdx + 5); i++) {
      const candidate = entries[i];
      if (candidate.id === err.id) continue;
      // Same service or same host or same IP
      if ((err.service && candidate.service === err.service) ||
          (err.host && candidate.host === err.host) ||
          (err.ip && candidate.ip === err.ip)) {
        related.push(candidate);
      }
    }
    if (related.length > 0) {
      let correlation = "Temporal proximity";
      if (related.some(r => r.service === err.service)) correlation = `Same service: ${err.service}`;
      else if (related.some(r => r.host === err.host)) correlation = `Same host: ${err.host}`;
      else if (related.some(r => r.ip === err.ip)) correlation = `Same IP: ${err.ip}`;
      correlations.push({ primary: err, related, correlation });
    }
  }
  return correlations;
}

export function detectSecurityFindings(entries: ParsedLogEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lower = (e: ParsedLogEntry) => e.message.toLowerCase();

  // Brute force detection
  const failedLogins = entries.filter(e =>
    lower(e).includes("failed") && (lower(e).includes("login") || lower(e).includes("password") || lower(e).includes("auth"))
  );
  if (failedLogins.length >= 3) {
    const ipCounts = new Map<string, number>();
    failedLogins.forEach(e => { if (e.ip) ipCounts.set(e.ip, (ipCounts.get(e.ip) || 0) + 1); });
    const topIP = Array.from(ipCounts.entries()).sort((a, b) => b[1] - a[1])[0];
    findings.push({
      type: "brute_force", severity: failedLogins.length >= 10 ? "critical" : "high",
      title: `Brute Force Attack (${failedLogins.length} attempts)`,
      description: `${failedLogins.length} failed authentication attempts detected${topIP ? ` — primary source: ${topIP[0]} (${topIP[1]} attempts)` : ""}`,
      entries: failedLogins,
      recommendation: topIP ? `Block IP ${topIP[0]} using firewall. Consider implementing fail2ban or rate limiting.` : "Implement account lockout policies and IP-based rate limiting.",
    });
  }

  // Access denied
  const denied = entries.filter(e =>
    lower(e).includes("denied") || lower(e).includes("forbidden") || lower(e).includes("unauthorized") ||
    e.message.includes("403") || e.message.includes("401")
  );
  if (denied.length >= 2) {
    findings.push({
      type: "access_denied", severity: denied.length >= 10 ? "high" : "medium",
      title: `Access Denied Events (${denied.length})`,
      description: `${denied.length} unauthorized access attempts detected across your services.`,
      entries: denied,
      recommendation: "Review access control policies. Ensure proper RBAC is configured.",
    });
  }

  // Privilege escalation
  const privEsc = entries.filter(e =>
    lower(e).includes("root") || lower(e).includes("sudo") || lower(e).includes("privilege") || lower(e).includes("escalat")
  );
  if (privEsc.length > 0) {
    findings.push({
      type: "privilege_escalation", severity: "high",
      title: `Privilege Escalation Attempts (${privEsc.length})`,
      description: `${privEsc.length} events involving root/sudo/privilege changes detected.`,
      entries: privEsc,
      recommendation: "Audit sudo configurations. Limit root access. Use least-privilege principle.",
    });
  }

  // Service scanning
  const portScan = entries.filter(e =>
    lower(e).includes("scan") || lower(e).includes("probe") ||
    (lower(e).includes("connection") && lower(e).includes("refused"))
  );
  if (portScan.length >= 3) {
    findings.push({
      type: "service_scan", severity: "medium",
      title: `Potential Port/Service Scanning (${portScan.length})`,
      description: `Multiple connection refused or scan-related events detected.`,
      entries: portScan,
      recommendation: "Review firewall rules. Consider implementing port knocking or IDS/IPS.",
    });
  }

  // Critical events
  const criticals = entries.filter(e => e.severity === "critical" || e.severity === "emergency");
  if (criticals.length > 0) {
    findings.push({
      type: "critical_event", severity: "critical",
      title: `Critical System Events (${criticals.length})`,
      description: `${criticals.length} critical/emergency events require immediate attention.`,
      entries: criticals,
      recommendation: "Investigate each critical event. Check service health and system resources.",
    });
  }

  return findings.sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return sevOrder[a.severity] - sevOrder[b.severity];
  });
}

export function computeHealthScore(stats: LogStats, securityFindings: SecurityFinding[]): { score: number; grade: string; factors: { name: string; impact: number; detail: string }[] } {
  let score = 100;
  const factors: { name: string; impact: number; detail: string }[] = [];

  const errorRate = stats.total ? ((stats.bySeverity.error + stats.bySeverity.critical + stats.bySeverity.emergency + stats.bySeverity.alert) / stats.total * 100) : 0;

  if (errorRate > 20) { score -= 30; factors.push({ name: "High Error Rate", impact: -30, detail: `${errorRate.toFixed(1)}% error rate` }); }
  else if (errorRate > 10) { score -= 20; factors.push({ name: "Elevated Error Rate", impact: -20, detail: `${errorRate.toFixed(1)}% error rate` }); }
  else if (errorRate > 5) { score -= 10; factors.push({ name: "Moderate Error Rate", impact: -10, detail: `${errorRate.toFixed(1)}% error rate` }); }

  if (stats.bySeverity.critical > 0) { const penalty = Math.min(stats.bySeverity.critical * 5, 20); score -= penalty; factors.push({ name: "Critical Events", impact: -penalty, detail: `${stats.bySeverity.critical} critical events` }); }

  const criticalFindings = securityFindings.filter(f => f.severity === "critical").length;
  const highFindings = securityFindings.filter(f => f.severity === "high").length;
  if (criticalFindings > 0) { score -= criticalFindings * 10; factors.push({ name: "Critical Security Findings", impact: -criticalFindings * 10, detail: `${criticalFindings} critical findings` }); }
  if (highFindings > 0) { score -= highFindings * 5; factors.push({ name: "High Security Findings", impact: -highFindings * 5, detail: `${highFindings} high findings` }); }

  const repeatedErrors = stats.patterns.filter(p => p.count >= 5 && (p.severity === "error" || p.severity === "critical")).length;
  if (repeatedErrors > 0) { score -= repeatedErrors * 3; factors.push({ name: "Repeated Error Patterns", impact: -repeatedErrors * 3, detail: `${repeatedErrors} repeating error patterns` }); }

  score = Math.max(0, Math.min(100, score));
  let grade = "A";
  if (score < 40) grade = "F";
  else if (score < 55) grade = "D";
  else if (score < 70) grade = "C";
  else if (score < 85) grade = "B";

  return { score, grade, factors };
}

export function filterEntries(
  entries: ParsedLogEntry[],
  filters: { severity?: ParsedLogEntry["severity"][]; search?: string; host?: string; service?: string; ip?: string; customName?: string; dateTimeFrom?: string; dateTimeTo?: string; }
): ParsedLogEntry[] {
  return entries.filter(e => {
    if (filters.severity?.length && !filters.severity.includes(e.severity)) return false;
    if (filters.host && e.host !== filters.host) return false;
    if (filters.service && e.service !== filters.service) return false;
    if (filters.ip && e.ip !== filters.ip) return false;
    if (filters.customName) {
      const term = filters.customName.toLowerCase();
      const matchesHost = e.host?.toLowerCase().includes(term);
      const matchesService = e.service?.toLowerCase().includes(term);
      const matchesIp = e.ip?.toLowerCase().includes(term);
      if (!matchesHost && !matchesService && !matchesIp) return false;
    }
    if (filters.search) {
      const term = filters.search.toLowerCase();
      if (!e.raw.toLowerCase().includes(term)) return false;
    }
    if (filters.dateTimeFrom && e.timestamp) {
      if (e.timestamp < filters.dateTimeFrom) return false;
    }
    if (filters.dateTimeTo && e.timestamp) {
      if (e.timestamp > filters.dateTimeTo) return false;
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
