import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, CheckCircle2, AlertTriangle, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Sidebar } from "@/components/Sidebar";

interface AuditItem {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  checked: boolean;
  remediation: string;
}

const SecurityAudit = () => {
  const [auditItems, setAuditItems] = useState<AuditItem[]>([
    {
      id: "ssh-root",
      category: "SSH Security",
      title: "SSH root login disabled",
      description: "Check that PermitRootLogin is set to 'no' in /etc/ssh/sshd_config",
      severity: "critical",
      checked: false,
      remediation: "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then restart SSH service",
    },
    {
      id: "ssh-password",
      category: "SSH Security",
      title: "SSH password authentication disabled",
      description: "Ensure PasswordAuthentication is set to 'no' (use key-based auth)",
      severity: "high",
      checked: false,
      remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and use SSH keys",
    },
    {
      id: "firewall-enabled",
      category: "Firewall",
      title: "Firewall is enabled and configured",
      description: "Verify iptables or nftables is active with proper rules",
      severity: "critical",
      checked: false,
      remediation: "Enable and configure firewall using iptables or nftables",
    },
    {
      id: "open-ports",
      category: "Network",
      title: "Only necessary ports are open",
      description: "Audit open ports with 'ss -tulpn' or 'netstat -tulpn'",
      severity: "high",
      checked: false,
      remediation: "Close unnecessary ports and restrict access using firewall rules",
    },
    {
      id: "updates",
      category: "System",
      title: "System packages are up to date",
      description: "Check for available security updates",
      severity: "high",
      checked: false,
      remediation: "Run 'apt update && apt upgrade' or equivalent for your distribution",
    },
    {
      id: "fail2ban",
      category: "Intrusion Prevention",
      title: "Fail2Ban or similar is installed",
      description: "Verify intrusion prevention system is monitoring failed login attempts",
      severity: "medium",
      checked: false,
      remediation: "Install and configure Fail2Ban: 'apt install fail2ban'",
    },
    {
      id: "world-writable",
      category: "File Permissions",
      title: "No world-writable files in critical directories",
      description: "Find world-writable files: 'find / -perm -002 -type f 2>/dev/null'",
      severity: "high",
      checked: false,
      remediation: "Review and fix permissions on world-writable files",
    },
    {
      id: "sudo-nopasswd",
      category: "User Privileges",
      title: "No NOPASSWD entries in sudoers",
      description: "Check /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries",
      severity: "high",
      checked: false,
      remediation: "Remove NOPASSWD entries from sudoers configuration",
    },
    {
      id: "selinux-apparmor",
      category: "Mandatory Access Control",
      title: "SELinux or AppArmor is enabled",
      description: "Verify mandatory access control is active",
      severity: "medium",
      checked: false,
      remediation: "Enable and configure SELinux (RHEL/CentOS) or AppArmor (Debian/Ubuntu)",
    },
    {
      id: "password-policy",
      category: "User Management",
      title: "Strong password policy enforced",
      description: "Check password requirements in /etc/pam.d/common-password or /etc/security/pwquality.conf",
      severity: "medium",
      checked: false,
      remediation: "Configure PAM to enforce strong passwords with minimum length and complexity",
    },
    {
      id: "inactive-users",
      category: "User Management",
      title: "No inactive users with login access",
      description: "Review user accounts in /etc/passwd for unused accounts",
      severity: "medium",
      checked: false,
      remediation: "Lock or remove inactive user accounts: 'usermod -L username'",
    },
    {
      id: "log-rotation",
      category: "Logging",
      title: "Log rotation configured",
      description: "Verify logrotate is configured for system logs",
      severity: "low",
      checked: false,
      remediation: "Configure logrotate in /etc/logrotate.d/ for all critical log files",
    },
    {
      id: "ssl-certs",
      category: "SSL/TLS",
      title: "SSL certificates are valid and not expired",
      description: "Check certificate expiration dates for web services",
      severity: "high",
      checked: false,
      remediation: "Renew expiring certificates and set up auto-renewal (e.g., certbot)",
    },
    {
      id: "unattended-upgrades",
      category: "System",
      title: "Automatic security updates enabled",
      description: "Check if unattended-upgrades or similar is configured",
      severity: "medium",
      checked: false,
      remediation: "Install and enable unattended-upgrades for automatic security patches",
    },
  ]);

  const [showReport, setShowReport] = useState(false);

  const toggleCheck = (id: string) => {
    setAuditItems(prev =>
      prev.map(item =>
        item.id === id ? { ...item, checked: !item.checked } : item
      )
    );
  };

  const selectAll = () => {
    setAuditItems(prev => prev.map(item => ({ ...item, checked: true })));
    toast.success("All items marked as complete");
  };

  const clearAll = () => {
    setAuditItems(prev => prev.map(item => ({ ...item, checked: false })));
    toast.success("All items cleared");
  };

  const generateReport = () => {
    setShowReport(true);
    toast.success("Security audit report generated");
  };

  const checkedCount = auditItems.filter(item => item.checked).length;
  const totalCount = auditItems.length;
  const completionPercentage = Math.round((checkedCount / totalCount) * 100);

  const criticalUnchecked = auditItems.filter(item => item.severity === "critical" && !item.checked).length;
  const highUnchecked = auditItems.filter(item => item.severity === "high" && !item.checked).length;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-destructive text-destructive-foreground";
      case "high": return "bg-orange-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-blue-500 text-white";
      default: return "bg-muted";
    }
  };

  const groupedItems = auditItems.reduce((acc, item) => {
    if (!acc[item.category]) acc[item.category] = [];
    acc[item.category].push(item);
    return acc;
  }, {} as Record<string, AuditItem[]>);

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-8">
          <div className="text-center my-8">
            <div className="flex items-center justify-center gap-3 mb-4">
              <ShieldAlert className="w-10 h-10 text-primary" />
              <h1 className="text-4xl font-bold text-foreground">Security Audit Checklist</h1>
            </div>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Comprehensive security checklist for Linux system administrators
            </p>
          </div>

          <div className="grid lg:grid-cols-3 gap-6 mb-8">
            <Card className="border-border/40 shadow-lg">
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-4xl font-bold text-primary mb-2">{completionPercentage}%</div>
                  <div className="text-sm text-muted-foreground">Completion</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {checkedCount} of {totalCount} items
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/40 shadow-lg border-destructive/20">
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-4xl font-bold text-destructive mb-2">{criticalUnchecked}</div>
                  <div className="text-sm text-muted-foreground">Critical Issues</div>
                  <div className="text-xs text-muted-foreground mt-1">Require immediate attention</div>
                </div>
              </CardContent>
            </Card>

            <Card className="border-border/40 shadow-lg border-orange-500/20">
              <CardContent className="pt-6">
                <div className="text-center">
                  <div className="text-4xl font-bold text-orange-500 mb-2">{highUnchecked}</div>
                  <div className="text-sm text-muted-foreground">High Priority</div>
                  <div className="text-xs text-muted-foreground mt-1">Should be addressed soon</div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="border-border/40 shadow-lg mb-6">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Audit Checklist</CardTitle>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={selectAll}>
                    Select All
                  </Button>
                  <Button variant="outline" size="sm" onClick={clearAll}>
                    Clear All
                  </Button>
                  <Button size="sm" onClick={generateReport}>
                    Generate Report
                  </Button>
                </div>
              </div>
              <CardDescription>Check items as you verify each security measure</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {Object.entries(groupedItems).map(([category, items]) => (
                  <div key={category}>
                    <h3 className="font-semibold text-lg mb-3 text-foreground">{category}</h3>
                    <div className="space-y-3">
                      {items.map((item) => (
                        <div
                          key={item.id}
                          className={`border rounded-lg p-4 transition-colors ${
                            item.checked ? "bg-muted/30 border-primary/20" : "bg-card border-border"
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <Checkbox
                              id={item.id}
                              checked={item.checked}
                              onCheckedChange={() => toggleCheck(item.id)}
                              className="mt-1"
                            />
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <Label htmlFor={item.id} className="font-medium cursor-pointer">
                                  {item.title}
                                </Label>
                                <Badge className={getSeverityColor(item.severity)} variant="secondary">
                                  {item.severity.toUpperCase()}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mb-2">{item.description}</p>
                              <div className="bg-muted/50 p-2 rounded text-xs">
                                <span className="font-semibold text-foreground">Remediation: </span>
                                <span className="text-muted-foreground">{item.remediation}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {showReport && (
            <Card className="border-border/40 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5" />
                  Security Audit Report
                </CardTitle>
                <CardDescription>Summary of your security audit</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-lg">
                    {completionPercentage === 100 ? (
                      <CheckCircle2 className="w-8 h-8 text-green-500" />
                    ) : criticalUnchecked > 0 ? (
                      <XCircle className="w-8 h-8 text-destructive" />
                    ) : (
                      <AlertTriangle className="w-8 h-8 text-yellow-500" />
                    )}
                    <div>
                      <div className="font-semibold text-lg">
                        {completionPercentage === 100
                          ? "All security checks passed!"
                          : criticalUnchecked > 0
                          ? "Critical security issues found"
                          : "Some security improvements needed"}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {checkedCount} of {totalCount} checks completed ({completionPercentage}%)
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-destructive/10 p-3 rounded-lg text-center">
                      <div className="text-2xl font-bold text-destructive">{criticalUnchecked}</div>
                      <div className="text-xs text-muted-foreground">Critical</div>
                    </div>
                    <div className="bg-orange-500/10 p-3 rounded-lg text-center">
                      <div className="text-2xl font-bold text-orange-500">{highUnchecked}</div>
                      <div className="text-xs text-muted-foreground">High</div>
                    </div>
                    <div className="bg-yellow-500/10 p-3 rounded-lg text-center">
                      <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-500">
                        {auditItems.filter(item => item.severity === "medium" && !item.checked).length}
                      </div>
                      <div className="text-xs text-muted-foreground">Medium</div>
                    </div>
                    <div className="bg-blue-500/10 p-3 rounded-lg text-center">
                      <div className="text-2xl font-bold text-blue-500">
                        {auditItems.filter(item => item.severity === "low" && !item.checked).length}
                      </div>
                      <div className="text-xs text-muted-foreground">Low</div>
                    </div>
                  </div>

                  <div className="bg-muted/30 p-4 rounded-lg">
                    <h4 className="font-semibold mb-2">Recommendations</h4>
                    <ul className="text-sm text-muted-foreground space-y-1 list-disc list-inside">
                      {criticalUnchecked > 0 && (
                        <li>Address {criticalUnchecked} critical security issues immediately</li>
                      )}
                      {highUnchecked > 0 && (
                        <li>Review and fix {highUnchecked} high-priority items within 48 hours</li>
                      )}
                      <li>Schedule regular security audits (monthly recommended)</li>
                      <li>Keep detailed documentation of all security measures</li>
                      <li>Subscribe to security mailing lists for your distribution</li>
                    </ul>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </Sidebar>
  );
};

export default SecurityAudit;
