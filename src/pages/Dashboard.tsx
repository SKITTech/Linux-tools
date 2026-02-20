import { Link } from "react-router-dom";
import { Sidebar } from "@/components/Sidebar";
import {
  Activity, Network, Wifi, Globe, Shield, FileText,
  ShieldAlert, Terminal, GitCompare, ArrowRight, Sparkles,
} from "lucide-react";

import { Card } from "@/components/ui/card";


const tools = [
  { to: "/bridge-generator", icon: Activity, label: "Bridge Generator", desc: "Generate Linux bridge configs for KVM servers", color: "from-primary/20 to-primary/5" },
  { to: "/subnet-calculator", icon: Network, label: "Subnet Calculator", desc: "Calculate subnets, CIDR, and IP ranges", color: "from-accent/20 to-accent/5" },
  { to: "/network-diagnostics", icon: Wifi, label: "Network Diagnostics", desc: "Run diagnostic checks on network endpoints", color: "from-success/20 to-success/5" },
  { to: "/ipv6-converter", icon: Globe, label: "IPv6 Converter", desc: "Convert between IPv4 and IPv6 formats", color: "from-primary/20 to-primary/5" },
  { to: "/firewall-generator", icon: Shield, label: "Firewall Generator", desc: "Create iptables and firewall rules", color: "from-destructive/20 to-destructive/5" },
  { to: "/log-analyzer", icon: FileText, label: "Log Analyzer", desc: "Parse and analyze system log files", color: "from-accent/20 to-accent/5" },
  { to: "/security-audit", icon: ShieldAlert, label: "Security Audit", desc: "Audit server security configurations", color: "from-destructive/20 to-destructive/5" },
  { to: "/command-library", icon: Terminal, label: "Command Library", desc: "Browse common sysadmin commands", color: "from-success/20 to-success/5" },
  { to: "/database-comparator", icon: GitCompare, label: "DB Comparator", desc: "Compare database structures & generate fix SQL", color: "from-primary/20 to-primary/5" },
];

const Dashboard = () => {
  return (
    <Sidebar>
      <div className="min-h-screen bg-background">
        {/* Hero */}
        <header className="border-b border-border/50 bg-gradient-to-br from-primary/5 via-background to-accent/5">
          <div className="container mx-auto px-6 py-10">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                <Sparkles className="w-5 h-5 text-primary" />
              </div>
              <h1 className="text-3xl font-bold text-foreground tracking-tight">Dashboard</h1>
            </div>
            <p className="text-muted-foreground ml-[52px]">
              Quick access to all your system administration tools
            </p>
          </div>
        </header>

        <main className="container mx-auto px-6 py-8 space-y-8">

          {/* Tools Grid */}
          <div>
            <h2 className="text-lg font-semibold text-foreground mb-4">All Tools</h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {tools.map((tool) => {
                const Icon = tool.icon;
                return (
                  <Link key={tool.to} to={tool.to} className="group">
                    <Card className="p-5 h-full bg-card/80 backdrop-blur border-border/50 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300">
                      <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${tool.color} flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-200`}>
                        <Icon className="w-5 h-5 text-foreground" />
                      </div>
                      <h3 className="font-semibold text-foreground mb-1 flex items-center gap-2">
                        {tool.label}
                        <ArrowRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-200" />
                      </h3>
                      <p className="text-sm text-muted-foreground leading-relaxed">{tool.desc}</p>
                    </Card>
                  </Link>
                );
              })}
            </div>
          </div>
        </main>
      </div>
    </Sidebar>
  );
};

export default Dashboard;
