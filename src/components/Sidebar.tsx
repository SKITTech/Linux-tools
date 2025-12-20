import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { LucideIcon, Menu, X, Activity, Network, Wifi, Globe, Shield, FileText, ShieldAlert, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";

interface SidebarItem {
  to: string;
  icon: LucideIcon;
  label: string;
}

const navItems: SidebarItem[] = [
  { to: "/", icon: Activity, label: "Bridge Generator" },
  { to: "/subnet-calculator", icon: Network, label: "Subnet Calculator" },
  { to: "/network-diagnostics", icon: Wifi, label: "Network Diagnostics" },
  { to: "/ipv6-converter", icon: Globe, label: "IPv6 Converter" },
  { to: "/firewall-generator", icon: Shield, label: "Firewall Generator" },
  { to: "/log-analyzer", icon: FileText, label: "Log Analyzer" },
  { to: "/security-audit", icon: ShieldAlert, label: "Security Audit" },
  { to: "/command-library", icon: Terminal, label: "Command Library" },
];

interface SidebarProps {
  children: React.ReactNode;
}

export const Sidebar = ({ children }: SidebarProps) => {
  const [isOpen, setIsOpen] = useState(true);
  const location = useLocation();

  return (
    <div className="flex min-h-screen w-full">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 z-40 h-screen bg-card border-r border-border transition-all duration-300",
          isOpen ? "w-64" : "w-16"
        )}
      >
        {/* Toggle Button */}
        <div className="flex items-center justify-between p-4 border-b border-border">
          {isOpen && (
            <div className="flex items-center gap-2">
              <Network className="w-6 h-6 text-primary" />
              <span className="font-semibold text-foreground">Net Tools</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsOpen(!isOpen)}
            className="p-2 hover:bg-accent"
          >
            {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.to;

            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground"
                )}
                title={!isOpen ? item.label : undefined}
              >
                <Icon className="w-5 h-5 shrink-0" />
                {isOpen && <span className="text-sm font-medium">{item.label}</span>}
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <main
        className={cn(
          "flex-1 transition-all duration-300",
          isOpen ? "ml-64" : "ml-16"
        )}
      >
        {children}
      </main>
    </div>
  );
};
