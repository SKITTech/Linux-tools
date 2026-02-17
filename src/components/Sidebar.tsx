import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { LucideIcon, Menu, Activity, Network, Wifi, Globe, Shield, FileText, ShieldAlert, Terminal, GitCompare, ChevronLeft, Server, LayoutDashboard, Sun, Moon } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/ThemeProvider";

interface SidebarItem {
  to: string;
  icon: LucideIcon;
  label: string;
}

const navItems: SidebarItem[] = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/bridge-generator", icon: Activity, label: "Bridge Generator" },
  { to: "/subnet-calculator", icon: Network, label: "Subnet Calculator" },
  { to: "/network-diagnostics", icon: Wifi, label: "Network Diagnostics" },
  { to: "/ipv6-converter", icon: Globe, label: "IPv6 Converter" },
  { to: "/firewall-generator", icon: Shield, label: "Firewall Generator" },
  { to: "/log-analyzer", icon: FileText, label: "Log Analyzer" },
  { to: "/security-audit", icon: ShieldAlert, label: "Security Audit" },
  { to: "/command-library", icon: Terminal, label: "Command Library" },
  { to: "/database-comparator", icon: GitCompare, label: "DB Comparator" },
];

interface SidebarProps {
  children: React.ReactNode;
}

export const Sidebar = ({ children }: SidebarProps) => {
  const [isOpen, setIsOpen] = useState(true);
  const location = useLocation();
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="flex min-h-screen w-full">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 z-40 h-screen bg-card/80 backdrop-blur-xl border-r border-border/50 transition-all duration-300 ease-in-out",
          isOpen ? "w-[260px]" : "w-[60px]"
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 h-16 border-b border-border/50">
          {isOpen && (
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <Server className="w-4.5 h-4.5 text-primary" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-bold tracking-tight text-foreground leading-tight">System Admin</span>
                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest">Tools</span>
              </div>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsOpen(!isOpen)}
            className="h-8 w-8 shrink-0 hover:bg-muted/80 rounded-lg"
          >
            {isOpen ? <ChevronLeft className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="p-2 space-y-0.5 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.to;

            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 group relative",
                  isActive
                    ? "bg-primary text-primary-foreground shadow-sm shadow-primary/25"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
                )}
                title={!isOpen ? item.label : undefined}
              >
                <Icon className={cn("w-[18px] h-[18px] shrink-0 transition-transform duration-200", !isActive && "group-hover:scale-110")} />
                {isOpen && <span className="text-[13px] font-medium truncate">{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="absolute bottom-0 left-0 right-0 p-3 border-t border-border/50 space-y-2">
          <Button
            variant="ghost"
            size={isOpen ? "default" : "icon"}
            onClick={toggleTheme}
            className={cn("w-full hover:bg-muted/80 rounded-lg", isOpen ? "justify-start gap-2.5 px-3" : "h-9 w-9 mx-auto")}
          >
            {theme === "dark" ? <Sun className="w-4 h-4 shrink-0" /> : <Moon className="w-4 h-4 shrink-0" />}
            {isOpen && <span className="text-[13px] font-medium">{theme === "dark" ? "Light Mode" : "Dark Mode"}</span>}
          </Button>
          {isOpen && (
            <div className="text-[10px] text-muted-foreground/60 text-center uppercase tracking-wider">
              v2.0 · 2026
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main
        className={cn(
          "flex-1 transition-all duration-300 ease-in-out",
          isOpen ? "ml-[260px]" : "ml-[60px]"
        )}
      >
        {children}
      </main>
    </div>
  );
};
