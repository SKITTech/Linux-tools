import { BridgeConfigForm } from "@/components/BridgeConfigForm";
import { SEO } from "@/components/SEO";
import { Network, Server, Cpu, Shield, Zap } from "lucide-react";
import { Sidebar } from "@/components/Sidebar";
import { Badge } from "@/components/ui/badge";

const Index = () => {
  return (
    <Sidebar>
      <SEO title="Linux Bridge Generator — KVM/QEMU Configs" description="Generate production-ready Linux bridge configs for CentOS, AlmaLinux, and Ubuntu KVM servers." path="/#/bridge-generator" />
      <div className="min-h-screen bg-background">
        {/* Hero Header */}
        <header className="relative border-b border-border overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
          <div className="relative container mx-auto px-4 py-8 sm:px-6 lg:px-8">
            <div className="flex items-start gap-4">
              <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 border border-primary/20 shrink-0">
                <Network className="w-7 h-7 text-primary" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <h1 className="text-2xl font-bold text-foreground tracking-tight">
                    Linux Bridge Generator
                  </h1>
                  <Badge variant="secondary" className="text-xs font-mono">v2.0</Badge>
                </div>
                <p className="text-sm text-muted-foreground max-w-2xl">
                  Generate production-ready network bridge configurations for KVM/QEMU virtualization servers.
                  Supports CentOS, AlmaLinux, and Ubuntu with IPv6, bonding, and custom DNS.
                </p>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6">
              {[
                { icon: Server, label: "5 OS Distros", desc: "Supported" },
                { icon: Shield, label: "IPv6 Ready", desc: "Dual stack" },
                { icon: Cpu, label: "Bonding", desc: "Mode 1 & 4" },
                { icon: Zap, label: "Auto Parse", desc: "Config import" },
              ].map(({ icon: Icon, label, desc }) => (
                <div
                  key={label}
                  className="flex items-center gap-3 px-4 py-3 rounded-xl bg-card/60 backdrop-blur-sm border border-border/60"
                >
                  <Icon className="w-4 h-4 text-accent shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-foreground truncate">{label}</p>
                    <p className="text-xs text-muted-foreground">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-8 sm:px-6 lg:px-8">
          <BridgeConfigForm />
        </main>

        {/* Footer */}
        <footer className="border-t border-border py-4">
          <p className="text-xs text-muted-foreground text-center">
            Based on{" "}
            <a
              href="https://www.virtualizor.com/docs/admin/kvm-bridge/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              Virtualizor KVM Bridge Documentation
            </a>
          </p>
        </footer>
      </div>
    </Sidebar>
  );
};

export default Index;
