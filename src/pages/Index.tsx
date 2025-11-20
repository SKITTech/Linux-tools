import { BridgeConfigForm } from "@/components/BridgeConfigForm";
import { Network, Info } from "lucide-react";
import { Card } from "@/components/ui/card";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3">
            <Network className="w-8 h-8 text-primary" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">Linux Bridge Generator</h1>
              <p className="text-sm text-muted-foreground">Generate network bridge configuration commands for KVM/Linux servers</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Info Card */}
        <Card className="p-4 mb-6 bg-accent/10 border-accent/20">
          <div className="flex gap-3">
            <Info className="w-5 h-5 text-accent shrink-0 mt-0.5" />
            <div className="text-sm text-foreground">
              <p className="font-medium mb-1">About Network Bridges</p>
              <p className="text-muted-foreground">
                A network bridge connects two or more network segments, allowing virtual machines to appear on the same network as the host. 
                This tool generates the necessary commands to create and configure a Linux bridge interface for KVM virtualization.
              </p>
            </div>
          </div>
        </Card>

        {/* Form */}
        <BridgeConfigForm />

        {/* Footer Info */}
        <div className="mt-8 pt-6 border-t border-border">
          <p className="text-sm text-muted-foreground text-center">
            Based on <a href="https://www.virtualizor.com/docs/admin/kvm-bridge/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Virtualizor KVM Bridge Documentation</a>
          </p>
        </div>
      </main>
    </div>
  );
};

export default Index;
