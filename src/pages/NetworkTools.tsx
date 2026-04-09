import { useState } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Wifi, Network, Globe } from "lucide-react";

// Lazy import the inner content components
import NetworkDiagnosticsContent from "@/components/network-tools/NetworkDiagnosticsContent";
import SubnetCalculatorContent from "@/components/network-tools/SubnetCalculatorContent";
import IPv6ConverterContent from "@/components/network-tools/IPv6ConverterContent";

const NetworkTools = () => {
  const [activeTab, setActiveTab] = useState("diagnostics");

  return (
    <Sidebar>
      <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted/20">
        <div className="container mx-auto px-4 py-6 max-w-[1600px]">
          {/* Header */}
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-primary/10 border border-primary/20 shadow-lg shadow-primary/5">
              <Network className="w-7 h-7 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">Network Tools</h1>
              <p className="text-sm text-muted-foreground">Diagnostics, subnet calculation, and IPv6 conversion in one place</p>
            </div>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-3 h-11 bg-muted/50">
              <TabsTrigger value="diagnostics" className="text-xs gap-1.5 data-[state=active]:shadow-md">
                <Wifi className="w-3.5 h-3.5" /> Network Diagnostics
              </TabsTrigger>
              <TabsTrigger value="subnet" className="text-xs gap-1.5 data-[state=active]:shadow-md">
                <Network className="w-3.5 h-3.5" /> Subnet Calculator
              </TabsTrigger>
              <TabsTrigger value="ipv6" className="text-xs gap-1.5 data-[state=active]:shadow-md">
                <Globe className="w-3.5 h-3.5" /> IPv6 Converter
              </TabsTrigger>
            </TabsList>

            <TabsContent value="diagnostics">
              <NetworkDiagnosticsContent />
            </TabsContent>
            <TabsContent value="subnet">
              <SubnetCalculatorContent />
            </TabsContent>
            <TabsContent value="ipv6">
              <IPv6ConverterContent />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </Sidebar>
  );
};

export default NetworkTools;
