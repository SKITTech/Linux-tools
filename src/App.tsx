import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import Dashboard from "./pages/Dashboard";
import Index from "./pages/Index";
import SubnetCalculator from "./pages/SubnetCalculator";
import NetworkDiagnostics from "./pages/NetworkDiagnostics";
import IPv6Converter from "./pages/IPv6Converter";
import FirewallGenerator from "./pages/FirewallGenerator";
import LogAnalyzer from "./pages/LogAnalyzer";
import SecurityAudit from "./pages/SecurityAudit";
import CommandLibrary from "./pages/CommandLibrary";
import DatabaseComparator from "./pages/DatabaseComparator";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <HashRouter>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/bridge-generator" element={<Index />} />
            <Route path="/subnet-calculator" element={<SubnetCalculator />} />
            <Route path="/network-diagnostics" element={<NetworkDiagnostics />} />
            <Route path="/ipv6-converter" element={<IPv6Converter />} />
            <Route path="/firewall-generator" element={<FirewallGenerator />} />
            <Route path="/log-analyzer" element={<LogAnalyzer />} />
            <Route path="/security-audit" element={<SecurityAudit />} />
            <Route path="/command-library" element={<CommandLibrary />} />
            <Route path="/database-comparator" element={<DatabaseComparator />} />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </HashRouter>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
