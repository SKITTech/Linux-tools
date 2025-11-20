import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { FileText, Upload } from "lucide-react";
import { parseNetworkConfig } from "@/utils/configParser";
import { ParsedConfig } from "@/types/networkConfig";
import { toast } from "sonner";

interface NetworkConfigParserProps {
  onParsed: (config: ParsedConfig) => void;
}

export const NetworkConfigParser = ({ onParsed }: NetworkConfigParserProps) => {
  const [configText, setConfigText] = useState("");

  const handleParse = () => {
    if (!configText.trim()) {
      toast.error("Please paste a network configuration first");
      return;
    }

    const parsed = parseNetworkConfig(configText);
    
    if (!parsed.ipAddress && !parsed.gateway && !parsed.netmask) {
      toast.error("Could not extract network information from the config");
      return;
    }

    onParsed(parsed);
    toast.success("Configuration parsed and auto-filled!");
  };

  return (
    <Card className="p-6 bg-card border-border">
      <div className="flex items-center gap-2 mb-4">
        <FileText className="w-5 h-5 text-primary" />
        <h3 className="text-lg font-semibold text-foreground">Smart Configuration Parser</h3>
      </div>
      
      <p className="text-sm text-muted-foreground mb-4">
        Paste your existing network configuration file (Netplan, ifcfg, or similar) and automatically extract IP, gateway, netmask, and interface details.
      </p>

      <div className="space-y-4">
        <div>
          <Label htmlFor="configText" className="text-foreground">
            Network Configuration File
          </Label>
          <Textarea
            id="configText"
            placeholder={`Paste your config here, e.g.:\n\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.168.1.10/24]\n      gateway4: 192.168.1.1`}
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            className="mt-1.5 bg-background border-input min-h-[200px] font-mono text-sm"
          />
        </div>

        <Button 
          onClick={handleParse} 
          className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
        >
          <Upload className="w-4 h-4 mr-2" />
          Parse and Auto-Fill
        </Button>
      </div>
    </Card>
  );
};
