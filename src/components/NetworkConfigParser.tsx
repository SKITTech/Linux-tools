import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { FileText, Upload, ChevronDown, Sparkles } from "lucide-react";
import { parseNetworkConfig } from "@/utils/configParser";
import { ParsedConfig } from "@/types/networkConfig";
import { toast } from "sonner";

interface NetworkConfigParserProps {
  onParsed: (config: ParsedConfig) => void;
}

export const NetworkConfigParser = ({ onParsed }: NetworkConfigParserProps) => {
  const [configText, setConfigText] = useState("");
  const [isOpen, setIsOpen] = useState(false);

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
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card className="overflow-hidden border-border">
        <CollapsibleTrigger asChild>
          <button className="w-full flex items-center justify-between px-5 py-4 hover:bg-muted/30 transition-colors text-left">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent/10 border border-accent/20">
                <Sparkles className="w-4 h-4 text-accent" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">Smart Config Parser</h3>
                <p className="text-xs text-muted-foreground">
                  Paste an existing config to auto-fill fields
                </p>
              </div>
            </div>
            <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${isOpen ? "rotate-180" : ""}`} />
          </button>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <CardContent className="pt-0 pb-5 px-5 border-t border-border">
            <div className="space-y-4 pt-4">
              <div className="space-y-1.5">
                <Label htmlFor="configText" className="text-foreground text-sm">
                  Network Configuration File
                </Label>
                <Textarea
                  id="configText"
                  placeholder={`Paste your config here, e.g.:\n\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.168.1.10/24]\n      gateway4: 192.168.1.1`}
                  value={configText}
                  onChange={(e) => setConfigText(e.target.value)}
                  className="bg-background border-input min-h-[160px] font-mono text-sm resize-y"
                />
              </div>

              <Button
                onClick={handleParse}
                className="w-full gap-2"
              >
                <Upload className="w-4 h-4" />
                Parse &amp; Auto-Fill
              </Button>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
};
