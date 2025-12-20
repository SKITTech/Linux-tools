import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";

interface CommandOutputProps {
  commands: string;
}

export const CommandOutput = ({ commands }: CommandOutputProps) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Parse commands into individual executable lines (skip comments and empty lines)
  const parseCommands = (commandString: string): { line: string; isCommand: boolean; originalIndex: number }[] => {
    return commandString.split('\n').map((line, idx) => ({
      line,
      isCommand: line.trim() !== '' && !line.trim().startsWith('#'),
      originalIndex: idx
    }));
  };

  const parsedLines = parseCommands(commands);

  const handleCopyCommand = async (command: string, index: number) => {
    await navigator.clipboard.writeText(command);
    setCopiedIndex(index);
    toast.success("Command copied!");
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="font-mono text-sm space-y-1">
      {parsedLines.map(({ line, isCommand, originalIndex }) => (
        <div
          key={originalIndex}
          className={`flex items-start gap-2 ${
            isCommand ? 'group hover:bg-terminal-border/30 rounded px-2 py-1 -mx-2' : 'px-2 py-0.5 -mx-2'
          }`}
        >
          <pre className={`flex-1 whitespace-pre-wrap break-all ${
            line.trim().startsWith('#') ? 'text-muted-foreground' : 'text-terminal-text'
          }`}>
            {line}
          </pre>
          {isCommand && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handleCopyCommand(line, originalIndex)}
              className="opacity-0 group-hover:opacity-100 transition-opacity h-6 w-6 p-0 shrink-0 bg-terminal-border/50 hover:bg-terminal-border text-terminal-text"
            >
              {copiedIndex === originalIndex ? (
                <Check className="w-3 h-3" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </Button>
          )}
        </div>
      ))}
    </div>
  );
};
