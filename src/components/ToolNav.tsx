import { Link, useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface ToolNavProps {
  items: {
    to: string;
    icon: LucideIcon;
    label: string;
  }[];
}

export const ToolNav = ({ items }: ToolNavProps) => {
  const location = useLocation();

  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item) => {
        const Icon = item.icon;
        const isActive = location.pathname === item.to;
        
        return (
          <Button
            key={item.to}
            asChild
            variant={isActive ? "default" : "outline"}
            className={cn(
              "gap-2",
              isActive && "pointer-events-none"
            )}
          >
            <Link to={item.to}>
              <Icon className="w-4 h-4" />
              {item.label}
            </Link>
          </Button>
        );
      })}
    </div>
  );
};
