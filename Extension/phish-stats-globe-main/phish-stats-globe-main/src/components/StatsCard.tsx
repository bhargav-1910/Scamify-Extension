import { Card } from "@/components/ui/card";
import { TrendingUp, TrendingDown, Shield, AlertTriangle } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: string;
  change: string;
  trend: "up" | "down";
  type: "threat" | "safe" | "warning" | "primary";
  icon: React.ReactNode;
}

const StatsCard = ({ title, value, change, trend, type, icon }: StatsCardProps) => {
  const getTypeStyles = () => {
    switch (type) {
      case "threat":
        return "bg-gradient-to-br from-cyber-red/20 to-destructive/20 border-cyber-red/30";
      case "safe":
        return "bg-gradient-to-br from-cyber-green/20 to-green-600/20 border-cyber-green/30";
      case "warning":
        return "bg-gradient-to-br from-cyber-yellow/20 to-yellow-600/20 border-cyber-yellow/30";
      default:
        return "bg-gradient-to-br from-cyber-blue/20 to-primary/20 border-primary/30";
    }
  };

  const getIconColor = () => {
    switch (type) {
      case "threat":
        return "text-cyber-red";
      case "safe":
        return "text-cyber-green";
      case "warning":
        return "text-cyber-yellow";
      default:
        return "text-primary";
    }
  };

  return (
    <Card className={`p-6 border-2 backdrop-blur-sm transition-all duration-300 hover:scale-105 hover:shadow-lg ${getTypeStyles()}`}>
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-muted-foreground text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold">{value}</p>
          <div className="flex items-center gap-1">
            {trend === "up" ? (
              <TrendingUp className="h-4 w-4 text-cyber-green" />
            ) : (
              <TrendingDown className="h-4 w-4 text-cyber-red" />
            )}
            <span className={`text-sm font-medium ${trend === "up" ? "text-cyber-green" : "text-cyber-red"}`}>
              {change}
            </span>
          </div>
        </div>
        <div className={`p-3 rounded-full bg-gradient-to-br from-black/20 to-black/40 ${getIconColor()}`}>
          {icon}
        </div>
      </div>
    </Card>
  );
};

export default StatsCard;