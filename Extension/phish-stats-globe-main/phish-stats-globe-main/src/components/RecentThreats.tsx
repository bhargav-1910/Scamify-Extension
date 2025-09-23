import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Shield, Clock } from "lucide-react";

const RecentThreats = () => {
  const threats = [
    {
      id: 1,
      title: "Banking Credential Harvest",
      description: "Fake Chase Bank login page targeting mobile users",
      severity: "critical",
      location: "United States",
      time: "2 min ago",
      targets: 1247
    },
    {
      id: 2,
      title: "Microsoft 365 Phishing Campaign",
      description: "Sophisticated email campaign mimicking Microsoft authentication",
      severity: "high",
      location: "Global",
      time: "15 min ago",
      targets: 892
    },
    {
      id: 3,
      title: "Cryptocurrency Scam",
      description: "Fake investment platform promising high returns",
      severity: "medium",
      location: "Europe",
      time: "32 min ago",
      targets: 456
    },
    {
      id: 4,
      title: "Social Media Account Takeover",
      description: "Automated bot network targeting Instagram accounts",
      severity: "high",
      location: "Asia Pacific",
      time: "1 hour ago",
      targets: 2341
    },
    {
      id: 5,
      title: "SMS Verification Bypass",
      description: "SIM swapping attacks targeting 2FA systems",
      severity: "critical",
      location: "North America",
      time: "2 hours ago",
      targets: 189
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-cyber-red text-white";
      case "high": return "bg-destructive text-white";
      case "medium": return "bg-cyber-yellow text-black";
      case "low": return "bg-cyber-green text-black";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
      case "high":
        return <AlertTriangle className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-2 border-primary/20">
      <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
        <Clock className="h-5 w-5 text-primary" />
        Recent Threat Detections
      </h3>
      
      <div className="space-y-4 max-h-96 overflow-y-auto">
        {threats.map((threat) => (
          <div key={threat.id} className="p-4 rounded-lg bg-secondary/30 border border-border/50 hover:bg-secondary/50 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <Badge className={`${getSeverityColor(threat.severity)} flex items-center gap-1`}>
                  {getSeverityIcon(threat.severity)}
                  {threat.severity}
                </Badge>
                <span className="text-sm text-muted-foreground">{threat.time}</span>
              </div>
              <div className="text-right">
                <p className="text-sm font-medium">{threat.targets.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">targets</p>
              </div>
            </div>
            
            <h4 className="font-semibold mb-1">{threat.title}</h4>
            <p className="text-sm text-muted-foreground mb-2">{threat.description}</p>
            
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">📍 {threat.location}</span>
              <div className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${
                  threat.severity === 'critical' ? 'bg-cyber-red animate-pulse' :
                  threat.severity === 'high' ? 'bg-destructive animate-pulse' :
                  threat.severity === 'medium' ? 'bg-cyber-yellow' :
                  'bg-cyber-green'
                }`} />
                <span className="text-xs text-muted-foreground">Active</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

export default RecentThreats;