import { Card } from "@/components/ui/card";
import cyberGlobe from "@/assets/cyber-globe.jpg";

const WorldMap = () => {
  const regions = [
    { name: "North America", threats: 2847, status: "high", x: "25%", y: "35%" },
    { name: "Europe", threats: 1923, status: "medium", x: "50%", y: "30%" },
    { name: "Asia Pacific", threats: 3421, status: "critical", x: "75%", y: "40%" },
    { name: "South America", threats: 892, status: "low", x: "30%", y: "65%" },
    { name: "Africa", threats: 654, status: "low", x: "55%", y: "60%" },
    { name: "Middle East", threats: 1245, status: "medium", x: "60%", y: "45%" }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case "critical": return "bg-cyber-red shadow-[0_0_20px_hsl(var(--cyber-red)/0.8)]";
      case "high": return "bg-destructive shadow-[0_0_15px_hsl(var(--destructive)/0.6)]";
      case "medium": return "bg-cyber-yellow shadow-[0_0_15px_hsl(var(--cyber-yellow)/0.6)]";
      case "low": return "bg-cyber-green shadow-[0_0_15px_hsl(var(--cyber-green)/0.6)]";
      default: return "bg-primary";
    }
  };

  return (
    <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-2 border-primary/20">
      <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
        <span className="text-primary">🌍</span>
        Global Threat Distribution
      </h3>
      
      <div className="relative w-full h-96 rounded-lg overflow-hidden">
        <img 
          src={cyberGlobe} 
          alt="Global cyber threat visualization" 
          className="w-full h-full object-cover opacity-80"
        />
        <div className="absolute inset-0 bg-background/40" />
        
        {regions.map((region, index) => (
          <div
            key={index}
            className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer"
            style={{ left: region.x, top: region.y }}
          >
            <div className={`w-4 h-4 rounded-full ${getStatusColor(region.status)} animate-pulse`} />
            <div className="absolute bottom-6 left-1/2 transform -translate-x-1/2 bg-black/90 backdrop-blur-sm rounded-lg p-3 min-w-48 opacity-0 group-hover:opacity-100 transition-opacity border border-primary/30">
              <h4 className="font-semibold text-primary">{region.name}</h4>
              <p className="text-sm text-muted-foreground">Threats: {region.threats.toLocaleString()}</p>
              <p className="text-sm capitalize">Status: 
                <span className={`ml-1 font-medium ${
                  region.status === 'critical' ? 'text-cyber-red' :
                  region.status === 'high' ? 'text-destructive' :
                  region.status === 'medium' ? 'text-cyber-yellow' :
                  'text-cyber-green'
                }`}>
                  {region.status}
                </span>
              </p>
            </div>
          </div>
        ))}
      </div>
      
      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-cyber-red animate-pulse" />
          <span className="text-sm text-muted-foreground">Critical</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-destructive animate-pulse" />
          <span className="text-sm text-muted-foreground">High</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-cyber-yellow animate-pulse" />
          <span className="text-sm text-muted-foreground">Medium</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-cyber-green animate-pulse" />
          <span className="text-sm text-muted-foreground">Low</span>
        </div>
      </div>
    </Card>
  );
};

export default WorldMap;