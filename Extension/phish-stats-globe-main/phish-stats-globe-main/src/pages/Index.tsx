import StatsCard from "@/components/StatsCard";
import WorldMap from "@/components/WorldMap";
import ThreatChart from "@/components/ThreatChart";
import RecentThreats from "@/components/RecentThreats";
import { Shield, AlertTriangle, TrendingUp, Users, Globe, Eye } from "lucide-react";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-primary/20 bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/20">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">Global Phishing Monitor</h1>
                <p className="text-sm text-muted-foreground">Real-time threat intelligence dashboard</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
              <span>Live Monitoring Active</span>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-6 py-8 space-y-8">
        {/* Hero Stats */}
        <section>
          <h2 className="text-3xl font-bold mb-2">Global Threat Overview</h2>
          <p className="text-muted-foreground mb-8">Live statistics from our global monitoring network</p>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <StatsCard
              title="Active Threats"
              value="12,847"
              change="+23.5%"
              trend="up"
              type="threat"
              icon={<AlertTriangle className="h-6 w-6" />}
            />
            <StatsCard
              title="Blocked Attacks"
              value="2.4M"
              change="+15.2%"
              trend="up"
              type="safe"
              icon={<Shield className="h-6 w-6" />}
            />
            <StatsCard
              title="Global Reach"
              value="195"
              change="+2"
              trend="up"
              type="primary"
              icon={<Globe className="h-6 w-6" />}
            />
            <StatsCard
              title="Monitored Users"
              value="48.2M"
              change="+8.7%"
              trend="up"
              type="primary"
              icon={<Users className="h-6 w-6" />}
            />
          </div>
        </section>

        {/* World Map */}
        <section>
          <WorldMap />
        </section>

        {/* Charts and Recent Threats */}
        <section className="grid lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <ThreatChart />
          </div>
          <div>
            <RecentThreats />
          </div>
        </section>

        {/* Additional Metrics */}
        <section>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-gradient-to-br from-card to-card/80 border-2 border-primary/20 rounded-lg p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-full bg-cyber-blue/20">
                  <Eye className="h-5 w-5 text-cyber-blue" />
                </div>
                <h3 className="font-semibold">Detection Rate</h3>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Current</span>
                  <span className="font-bold text-cyber-green">99.2%</span>
                </div>
                <div className="w-full bg-secondary/30 rounded-full h-2">
                  <div className="bg-gradient-to-r from-cyber-green to-cyber-blue h-2 rounded-full" style={{ width: '99.2%' }} />
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-card to-card/80 border-2 border-primary/20 rounded-lg p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-full bg-cyber-yellow/20">
                  <TrendingUp className="h-5 w-5 text-cyber-yellow" />
                </div>
                <h3 className="font-semibold">Response Time</h3>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Average</span>
                  <span className="font-bold text-cyber-yellow">0.3s</span>
                </div>
                <div className="text-xs text-muted-foreground">Real-time threat blocking</div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-card to-card/80 border-2 border-primary/20 rounded-lg p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-full bg-cyber-purple/20">
                  <Shield className="h-5 w-5 text-cyber-purple" />
                </div>
                <h3 className="font-semibold">Coverage</h3>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Protected</span>
                  <span className="font-bold text-cyber-purple">Global</span>
                </div>
                <div className="text-xs text-muted-foreground">24/7 monitoring active</div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-primary/20 mt-16">
        <div className="container mx-auto px-6 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
              <span>System Status: Operational</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Last updated: {new Date().toLocaleString()}
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;