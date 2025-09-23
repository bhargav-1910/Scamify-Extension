import { Card } from "@/components/ui/card";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from "recharts";

const ThreatChart = () => {
  const monthlyData = [
    { month: "Jan", phishing: 1200, malware: 800, spam: 1500 },
    { month: "Feb", phishing: 1350, malware: 750, spam: 1200 },
    { month: "Mar", phishing: 1800, malware: 900, spam: 1800 },
    { month: "Apr", phishing: 2100, malware: 1100, spam: 1600 },
    { month: "May", phishing: 2400, malware: 1200, spam: 1900 },
    { month: "Jun", phishing: 2800, malware: 1400, spam: 2100 }
  ];

  const threatTypes = [
    { name: "Email Phishing", value: 45, color: "#00d4ff" },
    { name: "SMS Phishing", value: 25, color: "#8b5cf6" },
    { name: "Voice Phishing", value: 15, color: "#ff4d6d" },
    { name: "Social Media", value: 10, color: "#22c55e" },
    { name: "Other", value: 5, color: "#f59e0b" }
  ];

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-2 border-primary/20">
        <h3 className="text-xl font-bold mb-6 text-primary">Monthly Threat Trends</h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={monthlyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis 
                dataKey="month" 
                axisLine={false}
                tickLine={false}
                tick={{ fill: "hsl(var(--muted-foreground))" }}
              />
              <YAxis 
                axisLine={false}
                tickLine={false}
                tick={{ fill: "hsl(var(--muted-foreground))" }}
              />
              <Line 
                type="monotone" 
                dataKey="phishing" 
                stroke="hsl(var(--cyber-blue))" 
                strokeWidth={3}
                dot={{ fill: "hsl(var(--cyber-blue))", strokeWidth: 2, r: 6 }}
                activeDot={{ r: 8, stroke: "hsl(var(--cyber-blue))", strokeWidth: 2 }}
              />
              <Line 
                type="monotone" 
                dataKey="malware" 
                stroke="hsl(var(--cyber-red))" 
                strokeWidth={3}
                dot={{ fill: "hsl(var(--cyber-red))", strokeWidth: 2, r: 6 }}
              />
              <Line 
                type="monotone" 
                dataKey="spam" 
                stroke="hsl(var(--cyber-yellow))" 
                strokeWidth={3}
                dot={{ fill: "hsl(var(--cyber-yellow))", strokeWidth: 2, r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card className="p-6 bg-gradient-to-br from-card to-card/80 border-2 border-primary/20">
        <h3 className="text-xl font-bold mb-6 text-primary">Threat Distribution</h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={threatTypes}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={120}
                paddingAngle={2}
                dataKey="value"
              >
                {threatTypes.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="space-y-2">
          {threatTypes.map((threat, index) => (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div 
                  className="w-3 h-3 rounded-full" 
                  style={{ backgroundColor: threat.color }}
                />
                <span className="text-sm text-muted-foreground">{threat.name}</span>
              </div>
              <span className="text-sm font-medium">{threat.value}%</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default ThreatChart;