import { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Shield, Upload, Activity, Code, TerminalSquare } from 'lucide-react';
import { cn } from '../lib/utils';
import AgentFeed from './AgentFeed';

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [functions, setFunctions] = useState<any[]>([]);
  const [selectedFunc, setSelectedFunc] = useState<any | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.[0]) return;
    const uploadedFile = e.target.files[0];
    setFile(uploadedFile);

    const formData = new FormData();
    formData.append('file', uploadedFile);

    try {
      const res = await fetch('http://localhost:8000/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      setFunctions(data.functions);
    } catch (err) {
      console.error(err);
    }
  };

  const startScan = (func: any) => {
    setSelectedFunc(func);
    setEvents([]);
    setIsScanning(true);

    if (wsRef.current) wsRef.current.close();
    
    const ws = new WebSocket('ws://localhost:8000/ws/scan');
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify(func));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents((prev) => [...prev, data]);
      if (data.type === 'complete' || data.type === 'error') {
        setIsScanning(false);
      }
    };
  };

  return (
    <div className="min-h-screen p-8 lg:p-12 font-sans relative overflow-hidden">
      {/* Background Noise & Gradients */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-[0.03] bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>
      <div className="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-900/20 blur-[120px] pointer-events-none z-0"></div>
      
      <div className="relative z-10 max-w-7xl mx-auto">
        <header className="mb-12 flex items-center justify-between">
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-4"
          >
            <div className="p-3 bg-white/5 rounded-2xl border border-white/10 shadow-2xl backdrop-blur-md">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-white">VulnGuard</h1>
              <p className="text-white/50 text-sm tracking-widest uppercase">Autonomous Security Agents</p>
            </div>
          </motion.div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Upload & Code */}
          <div className="lg:col-span-4 flex flex-col gap-6">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="glassmorphism rounded-3xl p-6"
            >
              <h2 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                <Upload className="w-5 h-5 text-white/50" /> Upload Target
              </h2>
              
              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-white/20 rounded-2xl cursor-pointer hover:bg-white/5 hover:border-white/40 transition-all">
                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                  <Upload className="w-8 h-8 mb-3 text-white/40" />
                  <p className="mb-2 text-sm text-white/60"><span className="font-semibold text-white">Click to upload</span> or drag and drop</p>
                </div>
                <input type="file" className="hidden" onChange={handleFileUpload} />
              </label>

              {file && (
                <div className="mt-6">
                  <h3 className="text-sm font-medium text-white/70 mb-3">Detected Functions</h3>
                  <div className="space-y-2">
                    {functions.map((f, i) => (
                      <button
                        key={i}
                        onClick={() => startScan(f)}
                        className={cn(
                          "w-full text-left p-3 rounded-xl border transition-all text-sm flex items-center justify-between group",
                          selectedFunc?.id === f.id 
                            ? "bg-white/10 border-white/30 text-white" 
                            : "bg-white/5 border-white/10 text-white/60 hover:bg-white/10 hover:text-white"
                        )}
                      >
                        <span className="flex items-center gap-2"><Code className="w-4 h-4"/> {f.name}</span>
                        <Activity className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          </div>

          {/* Right Column: Agent Feed */}
          <div className="lg:col-span-8 flex flex-col gap-6">
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glassmorphism rounded-3xl p-0 overflow-hidden flex flex-col h-[700px]"
            >
              <div className="p-4 border-b border-white/10 bg-white/5 flex items-center gap-3">
                <TerminalSquare className="w-5 h-5 text-white/50" />
                <h2 className="text-sm font-medium text-white/80">Live Agent Stream</h2>
                {isScanning && (
                  <span className="ml-auto flex items-center gap-2 text-xs text-white/50">
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" /> Running
                  </span>
                )}
              </div>
              
              <div className="flex-1 p-6 overflow-y-auto">
                <AgentFeed events={events} selectedFunc={selectedFunc} />
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}
