import { useEffect, useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Shield, Upload, Activity, Code, TerminalSquare, AlertCircle, Play, Square } from 'lucide-react';
import { cn } from '../lib/utils';
import AgentFeed from './AgentFeed';

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [functions, setFunctions] = useState<any[]>([]);
  const [selectedFunc, setSelectedFunc] = useState<any | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [metrics, setMetrics] = useState({ total_scans: 0, vulnerabilities_found: 0, patches_validated: 0 });
  const [history, setHistory] = useState<any[]>([]);
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 });
  const wsRef = useRef<WebSocket | null>(null);
  const cancelledRef = useRef(false);

  const loadDashboardData = async () => {
    try {
      const [metricsResponse, scansResponse] = await Promise.all([
        fetch('http://localhost:8000/api/metrics'),
        fetch('http://localhost:8000/api/scan/status'),
      ]);
      if (metricsResponse.ok) setMetrics(await metricsResponse.json());
      if (scansResponse.ok) {
        const data = await scansResponse.json();
        setHistory(Object.values(data.scans).slice(0, 5));
      }
    } catch {
      // The scan workflow reports connection errors where the user acts on them.
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.[0]) return;
    const uploadedFile = e.target.files[0];
    setFile(uploadedFile);
    setFunctions([]);
    setSelectedFunc(null);
    setUploadError('');

    const formData = new FormData();
    formData.append('file', uploadedFile);

    try {
      const res = await fetch('http://localhost:8000/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed');
      setFunctions(data.functions);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
    }
  };

  const runScan = (func: any, clearEvents: boolean) => new Promise<void>((resolve) => {
    setSelectedFunc(func);
    if (clearEvents) setEvents([]);
    setEvents((previous) => [
      ...previous,
      { type: 'batch_function', function_name: func.name, relative_path: func.relative_path },
    ]);

    if (wsRef.current) wsRef.current.close();
    const ws = new WebSocket('ws://localhost:8000/ws/scan');
    wsRef.current = ws;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve();
    };

    ws.onopen = () => {
      ws.send(JSON.stringify(func));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents((prev) => [...prev, { ...data, function_name: func.name }]);
      if (data.type === 'complete' || data.type === 'error') {
        ws.close();
        finish();
      }
    };

    ws.onerror = () => {
      setEvents((prev) => [...prev, { type: 'error', message: 'WebSocket connection failed', function_name: func.name }]);
      finish();
    };
    ws.onclose = finish;
  });

  const startScan = async (func: any) => {
    cancelledRef.current = false;
    setIsScanning(true);
    setBatchProgress({ current: 1, total: 1 });
    await runScan(func, true);
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const startBatchScan = async () => {
    cancelledRef.current = false;
    setIsScanning(true);
    setEvents([]);
    for (let index = 0; index < functions.length; index += 1) {
      if (cancelledRef.current) break;
      setBatchProgress({ current: index + 1, total: functions.length });
      await runScan(functions[index], false);
    }
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const cancelScan = () => {
    cancelledRef.current = true;
    wsRef.current?.close();
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
  };

  return (
    <div className="min-h-screen p-8 lg:p-12 font-sans relative overflow-hidden">
      {/* Background Noise & Gradients */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-[0.03] bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>
      <div className="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-900/20 blur-[120px] pointer-events-none z-0"></div>
      
      <div className="relative z-10 max-w-7xl mx-auto">
        <header className="mb-8 flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
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
          <div className="grid w-full grid-cols-3 border-y border-white/10 md:w-auto md:min-w-[420px]">
            {[
              ['Scans', metrics.total_scans],
              ['Vulnerabilities', metrics.vulnerabilities_found],
              ['Validated', metrics.patches_validated],
            ].map(([label, value]) => (
              <div key={label} className="px-4 py-3 text-center">
                <div className="text-xl font-semibold text-white">{value}</div>
                <div className="text-xs text-white/40">{label}</div>
              </div>
            ))}
          </div>
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
                  <p className="mb-2 text-sm text-white/60"><span className="font-semibold text-white">Upload source or ZIP</span></p>
                </div>
                <input type="file" accept=".py,.c,.h,.cpp,.cc,.cxx,.hpp,.java,.js,.mjs,.cjs,.zip" className="hidden" onChange={handleFileUpload} />
              </label>

              {uploadError && (
                <div className="mt-4 flex items-start gap-2 text-sm text-red-300">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {file && (
                <div className="mt-6">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h3 className="text-sm font-medium text-white/70">Detected Functions</h3>
                    {functions.length > 1 && !isScanning && (
                      <button
                        type="button"
                        onClick={startBatchScan}
                        className="flex items-center gap-1.5 text-xs text-white/60 hover:text-white"
                      >
                        <Play className="h-3.5 w-3.5" /> Scan all {functions.length}
                      </button>
                    )}
                  </div>
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {functions.map((f, i) => (
                      <button
                        key={i}
                        disabled={isScanning}
                        onClick={() => startScan(f)}
                        className={cn(
                          "w-full text-left p-3 rounded-lg border transition-all text-sm flex items-center justify-between group disabled:cursor-not-allowed disabled:opacity-50",
                          selectedFunc?.id === f.id 
                            ? "bg-white/10 border-white/30 text-white" 
                            : "bg-white/5 border-white/10 text-white/60 hover:bg-white/10 hover:text-white"
                        )}
                      >
                        <span className="min-w-0 flex items-center gap-2">
                          <Code className="w-4 h-4 shrink-0"/>
                          <span className="min-w-0">
                            <span className="block truncate">{f.name}</span>
                            <span className="block truncate text-xs text-white/35">{f.relative_path}</span>
                          </span>
                        </span>
                        <Activity className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {history.length > 0 && (
                <div className="mt-6 border-t border-white/10 pt-4">
                  <h3 className="mb-3 text-xs font-medium text-white/40">Recent scans</h3>
                  <div className="space-y-2">
                    {history.map((scan) => (
                      <div key={scan.scan_id} className="flex items-center justify-between gap-3 text-xs">
                        <span className="truncate text-white/60">{scan.function_id}</span>
                        <span className="shrink-0 font-mono text-white/35">{scan.judge_verdict || scan.pipeline_status}</span>
                      </div>
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
                  <div className="ml-auto flex items-center gap-3 text-xs text-white/50">
                    <span className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      {batchProgress.total > 1 ? `${batchProgress.current}/${batchProgress.total}` : 'Running'}
                    </span>
                    <button type="button" onClick={cancelScan} title="Cancel scan" aria-label="Cancel scan" className="p-1 hover:text-white">
                      <Square className="h-3.5 w-3.5" />
                    </button>
                  </div>
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
