import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Wrench, Scale, Terminal } from 'lucide-react';
import { cn } from '../lib/utils';

export default function AgentFeed({ events, selectedFunc }: { events: any[], selectedFunc: any }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  if (!selectedFunc) {
    return (
      <div className="flex h-full items-center justify-center text-white/30">
        <div className="flex flex-col items-center gap-4">
          <Terminal className="w-12 h-12" />
          <p>Select a function to begin analysis</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <AnimatePresence>
        {events.map((ev, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 10, filter: 'blur(10px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            className="flex flex-col gap-2"
          >
            {ev.type === 'status' && (
              <div className="flex items-center gap-2 text-sm text-white/50 font-mono">
                <span className="text-white/30">{'>'}</span> {ev.message}
              </div>
            )}
            
            {ev.type === 'triage_result' && (
              <div className="glassmorphism p-4 rounded-2xl flex items-center justify-between border-white/5">
                <div>
                  <h3 className="text-sm text-white/60 uppercase tracking-wider mb-1">ML Triage Score</h3>
                  <div className="text-2xl font-mono">
                    <span className={cn(ev.is_high_risk ? "text-red-400" : "text-green-400")}>{ev.score}</span>
                    <span className="text-white/30 text-lg">/100</span>
                  </div>
                </div>
                {ev.is_high_risk && (
                  <div className="px-3 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded-full text-xs font-medium animate-pulse">
                    HIGH RISK DETECTED
                  </div>
                )}
              </div>
            )}

            {ev.type === 'agent_update' && ev.agent === 'red_agent' && (
              ev.state.vulnerability_found ? (
                <div className="glassmorphism p-5 rounded-2xl border-red-500/20 bg-red-950/20 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-red-500/20 text-red-400 rounded-lg"><ShieldAlert className="w-5 h-5"/></div>
                    <h3 className="font-semibold text-red-200">Red Agent Attack Payload</h3>
                  </div>
                  <div className="bg-black/50 p-4 rounded-xl border border-white/5 overflow-x-auto">
                    <code className="text-sm text-red-300 whitespace-pre">{ev.state.exploit_harness || ev.state.error_logs}</code>
                  </div>
                </div>
              ) : (
                <div className="glassmorphism p-5 rounded-2xl border-green-500/20 bg-green-950/20 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-green-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-500/20 text-green-400 rounded-lg"><ShieldAlert className="w-5 h-5"/></div>
                    <h3 className="font-semibold text-green-200">Red Agent: No Exploit Found</h3>
                  </div>
                  <p className="text-white/70 text-sm mt-3 pl-11">The agent attempted to attack the function but could not find a working exploit.</p>
                </div>
              )
            )}

            {ev.type === 'agent_update' && ev.agent === 'blue_agent' && ev.state.patched_code && (
              <div className="glassmorphism p-5 rounded-2xl border-blue-500/20 bg-blue-950/20 relative overflow-hidden">
                 <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-blue-500/20 text-blue-400 rounded-lg"><Wrench className="w-5 h-5"/></div>
                  <h3 className="font-semibold text-blue-200">Blue Agent Secure Patch</h3>
                </div>
                <div className="bg-black/50 p-4 rounded-xl border border-white/5 overflow-x-auto">
                  <code className="text-sm text-blue-300 whitespace-pre">{ev.state.patched_code}</code>
                </div>
              </div>
            )}

            {ev.type === 'agent_update' && ev.agent === 'judge_agent' && (
              <div className="glassmorphism p-5 rounded-2xl border-yellow-500/20 bg-yellow-950/10 relative overflow-hidden">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-yellow-500/20 text-yellow-400 rounded-lg"><Scale className="w-5 h-5"/></div>
                  <h3 className="font-semibold text-yellow-200">Judge Agent Verdict</h3>
                </div>
                <p className="text-white/80 pl-11 mb-2">
                  Verdict: <span className="font-bold text-white">{ev.state.judge_verdict}</span>
                </p>
                {ev.state.error_logs && (
                  <div className="mt-2 ml-11 bg-black/50 p-3 rounded-xl border border-red-500/20 overflow-x-auto">
                    <code className="text-sm text-red-300 whitespace-pre-wrap">{ev.state.error_logs}</code>
                  </div>
                )}
              </div>
            )}

            {ev.type === 'error' && (
              <div className="glassmorphism p-5 rounded-2xl border-red-500/50 bg-red-950/20 relative overflow-hidden">
                <h3 className="text-red-400 font-bold mb-2">Pipeline Error</h3>
                <code className="text-red-300 text-sm whitespace-pre-wrap">{ev.message}</code>
              </div>
            )}

          </motion.div>
        ))}
      </AnimatePresence>
      <div ref={bottomRef} className="h-4" />
    </div>
  );
}
