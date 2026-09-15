
import Dashboard from './components/Dashboard';
import { Spotlight } from './components/ui/Spotlight';
import { BackgroundBeams } from './components/ui/BackgroundBeams';
import { BentoDashboard } from './components/dashboard/BentoDashboard';

function App() {
  return (
    <div className="min-h-screen bg-dark-bg text-white selection:bg-white/30 relative">
      <Spotlight className="-top-40 left-0 md:left-60 md:-top-20" fill="#f59e0b" />
      <BackgroundBeams />
      
      <div className="relative z-10 pt-20 pb-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-12 text-center">
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-4">
            Next-Gen <span className="text-amber-500">Telemetry</span>
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto text-lg">
            High-performance vulnerability monitoring and threat sandboxing.
          </p>
        </div>
        
        <BentoDashboard />
      </div>

      <div className="relative z-10 border-t border-white/10 mt-12 bg-black/50 backdrop-blur-3xl">
        <Dashboard />
      </div>
    </div>
  );
}

export default App;
