import { Link } from "@tanstack/react-router";
import {
  ArrowUpRight,
  AudioLines,
  Blocks,
  Bot,
  Cpu,
  GitFork,
  Eye,
  Network,
  Server,
  SlidersHorizontal,
  Orbit,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";
import { useEffect, useRef } from "react";

export const modules = [
  {
    slug: "studio",
    index: "01",
    title: "STEEL Studio",
    eyebrow: "Sound / composition",
    summary: "A composition desk for patterns, voice, film and live signal.",
    accent: "from-orange-400 via-amber-200 to-yellow-50",
    icon: AudioLines,
    href: "/workspace/studio",
  },
  {
    slug: "aura",
    index: "02",
    title: "AURA Visualizer",
    eyebrow: "Motion / signal",
    summary: "Reactive canvas scenes for sound, light and captured performance.",
    accent: "from-fuchsia-500 via-violet-500 to-cyan-200",
    icon: Orbit,
    href: "/workspace/aura",
  },
  {
    slug: "command",
    index: "03",
    title: "Command Center",
    eyebrow: "Systems / coordination",
    summary: "A focused operational layer for the 3XTRINITY network.",
    accent: "from-sky-400 via-cyan-300 to-emerald-100",
    icon: Network,
    href: "/workspace/command",
  },
  {
    slug: "kernel",
    index: "04",
    title: "Kernel",
    eyebrow: "Core / protocol",
    summary: "Inspect the STEEL runtime, hosts and the active system channel.",
    accent: "from-slate-200 via-zinc-400 to-emerald-200",
    icon: Cpu,
    href: "/workspace/kernel",
  },
  {
    slug: "audit",
    index: "05",
    title: "Audit Lab",
    eyebrow: "Trust / review",
    summary: "Review permissions, signals and evidence across the working surface.",
    accent: "from-rose-400 via-orange-300 to-stone-100",
    icon: ShieldCheck,
    href: "/workspace/audit",
  },
  {
    slug: "artwork",
    index: "06",
    title: "Artwork Lab",
    eyebrow: "AI direction / identity",
    summary: "A prompt-led art direction space for campaign worlds and visual systems.",
    accent: "from-lime-300 via-teal-300 to-blue-200",
    icon: Sparkles,
    href: "/workspace/desk",
  },
  {
    slug: "pipeline",
    index: "07",
    title: "Signal Pipeline",
    eyebrow: "Audio / routing",
    summary: "Shape a live audio chain with controllable inserts and a web output tap.",
    accent: "from-emerald-300 via-cyan-300 to-sky-100",
    icon: GitFork,
    href: "/workspace/pipeline",
  },
  {
    slug: "hosts",
    index: "08",
    title: "Host Matrix",
    eyebrow: "MIDI / systems",
    summary: "Map host profiles, operating systems and control surfaces for live work.",
    accent: "from-slate-300 via-blue-300 to-violet-200",
    icon: Server,
    href: "/workspace/hosts",
  },
  {
    slug: "fleet",
    index: "09",
    title: "Delivery Fleet",
    eyebrow: "AI / delivery",
    summary: "Assemble a 15-role delivery sequence with visible approval gates.",
    accent: "from-cyan-300 via-teal-300 to-emerald-100",
    icon: Workflow,
    href: "/client/fleet",
  },
  {
    slug: "orchestrator",
    index: "10",
    title: "Project Orchestrator",
    eyebrow: "Client / workflow",
    summary: "Prepare transparent, human-controlled handoffs across creative disciplines.",
    accent: "from-indigo-300 via-violet-300 to-fuchsia-200",
    icon: Network,
    href: "/client/orchestrator",
  },
  {
    slug: "modulation",
    index: "11",
    title: "Modulation Lab",
    eyebrow: "AURA / control",
    summary: "Design reactive visual scenes and move directly into the live visualizer.",
    accent: "from-rose-300 via-fuchsia-300 to-cyan-200",
    icon: SlidersHorizontal,
    href: "/client/modulation",
  },
] as const;

type Module = (typeof modules)[number];

function SignalCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let frame = 0;
    const paint = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(devicePixelRatio || 1, 2);
      if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const { width, height } = rect;
      ctx.fillStyle = "#07090e";
      ctx.fillRect(0, 0, width, height);
      const t = frame / 130;
      for (let ring = 0; ring < 10; ring++) {
        ctx.beginPath();
        const radius = 44 + ring * 28;
        for (let i = 0; i <= 160; i++) {
          const a = (i / 160) * Math.PI * 2;
          const noise = Math.sin(a * 5 + t * 1.7 + ring) * 8 + Math.cos(a * 9 - t + ring * 0.4) * 4;
          const r = radius + noise;
          const x = width * 0.5 + Math.cos(a + t * (ring % 2 ? -0.07 : 0.07)) * r * 1.4;
          const y = height * 0.5 + Math.sin(a + t * (ring % 2 ? -0.07 : 0.07)) * r;
          if (i) ctx.lineTo(x, y);
          else ctx.moveTo(x, y);
        }
        ctx.strokeStyle = `hsla(${190 + ring * 17}, 88%, ${63 - ring * 2}%, ${0.54 - ring * 0.035})`;
        ctx.lineWidth = 1.1;
        ctx.stroke();
      }
      frame++;
      requestAnimationFrame(paint);
    };
    const id = requestAnimationFrame(paint);
    return () => cancelAnimationFrame(id);
  }, []);
  return <canvas ref={ref} className="absolute inset-0 size-full" aria-hidden="true" />;
}

function ModuleCard({ module }: { module: Module }) {
  const Icon = module.icon;
  return (
    <a
      href={module.href}
      className="group relative min-h-72 overflow-hidden rounded-3xl border border-white/10 bg-white/[0.045] p-6 transition duration-500 hover:-translate-y-1 hover:border-white/30 hover:bg-white/[0.08]"
    >
      <div
        className={`absolute -right-16 -top-20 size-52 rounded-full bg-gradient-to-br ${module.accent} opacity-20 blur-2xl transition duration-500 group-hover:scale-125 group-hover:opacity-35`}
      />
      <div className="relative flex h-full flex-col justify-between">
        <div className="flex items-start justify-between">
          <span className="font-mono text-xs tracking-[0.18em] text-white/45">{module.index}</span>
          <Icon className="size-5 text-white/70" />
        </div>
        <div>
          <p className="mb-3 font-mono text-xs tracking-[0.16em] text-cyan-200/80 uppercase">
            {module.eyebrow}
          </p>
          <h3 className="text-3xl text-white">{module.title}</h3>
          <p className="mt-3 max-w-sm text-sm leading-6 text-white/60">{module.summary}</p>
        </div>
        <div className="mt-7 flex items-center gap-2 text-sm text-white">
          Explore module{" "}
          <ArrowUpRight className="size-4 transition group-hover:translate-x-1 group-hover:-translate-y-1" />
        </div>
      </div>
    </a>
  );
}

export function TrinityPortal() {
  return (
    <div className="min-h-dvh overflow-hidden bg-[#07090e] text-white selection:bg-cyan-300 selection:text-black">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-display text-lg tracking-[0.24em]">
          3XTRINITY
        </Link>
        <div className="hidden items-center gap-6 font-mono text-xs tracking-widest text-white/55 md:flex">
          <a href="#modules">MODULES</a>
          <a href="#manifesto">MANIFESTO</a>
        </div>
        <Link
          to="/client/workbench"
          className="rounded-full border border-white/25 px-4 py-2 font-mono text-xs tracking-wider transition hover:bg-white hover:text-black"
        >
          START A PROJECT
        </Link>
      </header>
      <main>
        <section className="relative mx-auto grid min-h-[78vh] max-w-7xl items-end gap-10 px-6 pb-16 pt-16 lg:grid-cols-[1.05fr_.95fr] lg:px-10">
          <div className="absolute inset-0 -z-0 opacity-70">
            <SignalCanvas />
          </div>
          <div className="relative z-10">
            <p className="mb-5 flex items-center gap-2 font-mono text-xs tracking-[0.2em] text-cyan-200">
              <span className="size-2 animate-pulse rounded-full bg-cyan-300" /> DIGITAL ARTS /
              SYSTEMS / CULTURE
            </p>
            <h1 className="max-w-3xl text-6xl leading-[0.88] sm:text-8xl">
              A living network for <span className="text-cyan-200">new worlds.</span>
            </h1>
            <p className="mt-8 max-w-xl text-lg leading-8 text-white/65">
              3XTRINITY CORPORATION connects sound, intelligent tools and immersive visuals through
              independent, interoperable modules.
            </p>
            <div className="mt-10 flex flex-wrap gap-3">
              <Link
                to="/client/workbench"
                className="rounded-full bg-white px-6 py-3 text-sm font-medium text-black transition hover:bg-cyan-200"
              >
                Start a project
              </Link>
              <Link
                to="/modules/$module"
                params={{ module: "aura" }}
                className="rounded-full border border-white/30 px-6 py-3 text-sm transition hover:border-cyan-200 hover:text-cyan-200"
              >
                Open visualizer
              </Link>
            </div>
          </div>
          <div className="relative z-10 grid gap-3 self-center lg:justify-self-end">
            <div className="rounded-2xl border border-white/15 bg-black/30 p-5 backdrop-blur">
              <p className="font-mono text-xs tracking-widest text-white/40">NETWORK MAP</p>
              <p className="mt-2 text-2xl">11 modular gateways</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <Eye className="size-5 text-fuchsia-300" />
                <p className="mt-7 text-sm text-white/50">Visual systems</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <Bot className="size-5 text-cyan-200" />
                <p className="mt-7 text-sm text-white/50">AI-directed craft</p>
              </div>
            </div>
          </div>
        </section>
        <section id="modules" className="mx-auto max-w-7xl px-6 py-20 lg:px-10">
          <div className="mb-10 flex flex-wrap items-end justify-between gap-5">
            <div>
              <p className="font-mono text-xs tracking-[0.2em] text-cyan-200">MODULAR ECOSYSTEM</p>
              <h2 className="mt-3 text-4xl sm:text-5xl">One identity. Many entry points.</h2>
            </div>
            <p className="max-w-sm text-sm leading-6 text-white/55">
              Start with a client-ready project direction, then move into the exact workspace that
              makes it real.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {modules.map((module) => (
              <ModuleCard key={module.slug} module={module} />
            ))}
          </div>
        </section>
        <section id="manifesto" className="border-y border-white/10 bg-white/[0.03]">
          <div className="mx-auto grid max-w-7xl gap-10 px-6 py-20 lg:grid-cols-[.7fr_1.3fr] lg:px-10">
            <Blocks className="size-12 text-cyan-200" />
            <p className="text-3xl leading-tight text-white/85 sm:text-5xl">
              We build environments where every tool can stand alone, then become more powerful
              together.
            </p>
          </div>
        </section>
      </main>
      <footer className="mx-auto flex max-w-7xl flex-wrap justify-between gap-4 px-6 py-8 font-mono text-xs tracking-wider text-white/40 lg:px-10">
        <span>© 3XTRINITY CORPORATION</span>
        <span>ESTONIA / GLOBAL</span>
      </footer>
    </div>
  );
}

export function ModuleLanding({ module }: { module: Module }) {
  const Icon = module.icon;
  return (
    <div className="min-h-dvh bg-[#07090e] text-white">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-mono text-xs tracking-[0.2em] text-white/60">
          ← 3XTRINITY HOME
        </Link>
        <span className="font-mono text-xs tracking-widest text-cyan-200">
          MODULE {module.index}
        </span>
      </header>
      <main className="mx-auto grid max-w-7xl gap-12 px-6 py-16 lg:grid-cols-[1fr_.8fr] lg:px-10 lg:py-24">
        <div>
          <p className="font-mono text-xs tracking-[0.2em] text-cyan-200">{module.eyebrow}</p>
          <h1 className="mt-5 text-6xl leading-none sm:text-8xl">{module.title}</h1>
          <p className="mt-8 max-w-xl text-xl leading-8 text-white/65">{module.summary}</p>
          <p className="mt-5 max-w-xl leading-7 text-white/45">
            This is the module’s entry layer: orientation, intent and a direct gateway into the live
            workspace.
          </p>
          <a
            href={module.href}
            className="mt-10 inline-flex items-center gap-2 rounded-full bg-white px-6 py-3 text-sm font-medium text-black transition hover:bg-cyan-200"
          >
            Open {module.title} <ArrowUpRight className="size-4" />
          </a>
        </div>
        <div className="relative min-h-80 overflow-hidden rounded-3xl border border-white/15 bg-white/[0.04] p-8">
          <div className={`absolute inset-0 bg-gradient-to-br ${module.accent} opacity-20`} />
          <div className="relative flex h-full flex-col justify-between">
            <Icon className="size-12" />
            <div>
              <p className="font-mono text-xs tracking-[0.2em] text-white/60">
                3XTRINITY / {module.slug.toUpperCase()}
              </p>
              <p className="mt-3 text-2xl">
                Independent module.
                <br />
                Shared system.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export function findModule(slug: string) {
  return modules.find((module) => module.slug === slug);
}
