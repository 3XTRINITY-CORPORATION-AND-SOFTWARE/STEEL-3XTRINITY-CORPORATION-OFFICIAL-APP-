import { Link } from "@tanstack/react-router";
import { Eye, RotateCcw, SlidersHorizontal, Sparkles, Waves } from "lucide-react";
import { useAura } from "@/lib/aura/store";
import type { AuraMode, AuraPalette } from "@/lib/aura/types";

const scenes: {
  name: string;
  mode: AuraMode;
  palette: AuraPalette;
  sensitivity: number;
  eq: number[];
  note: string;
}[] = [
  {
    name: "Northern signal",
    mode: "ring",
    palette: "ice",
    sensitivity: 1.15,
    eq: [0, 1, 2, 1, 0, 2, 3, 2],
    note: "Clean, responsive product reveal.",
  },
  {
    name: "Ember pulse",
    mode: "bloom",
    palette: "ember",
    sensitivity: 1.7,
    eq: [3, 2, 1, 0, 2, 3, 1, 0],
    note: "High-energy launch atmosphere.",
  },
  {
    name: "Tidal field",
    mode: "wave",
    palette: "tide",
    sensitivity: 0.85,
    eq: [-1, 0, 1, 2, 1, 0, 2, 3],
    note: "Slow, immersive motion system.",
  },
];

export function ModulationLab() {
  const aura = useAura();
  const apply = (scene: (typeof scenes)[number]) =>
    aura.set({
      mode: scene.mode,
      palette: scene.palette,
      sensitivity: scene.sensitivity,
      eq: scene.eq,
    });
  return (
    <div className="min-h-dvh bg-[#07090e] text-white">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-mono text-xs tracking-[.2em] text-white/60">
          ← 3XTRINITY HOME
        </Link>
        <span className="font-mono text-xs tracking-widest text-cyan-200">MODULATION LAB</span>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-12 lg:px-10 lg:py-20">
        <div className="max-w-3xl">
          <p className="font-mono text-xs tracking-[.2em] text-cyan-200">AURA CONTROL SURFACE</p>
          <h1 className="mt-5 text-5xl leading-[.92] sm:text-7xl">
            Shape the curve.
            <br />
            <span className="text-cyan-200">Direct the feeling.</span>
          </h1>
          <p className="mt-7 text-lg leading-8 text-white/60">
            Build a visual response before opening the live AURA workspace. Every control below
            writes directly into the visualizer state.
          </p>
        </div>
        <section className="mt-14 grid gap-5 lg:grid-cols-[.9fr_1.1fr]">
          <aside className="rounded-3xl border border-white/15 bg-white/[.04] p-6">
            <div className="flex items-center gap-3">
              <SlidersHorizontal className="size-5 text-cyan-200" />
              <h2 className="text-xl">Live parameters</h2>
            </div>
            <label className="mt-7 grid gap-3 text-sm text-white/65">
              Sensitivity{" "}
              <span className="font-mono text-cyan-200">{aura.sensitivity.toFixed(2)}×</span>
              <input
                aria-label="Sensitivity"
                type="range"
                min="0.5"
                max="2.5"
                step="0.05"
                value={aura.sensitivity}
                onChange={(event) => aura.set({ sensitivity: Number(event.target.value) })}
              />
            </label>
            <div className="mt-7">
              <p className="text-sm text-white/65">Visual mode</p>
              <div className="mt-3 grid grid-cols-2 gap-2">
                {(["bars", "ring", "wave", "bloom"] as AuraMode[]).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => aura.set({ mode })}
                    className={`rounded-lg border px-3 py-2 text-sm capitalize ${aura.mode === mode ? "border-cyan-200 bg-cyan-200/10 text-cyan-200" : "border-white/10 text-white/60"}`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-7">
              <p className="text-sm text-white/65">Frequency shaping</p>
              <div className="mt-3 grid grid-cols-4 gap-2">
                {aura.eq.map((gain, index) => (
                  <label
                    key={index}
                    className="rounded-lg border border-white/10 bg-black/20 p-2 text-center font-mono text-xs text-white/50"
                  >
                    {index + 1}
                    <input
                      aria-label={`Band ${index + 1}`}
                      className="mt-2 h-20 w-full accent-cyan-200"
                      type="range"
                      min="-6"
                      max="6"
                      step="1"
                      value={gain}
                      onChange={(event) => {
                        const eq = [...aura.eq];
                        eq[index] = Number(event.target.value);
                        aura.set({ eq });
                      }}
                    />
                  </label>
                ))}
              </div>
            </div>
            <button
              type="button"
              onClick={() =>
                aura.set({
                  sensitivity: 1.15,
                  mode: "ring",
                  palette: "ice",
                  eq: aura.eq.map(() => 0),
                })
              }
              className="mt-7 inline-flex items-center gap-2 text-sm text-white/55 hover:text-cyan-200"
            >
              <RotateCcw className="size-4" />
              Reset
            </button>
          </aside>
          <div className="space-y-4">
            <div className="rounded-3xl border border-cyan-200/20 bg-gradient-to-br from-cyan-200/[.11] to-violet-500/[.08] p-7">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-xs tracking-widest text-cyan-200">CURRENT OUTPUT</p>
                  <h2 className="mt-3 text-3xl capitalize">
                    {aura.mode} / {aura.palette}
                  </h2>
                </div>
                <Waves className="size-8 text-cyan-200" />
              </div>
              <p className="mt-6 max-w-lg text-white/60">
                The next AURA session opens with this modulation profile. Start the live signal only
                when you are ready.
              </p>
              <Link
                to="/workspace/$module"
                params={{ module: "aura" }}
                className="mt-7 inline-flex items-center gap-2 rounded-full bg-white px-5 py-3 text-sm font-medium text-black hover:bg-cyan-200"
              >
                Open AURA Visualizer <Eye className="size-4" />
              </Link>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {scenes.map((scene) => (
                <button
                  key={scene.name}
                  type="button"
                  onClick={() => apply(scene)}
                  className="rounded-2xl border border-white/10 bg-white/[.035] p-5 text-left transition hover:border-cyan-200 hover:bg-white/[.07]"
                >
                  <Sparkles className="size-5 text-cyan-200" />
                  <h3 className="mt-8 text-lg">{scene.name}</h3>
                  <p className="mt-2 text-sm leading-6 text-white/50">{scene.note}</p>
                </button>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
