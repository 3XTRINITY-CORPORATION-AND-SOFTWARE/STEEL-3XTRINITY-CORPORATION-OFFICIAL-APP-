import { Link } from "@tanstack/react-router";
import { Check, Clipboard, Compass, Eye, Headphones, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";

const outcomes = [
  {
    icon: Sparkles,
    title: "Visual concept",
    detail: "Turn a launch idea into a focused visual direction and artwork prompt.",
    workspace: "desk",
  },
  {
    icon: Headphones,
    title: "Sound direction",
    detail: "Open STEEL Studio for composition, voice, patterns and campaign sound.",
    workspace: "studio",
  },
  {
    icon: Eye,
    title: "Live visual",
    detail: "Open AURA for reactive visual scenes from a file, microphone or demo signal.",
    workspace: "aura",
  },
] as const;

const audiences = ["New audience", "Existing clients", "Creative community", "Internal team"];
const moods = ["Futurist clarity", "Cinematic energy", "Premium restraint", "Digital ritual"];

export function ClientWorkbench() {
  const [name, setName] = useState("");
  const [audience, setAudience] = useState(audiences[0]);
  const [mood, setMood] = useState(moods[0]);
  const [copied, setCopied] = useState(false);
  const brief = useMemo(() => {
    const subject = name.trim() || "your next project";
    return `Create a ${mood.toLowerCase()} campaign direction for ${subject}. Design it for ${audience.toLowerCase()}. Combine a distinctive visual world, concise message hierarchy, tactile motion language and a sound identity that can expand into a live visual experience.`;
  }, [audience, mood, name]);

  async function copyBrief() {
    try {
      await navigator.clipboard.writeText(brief);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="min-h-dvh bg-[#07090e] text-white">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-mono text-xs tracking-[0.2em] text-white/60">
          ← 3XTRINITY HOME
        </Link>
        <span className="font-mono text-xs tracking-widest text-cyan-200">CLIENT WORKBENCH</span>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-12 lg:px-10 lg:py-20">
        <section className="grid gap-12 lg:grid-cols-[.85fr_1.15fr]">
          <div>
            <p className="font-mono text-xs tracking-[0.2em] text-cyan-200">
              FROM IDEA TO WORKING DIRECTION
            </p>
            <h1 className="mt-5 max-w-xl text-5xl leading-[.92] sm:text-7xl">
              Show clients what happens next.
            </h1>
            <p className="mt-7 max-w-xl text-lg leading-8 text-white/60">
              Start with a short project direction, then move directly into the tools that create
              the visual, sound and live experience.
            </p>
            <div className="mt-10 space-y-4">
              {outcomes.map(({ icon: Icon, title, detail, workspace }, index) => (
                <Link
                  key={title}
                  to="/workspace/$module"
                  params={{ module: workspace }}
                  className="group flex gap-4 rounded-2xl border border-white/10 bg-white/[.035] p-5 transition hover:border-cyan-200/60 hover:bg-white/[.07]"
                >
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-full bg-cyan-200/10 text-cyan-200">
                    <Icon className="size-5" />
                  </span>
                  <span>
                    <span className="mb-1 block font-mono text-xs tracking-widest text-white/40">
                      0{index + 1}
                    </span>
                    <span className="block text-lg">{title}</span>
                    <span className="mt-1 block text-sm leading-6 text-white/55">{detail}</span>
                  </span>
                </Link>
              ))}
            </div>
          </div>
          <section className="rounded-3xl border border-white/15 bg-white/[.04] p-6 sm:p-9">
            <div className="flex items-center gap-3">
              <Compass className="size-5 text-cyan-200" />
              <p className="font-mono text-xs tracking-[0.18em] text-white/50">PROJECT DIRECTION</p>
            </div>
            <div className="mt-8 grid gap-5">
              <label className="grid gap-2 text-sm text-white/70">
                Project or campaign name
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="e.g. NIGHT WAVE 2026"
                  className="rounded-xl border border-white/15 bg-black/30 px-4 py-3 text-white outline-none transition placeholder:text-white/25 focus:border-cyan-200"
                />
              </label>
              <label className="grid gap-2 text-sm text-white/70">
                Audience
                <select
                  value={audience}
                  onChange={(event) => setAudience(event.target.value)}
                  className="rounded-xl border border-white/15 bg-black/30 px-4 py-3 text-white outline-none focus:border-cyan-200"
                >
                  {audiences.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className="grid gap-2 text-sm text-white/70">
                Creative tone
                <select
                  value={mood}
                  onChange={(event) => setMood(event.target.value)}
                  className="rounded-xl border border-white/15 bg-black/30 px-4 py-3 text-white outline-none focus:border-cyan-200"
                >
                  {moods.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="mt-8 rounded-2xl border border-cyan-200/20 bg-cyan-200/[.06] p-5">
              <p className="font-mono text-xs tracking-[.16em] text-cyan-200">
                ARTWORK / CREATIVE PROMPT
              </p>
              <p className="mt-4 leading-7 text-white/75">{brief}</p>
              <button
                type="button"
                onClick={() => void copyBrief()}
                className="mt-5 inline-flex items-center gap-2 rounded-full border border-white/20 px-4 py-2 text-sm transition hover:border-cyan-200 hover:text-cyan-200"
              >
                {copied ? <Check className="size-4" /> : <Clipboard className="size-4" />}
                {copied ? "Copied" : "Copy direction"}
              </button>
            </div>
            <p className="mt-5 text-sm leading-6 text-white/40">
              Use this direction with your preferred artwork model or hand it to the 3XTRINITY
              creative team. No external AI account is required for this planner.
            </p>
          </section>
        </section>
      </main>
    </div>
  );
}
