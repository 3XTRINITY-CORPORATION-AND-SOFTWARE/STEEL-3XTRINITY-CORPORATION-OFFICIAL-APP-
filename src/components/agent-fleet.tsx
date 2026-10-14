import { Link } from "@tanstack/react-router";
import {
  Check,
  Circle,
  Code2,
  Eye,
  FileSearch,
  Gauge,
  GitPullRequest,
  Layers3,
  Megaphone,
  Palette,
  ShieldCheck,
  Sparkles,
  TestTube2,
  Users,
  WandSparkles,
} from "lucide-react";
import { useMemo, useState } from "react";

const fleet = [
  ["Brief", "Turns an idea into a scoped brief", FileSearch],
  ["Research", "Finds approved source context", Eye],
  ["Strategy", "Maps outcome and audience", Layers3],
  ["UX", "Plans client journeys", Users],
  ["Visual", "Builds art direction prompts", Palette],
  ["Copy", "Drafts launch messaging", Megaphone],
  ["Sound", "Prepares sonic direction", WandSparkles],
  ["Motion", "Prepares AURA treatments", Sparkles],
  ["Builder", "Implements focused changes", Code2],
  ["Reviewer", "Checks for defects and risks", ShieldCheck],
  ["Test", "Runs type, lint and build gates", TestTube2],
  ["Performance", "Finds delivery bottlenecks", Gauge],
  ["Release", "Prepares preview deployment", GitPullRequest],
  ["Sales", "Packages client-facing outputs", Megaphone],
  ["Operator", "Coordinates approvals and audit", Check],
] as const;

type FleetId = (typeof fleet)[number][0];

export function AgentFleet() {
  const [selected, setSelected] = useState<FleetId[]>([
    "Brief",
    "Strategy",
    "Builder",
    "Reviewer",
    "Test",
  ]);
  const [armed, setArmed] = useState(false);
  const [project, setProject] = useState("");
  const queue = useMemo(() => fleet.filter(([name]) => selected.includes(name)), [selected]);
  const toggle = (name: FleetId) => {
    setArmed(false);
    setSelected((items) =>
      items.includes(name) ? items.filter((item) => item !== name) : [...items, name],
    );
  };
  return (
    <div className="min-h-dvh bg-[#07090e] text-white">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-mono text-xs tracking-[.2em] text-white/60">
          ← 3XTRINITY HOME
        </Link>
        <span className="font-mono text-xs tracking-widest text-cyan-200">
          AI GATEWAY / $0 GUARD
        </span>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-12 lg:px-10 lg:py-20">
        <div className="max-w-3xl">
          <p className="font-mono text-xs tracking-[.2em] text-cyan-200">15-ROLE DELIVERY FLEET</p>
          <h1 className="mt-5 text-5xl leading-[.92] sm:text-7xl">
            Build quickly.
            <br />
            <span className="text-cyan-200">Ship deliberately.</span>
          </h1>
          <p className="mt-7 text-lg leading-8 text-white/60">
            Choose specialist roles for a client job. In $0 mode this builds a visible, local
            execution plan. AI calls, PR publication and deploys remain explicit actions when an API
            key and free-tier model access are configured.
          </p>
        </div>
        <section className="mt-14 grid gap-7 lg:grid-cols-[1.1fr_.9fr]">
          <div>
            <label className="grid gap-2 text-sm text-white/70">
              Project name
              <input
                value={project}
                onChange={(e) => {
                  setProject(e.target.value);
                  setArmed(false);
                }}
                placeholder="CLIENT WEBSITE / PRODUCT / CAMPAIGN"
                className="rounded-xl border border-white/15 bg-black/30 px-4 py-3 text-white outline-none placeholder:text-white/25 focus:border-cyan-200"
              />
            </label>
            <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {fleet.map(([name, detail, Icon]) => {
                const on = selected.includes(name);
                return (
                  <button
                    key={name}
                    type="button"
                    onClick={() => toggle(name)}
                    className={`rounded-2xl border p-4 text-left transition ${on ? "border-cyan-200 bg-cyan-200/[.08]" : "border-white/10 bg-white/[.03] hover:border-white/30"}`}
                  >
                    <div className="flex justify-between">
                      <Icon className="size-4 text-cyan-200" />
                      {on ? (
                        <Check className="size-4 text-cyan-200" />
                      ) : (
                        <Circle className="size-4 text-white/20" />
                      )}
                    </div>
                    <strong className="mt-6 block text-sm">{name}</strong>
                    <span className="mt-1 block text-xs leading-5 text-white/45">{detail}</span>
                  </button>
                );
              })}
            </div>
          </div>
          <aside className="rounded-3xl border border-white/15 bg-white/[.04] p-6">
            <p className="font-mono text-xs tracking-[.16em] text-white/45">EXECUTION PLAN</p>
            <h2 className="mt-2 text-2xl">{project.trim() || "New client job"}</h2>
            <div className="mt-6 space-y-2">
              {queue.map(([name, detail], index) => (
                <div
                  key={name}
                  className="flex gap-3 rounded-xl border border-white/10 bg-black/20 p-3"
                >
                  <span className="font-mono text-xs text-cyan-200">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span>
                    <strong className="block text-sm">{name}</strong>
                    <small className="text-white/45">{detail}</small>
                  </span>
                </div>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setArmed(Boolean(selected.length))}
              disabled={!selected.length}
              className="mt-6 w-full rounded-full bg-white px-5 py-3 text-sm font-medium text-black disabled:opacity-30"
            >
              Prepare approved handoffs
            </button>
            {armed ? (
              <div className="mt-4 rounded-xl border border-cyan-200/20 bg-cyan-200/[.06] p-4 text-sm leading-6 text-cyan-50">
                Plan ready. Connect an AI Gateway key only when you want model generation. For code
                changes, the Builder → Reviewer → Test → Release chain produces a PR and preview;
                production stays an approval step.
              </div>
            ) : null}
            <p className="mt-5 text-xs leading-5 text-white/40">
              $0 guard: no model call is attempted without an explicit, configured Gateway
              credential. Free-tier limits may return 429 and should be retried later, not bypassed.
            </p>
          </aside>
        </section>
      </main>
    </div>
  );
}
