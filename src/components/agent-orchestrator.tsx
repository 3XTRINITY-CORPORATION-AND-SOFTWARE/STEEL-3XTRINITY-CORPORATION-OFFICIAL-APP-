import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  Bot,
  Check,
  Circle,
  Clock3,
  Eye,
  Layers3,
  Music2,
  Send,
  Sparkles,
} from "lucide-react";
import { useMemo, useState } from "react";

const agents = [
  {
    id: "strategy",
    title: "Strategy Agent",
    role: "Turns a client brief into an outcome map.",
    icon: Layers3,
    output: "Positioning, audience and delivery sequence",
    workspace: "desk",
  },
  {
    id: "art",
    title: "Artwork Agent",
    role: "Prepares an art direction prompt and visual language.",
    icon: Sparkles,
    output: "Creative prompt, palette and motion cues",
    workspace: "desk",
  },
  {
    id: "sound",
    title: "Sound Agent",
    role: "Routes the campaign through composition and voice tools.",
    icon: Music2,
    output: "Sound concept and STEEL Studio handoff",
    workspace: "studio",
  },
  {
    id: "motion",
    title: "Motion Agent",
    role: "Prepares a live visual treatment for AURA.",
    icon: Eye,
    output: "Scene language and visualizer handoff",
    workspace: "aura",
  },
] as const;

type AgentId = (typeof agents)[number]["id"];

export function AgentOrchestrator() {
  const [project, setProject] = useState("");
  const [active, setActive] = useState<AgentId[]>([]);
  const [sent, setSent] = useState(false);
  const selected = agents.filter((agent) => active.includes(agent.id));
  const projectName = project.trim() || "Untitled client project";
  const taskList = useMemo(
    () =>
      selected.map((agent, index) => ({ ...agent, stage: index === 0 ? "Ready now" : "Queued" })),
    [selected],
  );

  function toggle(id: AgentId) {
    setSent(false);
    setActive((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  }

  function prepare() {
    if (active.length) setSent(true);
  }

  return (
    <div className="min-h-dvh bg-[#07090e] text-white">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        <Link to="/" className="font-mono text-xs tracking-[.2em] text-white/60">
          ← 3XTRINITY HOME
        </Link>
        <span className="font-mono text-xs tracking-widest text-cyan-200">AGENT ORCHESTRATOR</span>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-12 lg:px-10 lg:py-20">
        <div className="max-w-3xl">
          <p className="font-mono text-xs tracking-[.2em] text-cyan-200">CLIENT-SAFE AI WORKFLOW</p>
          <h1 className="mt-5 text-5xl leading-[.92] sm:text-7xl">
            Assemble the work.
            <br />
            <span className="text-cyan-200">Keep humans in control.</span>
          </h1>
          <p className="mt-7 max-w-2xl text-lg leading-8 text-white/60">
            Choose the specialist roles needed for a project. This workspace prepares transparent
            handoffs to the real 3XTRINITY tools; it does not start background agents or call
            external AI services without an explicit integration.
          </p>
        </div>
        <section className="mt-14 grid gap-8 lg:grid-cols-[1.1fr_.9fr]">
          <div>
            <label className="grid gap-2 text-sm text-white/70">
              Client project
              <input
                value={project}
                onChange={(event) => setProject(event.target.value)}
                placeholder="e.g. AURORA PRODUCT LAUNCH"
                className="rounded-xl border border-white/15 bg-black/30 px-4 py-3 text-white outline-none placeholder:text-white/25 focus:border-cyan-200"
              />
            </label>
            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {agents.map((agent) => {
                const Icon = agent.icon;
                const isActive = active.includes(agent.id);
                return (
                  <button
                    key={agent.id}
                    type="button"
                    onClick={() => toggle(agent.id)}
                    className={`rounded-2xl border p-5 text-left transition ${isActive ? "border-cyan-200 bg-cyan-200/[.08]" : "border-white/10 bg-white/[.035] hover:border-white/30"}`}
                  >
                    <div className="flex items-start justify-between">
                      <Icon className="size-5 text-cyan-200" />
                      {isActive ? (
                        <Check className="size-5 text-cyan-200" />
                      ) : (
                        <Circle className="size-5 text-white/20" />
                      )}
                    </div>
                    <h2 className="mt-8 text-xl">{agent.title}</h2>
                    <p className="mt-2 text-sm leading-6 text-white/55">{agent.role}</p>
                  </button>
                );
              })}
            </div>
          </div>
          <aside className="rounded-3xl border border-white/15 bg-white/[.04] p-6 sm:p-8">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-mono text-xs tracking-[.16em] text-white/45">PROJECT QUEUE</p>
                <h2 className="mt-2 text-2xl">{projectName}</h2>
              </div>
              <Bot className="size-7 text-cyan-200" />
            </div>
            <div className="mt-8 space-y-3">
              {taskList.length ? (
                taskList.map((task, index) => (
                  <div key={task.id} className="rounded-xl border border-white/10 bg-black/20 p-4">
                    <div className="flex items-center justify-between gap-4">
                      <span className="text-sm">
                        {index + 1}. {task.title}
                      </span>
                      <span
                        className={`font-mono text-2xs tracking-wider ${index === 0 ? "text-cyan-200" : "text-white/40"}`}
                      >
                        {task.stage.toUpperCase()}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-white/50">{task.output}</p>
                    {sent && index === 0 ? (
                      <Link
                        to="/workspace/$module"
                        params={{ module: task.workspace }}
                        className="mt-3 inline-flex items-center gap-2 text-sm text-cyan-200"
                      >
                        Open working tool <ArrowRight className="size-4" />
                      </Link>
                    ) : null}
                  </div>
                ))
              ) : (
                <div className="rounded-xl border border-dashed border-white/15 p-5 text-sm leading-6 text-white/45">
                  <Clock3 className="mb-3 size-5" />
                  Select one or more roles to build a project queue.
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={prepare}
              disabled={!active.length}
              className="mt-7 inline-flex w-full items-center justify-center gap-2 rounded-full bg-white px-5 py-3 text-sm font-medium text-black transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-30"
            >
              <Send className="size-4" />
              Prepare handoffs
            </button>
            {sent ? (
              <p className="mt-4 text-sm leading-6 text-cyan-100/75">
                Handoffs are ready. Open the first workspace to start the work; other roles stay
                queued until you choose to continue.
              </p>
            ) : null}
          </aside>
        </section>
      </main>
    </div>
  );
}
