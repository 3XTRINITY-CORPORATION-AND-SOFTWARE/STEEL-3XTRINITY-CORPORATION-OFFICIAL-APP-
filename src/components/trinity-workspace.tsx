import { useEffect } from "react";
import { AppShell } from "@/components/app-shell";
import { AuraStage } from "@/components/aura-stage";
import { SteelAudit } from "@/components/steel-audit";
import { SteelConsole } from "@/components/steel-console";
import { SteelDesk } from "@/components/steel-desk";
import { SteelKernel } from "@/components/steel-kernel";
import { SteelPipeline } from "@/components/steel-pipeline";
import { SteelHosts } from "@/components/steel-hosts";
import { SteelStudio } from "@/components/steel-studio";
import { useSteel } from "@/lib/steel/store";
import type { SteelTab } from "@/lib/steel/types";

const tabs: Record<string, SteelTab> = {
  studio: "studio",
  aura: "aura",
  command: "console",
  kernel: "kernel",
  audit: "audit",
  desk: "desk",
  pipeline: "pipeline",
  hosts: "hosts",
};

export function isWorkspaceModule(slug: string) {
  return slug in tabs;
}

export function TrinityWorkspace({ slug }: { slug: string }) {
  const requested = tabs[slug];
  const tab = useSteel((state) => state.tab);
  const setTab = useSteel((state) => state.setTab);
  useEffect(() => {
    if (requested) setTab(requested);
  }, [requested, setTab]);
  if (!requested) return null;
  return (
    <AppShell>
      {tab === "desk" ? <SteelDesk /> : null}
      {tab === "studio" ? <SteelStudio /> : null}
      {tab === "console" ? <SteelConsole /> : null}
      {tab === "aura" ? <AuraStage /> : null}
      {tab === "kernel" ? <SteelKernel /> : null}
      {tab === "audit" ? <SteelAudit /> : null}
      {tab === "pipeline" ? <SteelPipeline /> : null}
      {tab === "hosts" ? <SteelHosts /> : null}
    </AppShell>
  );
}
