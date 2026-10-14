import { createFileRoute, notFound } from "@tanstack/react-router";
import { isWorkspaceModule, TrinityWorkspace } from "@/components/trinity-workspace";

export const Route = createFileRoute("/workspace/$module")({ component: WorkspacePage });
function WorkspacePage() {
  const { module } = Route.useParams();
  if (!isWorkspaceModule(module)) throw notFound();
  return <TrinityWorkspace slug={module} />;
}
