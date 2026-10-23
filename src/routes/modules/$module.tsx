import { createFileRoute, notFound } from "@tanstack/react-router";
import { findModule, ModuleLanding } from "@/components/trinity-portal";

export const Route = createFileRoute("/modules/$module")({
  component: ModulePage,
});

function ModulePage() {
  const { module: slug } = Route.useParams();
  const module = findModule(slug);
  if (!module) throw notFound();
  return <ModuleLanding module={module} />;
}
