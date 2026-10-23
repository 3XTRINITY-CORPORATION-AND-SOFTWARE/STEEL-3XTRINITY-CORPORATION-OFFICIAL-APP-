import { createFileRoute } from "@tanstack/react-router";
import { ModulationLab } from "@/components/modulation-lab";
export const Route = createFileRoute("/client/modulation")({ component: ModulationLab });
