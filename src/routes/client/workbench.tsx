import { createFileRoute } from "@tanstack/react-router";
import { ClientWorkbench } from "@/components/client-workbench";

export const Route = createFileRoute("/client/workbench")({ component: ClientWorkbench });
