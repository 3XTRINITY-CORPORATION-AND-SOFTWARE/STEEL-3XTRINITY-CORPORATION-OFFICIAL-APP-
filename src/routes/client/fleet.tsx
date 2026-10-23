import { createFileRoute } from "@tanstack/react-router";
import { AgentFleet } from "@/components/agent-fleet";
export const Route = createFileRoute("/client/fleet")({ component: AgentFleet });
