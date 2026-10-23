import { createFileRoute } from "@tanstack/react-router";
import { AgentOrchestrator } from "@/components/agent-orchestrator";
export const Route = createFileRoute("/client/orchestrator")({ component: AgentOrchestrator });
