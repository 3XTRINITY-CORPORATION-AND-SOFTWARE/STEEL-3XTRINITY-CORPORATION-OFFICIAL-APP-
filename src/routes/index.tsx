import { createFileRoute } from "@tanstack/react-router";
import { TrinityPortal } from "@/components/trinity-portal";

export const Route = createFileRoute("/")({ component: TrinityPortal });
