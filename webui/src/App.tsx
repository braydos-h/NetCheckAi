// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { lazy, Suspense, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Layout } from "@/components/Layout";
import { OnboardingGate } from "@/components/OnboardingGate";
import { TokenGate } from "@/components/TokenGate";
import { WelcomeGate } from "@/components/WelcomeScreen";
import { HomePage } from "@/routes/HomePage";
import { Spinner } from "@/components/Loading";
import { Toaster } from "@/components/Toaster";
import { queryClient } from "@/api/queryClient";

const AttackGraphPage = lazy(() =>
  import("@/features/graph/AttackGraphPage").then((m) => ({ default: m.AttackGraphPage })),
);
const RunListPage = lazy(() => import("@/routes/RunListPage").then((m) => ({ default: m.RunListPage })));
const NewRunPage = lazy(() => import("@/routes/NewRunPage").then((m) => ({ default: m.NewRunPage })));
const RunPage = lazy(() => import("@/routes/RunPage").then((m) => ({ default: m.RunPage })));
const ArtifactsPage = lazy(() => import("@/routes/ArtifactsPage").then((m) => ({ default: m.ArtifactsPage })));
const LootPage = lazy(() => import("@/routes/LootPage").then((m) => ({ default: m.LootPage })));
const GraphPage = lazy(() => import("@/routes/GraphPage").then((m) => ({ default: m.GraphPage })));
const MemoryPage = lazy(() => import("@/routes/MemoryPage").then((m) => ({ default: m.MemoryPage })));
const SkillsPage = lazy(() => import("@/routes/SkillsPage").then((m) => ({ default: m.SkillsPage })));
const SystemPage = lazy(() => import("@/routes/SystemPage").then((m) => ({ default: m.SystemPage })));
const AttackModulesPage = lazy(() => import("@/routes/AttackModulesPage").then((m) => ({ default: m.AttackModulesPage })));
const GoalsPage = lazy(() => import("@/routes/GoalsPage").then((m) => ({ default: m.GoalsPage })));
const StatsPage = lazy(() => import("@/routes/StatsPage").then((m) => ({ default: m.StatsPage })));
const HelpPage = lazy(() => import("@/routes/HelpPage").then((m) => ({ default: m.HelpPage })));
const ConnectionsPage = lazy(() => import("@/routes/ConnectionsPage").then((m) => ({ default: m.ConnectionsPage })));
const BenchmarksPage = lazy(() => import("@/routes/BenchmarksPage").then((m) => ({ default: m.BenchmarksPage })));
const BenchmarksStartPage = lazy(() => import("@/routes/BenchmarksStartPage").then((m) => ({ default: m.BenchmarksStartPage })));
const BenchmarksHistoryPage = lazy(() => import("@/routes/BenchmarksHistoryPage").then((m) => ({ default: m.BenchmarksHistoryPage })));
const BenchmarkRunPage = lazy(() => import("@/routes/BenchmarkRunPage").then((m) => ({ default: m.BenchmarkRunPage })));
const OpsPage = lazy(() => import("@/routes/OpsPage").then((m) => ({ default: m.OpsPage })));

/** Route-scoped error boundary: a render crash in one route shows a fallback
 *  with a retry, and navigating away auto-resets it via the pathname key.
 *  (The main.tsx boundary has no reset key and never resets.) */
function RouteErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <ErrorBoundary resetKey={pathname}>{children}</ErrorBoundary>;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <TokenGate>
          <OnboardingGate>
            <WelcomeGate>
              <Suspense
                fallback={
                  <div className="flex min-h-[50vh] items-center justify-center">
                    <Spinner label="Loading..." />
                  </div>
                }
              >
                <Routes>
                  <Route element={<RouteErrorBoundary><Layout /></RouteErrorBoundary>}>
                    <Route path="/" element={<HomePage />} />
                    <Route path="/sessions" element={<RunListPage />} />
                    <Route path="/runs/new" element={<NewRunPage />} />
                    <Route path="/runs/:runId" element={<RunPage />} />
                    <Route path="/runs/:runId/artifacts" element={<ArtifactsPage />} />
                    <Route path="/runs/:runId/loot" element={<LootPage />} />
                    <Route path="/runs/:runId/graph" element={<GraphPage />} />
                    <Route path="/skills" element={<SkillsPage />} />
                    <Route path="/modules" element={<AttackModulesPage />} />
                    <Route path="/goals" element={<GoalsPage />} />
                    <Route path="/graph" element={<AttackGraphPage />} />
                    <Route path="/stats" element={<StatsPage />} />
                    <Route path="/benchmarks" element={<BenchmarksPage />} />
                    <Route path="/benchmarks/new" element={<BenchmarksStartPage />} />
                    <Route path="/benchmarks/history" element={<BenchmarksHistoryPage />} />
                    <Route path="/benchmarks/:runId" element={<BenchmarkRunPage />} />
                    <Route path="/ops" element={<OpsPage />} />
                    <Route path="/connections" element={<ConnectionsPage />} />
                    <Route path="/help" element={<HelpPage />} />
                    <Route path="/memory" element={<MemoryPage />} />
                    <Route path="/system" element={<SystemPage />} />
                    <Route path="*" element={<Navigate to="/sessions" replace />} />
                  </Route>
                </Routes>
              </Suspense>
            </WelcomeGate>
          </OnboardingGate>
        </TokenGate>
      </BrowserRouter>
      <Toaster />
    </QueryClientProvider>
  );
}
