import { ThemeProvider } from "@/providers/ThemeProvider";
import { useAppStore } from "@/stores/app-store";
import { Wizard } from "@/components/wizard/Wizard";
import { Workspace } from "@/components/layout/Workspace";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { SessionLanding } from "@/components/landing/SessionLanding";
import { TourProvider } from "@/ftue/TourProvider";

function AppContent() {
  const appView = useAppStore((s) => s.appView);
  if (appView === "workspace") return <Workspace />;
  if (appView === "wizard") return <Wizard />;
  return <SessionLanding />;
}

export default function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary>
        <TourProvider>
          <AppContent />
        </TourProvider>
      </ErrorBoundary>
    </ThemeProvider>
  );
}
