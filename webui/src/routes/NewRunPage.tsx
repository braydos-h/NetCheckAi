import { useNavigate, useSearchParams } from "react-router-dom";
import { RunWizard } from "@/components/run-create/RunWizard";

export function NewRunPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // The wizard reads ?path= only at mount; remount when it changes (e.g. the
  // user edits the URL from ?path=recon to ?path=attack) so the mode follows.
  const pathKey = searchParams.get("path") ?? "";
  return (
    <RunWizard key={pathKey} onCreated={(runId) => navigate(`/runs/${runId}`)} />
  );
}
