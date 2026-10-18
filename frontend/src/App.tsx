import { Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import { ThemeProvider } from './components/theme';
import UploadPage from './pages/Upload';
import LiveScanPage from './pages/LiveScan';
import OverviewPage from './pages/Overview';
import FindingsPage from './pages/Findings';
import AiFindingsPage from './pages/AiFindings';
import HistoryPage from './pages/History';
import RulesPage from './pages/Rules';
import SystemPage from './pages/System';

export default function App() {
  return (
    <ThemeProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<UploadPage />} />
          <Route path="scans/:scanId/live" element={<LiveScanPage />} />
          <Route path="scans/:scanId" element={<OverviewPage />} />
          <Route path="scans/:scanId/findings" element={<FindingsPage />} />
          <Route path="scans/:scanId/ai-findings" element={<AiFindingsPage />} />
          <Route path="history" element={<HistoryPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="system" element={<SystemPage />} />
          <Route path="*" element={<UploadPage />} />
        </Route>
      </Routes>
    </ThemeProvider>
  );
}
