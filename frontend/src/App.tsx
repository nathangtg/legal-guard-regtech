import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import Analyze from './pages/Analyze'
import BulkAnalyze from './pages/BulkAnalyze'
import Compliance from './pages/Compliance'
import Regulations from './pages/Regulations'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Login from './pages/Login'
import Signup from './pages/Signup'
import AdminManagement from './pages/AdminManagement'
import AIInsights from './pages/AIInsights'
import ProtectedRoute from './components/ProtectedRoute'
import AnalysisResults from './pages/AnalysisResult'

export default function App() {
  return (
    <Router>
      <Routes>
        {/* Public routes */}
        <Route path='/' element={<Landing />} />
        <Route path='/login' element={<Login />} />
        <Route path='/signup' element={<Signup />} />
        <Route path='/compliance' element={<Compliance />} />
        <Route path='/regulations' element={<Regulations />} />

        {/* Protected routes */}
        <Route path='/dashboard' element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path='/analyze' element={
          <ProtectedRoute>
            <Analyze />
          </ProtectedRoute>
        } />
        <Route path='/analysis/:analysisId' element={
          <ProtectedRoute>
            <AnalysisResults />
          </ProtectedRoute>
        } />
        <Route path='/bulk-analyze' element={
          <ProtectedRoute>
            <BulkAnalyze />
          </ProtectedRoute>
        } />
        <Route path='/ai-insights' element={
          <ProtectedRoute>
            <AIInsights />
          </ProtectedRoute>
        } />
        <Route path='/reports' element={
          <ProtectedRoute>
            <Reports />
          </ProtectedRoute>
        } />
        <Route path='/settings' element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        } />
        <Route path='/admin' element={
          <ProtectedRoute requiredRole="super-admin">
            <AdminManagement />
          </ProtectedRoute>
        } />
      </Routes>
    </Router>
  )
}


