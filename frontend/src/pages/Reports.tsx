import { useState } from 'react';
import { FileText, BarChart2, TrendingUp, Calendar } from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    BarChart,
    Bar,
    Legend,
} from 'recharts';
import Header from '../components/layout/Header.tsx';

interface ComplianceTrendData {
    date: string;
    complianceRate: number;
    criticalAlerts: number;
}

interface ContractAnalysisHistory {
    id: string;
    contractName: string;
    dateAnalyzed: string;
    complianceScore: number;
    riskLevel: 'High' | 'Medium' | 'Low';
    jurisdiction: string;
}

interface RiskTrendData {
    date: string;
    high: number;
    medium: number;
    low: number;
}

// Mock data
const mockComplianceTrend: ComplianceTrendData[] = [
    { date: 'Jan', complianceRate: 70, criticalAlerts: 15 },
    { date: 'Feb', complianceRate: 75, criticalAlerts: 12 },
    { date: 'Mar', complianceRate: 80, criticalAlerts: 10 },
    { date: 'Apr', complianceRate: 82, criticalAlerts: 9 },
    { date: 'May', complianceRate: 85, criticalAlerts: 7 },
    { date: 'Jun', complianceRate: 87, criticalAlerts: 5 },
    { date: 'Jul', complianceRate: 89, criticalAlerts: 4 },
];

const mockContractHistory: ContractAnalysisHistory[] = [
    { id: 'C001', contractName: 'Service Agreement v2.1', dateAnalyzed: '2025-07-15', complianceScore: 92, riskLevel: 'Low', jurisdiction: 'MY' },
    { id: 'C002', contractName: 'NDA with GlobalTech', dateAnalyzed: '2025-07-14', complianceScore: 88, riskLevel: 'Medium', jurisdiction: 'SG' },
    { id: 'C003', contractName: 'Employment Contract - EU', dateAnalyzed: '2025-07-12', complianceScore: 75, riskLevel: 'High', jurisdiction: 'EU' },
    { id: 'C004', contractName: 'Privacy Policy Update', dateAnalyzed: '2025-07-10', complianceScore: 95, riskLevel: 'Low', jurisdiction: 'US' },
    { id: 'C005', contractName: 'Vendor Agreement Q3', dateAnalyzed: '2025-07-08', complianceScore: 80, riskLevel: 'Medium', jurisdiction: 'MY' },
];

const mockRiskTrend: RiskTrendData[] = [
    { date: 'Jan', high: 4, medium: 5, low: 3 },
    { date: 'Feb', high: 3, medium: 4, low: 6 },
    { date: 'Mar', high: 5, medium: 6, low: 7 },
    { date: 'Apr', high: 2, medium: 5, low: 8 },
    { date: 'May', high: 3, medium: 3, low: 10 },
    { date: 'Jun', high: 1, medium: 4, low: 11 },
    { date: 'Jul', high: 2, medium: 3, low: 12 },
];

export default function Reports() {
    const [startDate, setStartDate] = useState('2025-01-01');
    const [endDate, setEndDate] = useState('2025-07-31');
    const [reportGenerated, setReportGenerated] = useState(false);
    const [filteredComplianceTrend, setFilteredComplianceTrend] = useState<ComplianceTrendData[]>(mockComplianceTrend);
    const [filteredRiskTrend, setFilteredRiskTrend] = useState<RiskTrendData[]>(mockRiskTrend);
    const [filteredContractHistory, setFilteredContractHistory] = useState<ContractAnalysisHistory[]>(mockContractHistory);

    const generateReport = () => {
        const from = new Date(startDate);
        const to = new Date(endDate);

        const filteredCompliance = mockComplianceTrend.filter((d) => {
            const [year, month] = d.date.split('-').map(Number);
            const dateObj = new Date(year, month - 1);
            return dateObj >= from && dateObj <= to;
        });

        const filteredRisk = mockRiskTrend.filter((d) => {
            const [year, month] = d.date.split('-').map(Number);
            const dateObj = new Date(year, month - 1);
            return dateObj >= from && dateObj <= to;
        });

        const filteredContracts = mockContractHistory.filter((d) => {
            const dateObj = new Date(d.dateAnalyzed);
            return dateObj >= from && dateObj <= to;
        });

        setFilteredComplianceTrend(filteredCompliance);
        setFilteredRiskTrend(filteredRisk);
        setFilteredContractHistory(filteredContracts);
        setReportGenerated(true);
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 to-slate-950 text-gray-100">
            <Header />
            <main className="max-w-7xl mx-auto py-16 px-4 sm:px-6 lg:px-8">
                <h1 className="text-4xl font-extrabold text-white mb-8 text-center drop-shadow-lg">Reports & Analytics</h1>

                {/* Date Range Selector */}
                <section className="bg-slate-800 p-6 rounded-lg shadow-2xl border border-slate-700 mb-8">
                    <h2 className="text-xl font-semibold text-blue-300 mb-4 flex items-center gap-2">
                        <Calendar className="w-6 h-6" /> Select Report Period
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label htmlFor="start-date" className="block text-sm text-gray-300 mb-1">Start Date</label>
                            <input
                                type="date"
                                id="start-date"
                                className="w-full px-3 py-2 border rounded-md bg-slate-700 text-gray-200"
                                value={startDate}
                                onChange={(e) => setStartDate(e.target.value)}
                            />
                        </div>
                        <div>
                            <label htmlFor="end-date" className="block text-sm text-gray-300 mb-1">End Date</label>
                            <input
                                type="date"
                                id="end-date"
                                className="w-full px-3 py-2 border rounded-md bg-slate-700 text-gray-200"
                                value={endDate}
                                onChange={(e) => setEndDate(e.target.value)}
                            />
                        </div>
                    </div>
                    <div className="mt-6 text-right">
                        <button onClick={generateReport} className="bg-blue-700 hover:bg-blue-800 text-white py-2 px-6 rounded-md">Generate Report</button>
                    </div>
                </section>

                {/* Report Summary */}
                {reportGenerated && (
                    <section className="bg-slate-800 p-6 rounded-lg shadow-2xl border border-slate-700 mb-8">
                        <h2 className="text-xl font-semibold text-blue-300 mb-4">📊 Report Summary</h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 text-center">
                            <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-600">
                                <p className="text-sm text-gray-400">Total Contracts</p>
                                <p className="text-2xl font-bold text-white">{filteredContractHistory.length}</p>
                            </div>
                            <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-600">
                                <p className="text-sm text-gray-400">Avg Compliance Score</p>
                                <p className="text-2xl font-bold text-white">
                                    {filteredContractHistory.length > 0
                                        ? Math.round(
                                                filteredContractHistory.reduce((sum, c) => sum + c.complianceScore, 0) / filteredContractHistory.length
                                            )
                                        : 0}%
                                </p>
                            </div>
                            <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-600">
                                <p className="text-sm text-gray-400">High / Medium / Low Risk</p>
                                <p className="text-2xl font-bold text-white">
                                    {filteredContractHistory.filter((c) => c.riskLevel === 'High').length} /{' '}
                                    {filteredContractHistory.filter((c) => c.riskLevel === 'Medium').length} /{' '}
                                    {filteredContractHistory.filter((c) => c.riskLevel === 'Low').length}
                                </p>
                            </div>
                            <div className="bg-slate-900/40 p-4 rounded-lg border border-slate-600">
                                <p className="text-sm text-gray-400">Jurisdictions Involved</p>
                                <p className="text-2xl font-bold text-white">
                                    {[...new Set(filteredContractHistory.map(c => c.jurisdiction))].join(', ') || 'N/A'}
                                </p>
                            </div>
                        </div>
                    </section>
                )}

                {/* Compliance Charts */}
                <section className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                    <div className="bg-slate-800 p-6 rounded-lg shadow-2xl border border-slate-700">
                        <h2 className="text-xl font-semibold text-blue-300 mb-4 flex items-center gap-2">
                            <BarChart2 className="w-6 h-6" /> Historical Compliance Rate
                        </h2>
                        <ResponsiveContainer width="100%" height={300}>
                            <LineChart data={filteredComplianceTrend}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
                                <XAxis dataKey="date" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1e293b' }}
                                    itemStyle={{ color: '#e2e8f0' }}
                                    labelStyle={{ color: '#cbd5e1' }}
                                />
                                <Line type="monotone" dataKey="complianceRate" stroke="#059669" name="Compliance Rate (%)" />
                                <Line type="monotone" dataKey="criticalAlerts" stroke="#dc2626" name="Critical Alerts" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="bg-slate-800 p-6 rounded-lg shadow-2xl border border-slate-700">
                        <h2 className="text-xl font-semibold text-blue-300 mb-4 flex items-center gap-2">
                            <TrendingUp className="w-6 h-6" /> Risk Trend Analysis
                        </h2>
                        <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={filteredRiskTrend} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#475569" />
                                <XAxis dataKey="date" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1e293b' }}
                                    itemStyle={{ color: '#e2e8f0' }}
                                    labelStyle={{ color: '#cbd5e1' }}
                                />
                                <Legend />
                                <Bar dataKey="high" fill="#ef4444" name="High Risk" />
                                <Bar dataKey="medium" fill="#f59e0b" name="Medium Risk" />
                                <Bar dataKey="low" fill="#10b981" name="Low Risk" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </section>

                {/* Contract Analysis History */}
                <section className="bg-slate-800 p-6 rounded-lg shadow-2xl border border-slate-700 mb-8">
                    <h2 className="text-xl font-semibold text-blue-300 mb-4 flex items-center gap-2">
                        <FileText className="w-6 h-6" /> Contract Analysis History
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-slate-700/50">
                            <thead className="bg-slate-700/30">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs text-gray-400 uppercase">Contract Name</th>
                                    <th className="px-6 py-3 text-left text-xs text-gray-400 uppercase">Date</th>
                                    <th className="px-6 py-3 text-left text-xs text-gray-400 uppercase">Score</th>
                                    <th className="px-6 py-3 text-left text-xs text-gray-400 uppercase">Risk</th>
                                    <th className="px-6 py-3 text-left text-xs text-gray-400 uppercase">Jurisdiction</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-700">
                                {filteredContractHistory.map((c) => (
                                    <tr key={c.id} className="hover:bg-slate-700/20">
                                        <td className="px-6 py-4 text-sm text-white">{c.contractName}</td>
                                        <td className="px-6 py-4 text-sm text-gray-300">{c.dateAnalyzed}</td>
                                        <td className="px-6 py-4 text-sm text-gray-300">{c.complianceScore}%</td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2 inline-flex text-xs rounded-full border
                                                ${c.riskLevel === 'High'
                                                    ? 'bg-red-700/30 text-red-300 border-red-500'
                                                    : c.riskLevel === 'Medium'
                                                    ? 'bg-amber-700/30 text-amber-200 border-amber-500'
                                                    : 'bg-green-700/30 text-green-300 border-green-500'}`}>
                                                {c.riskLevel}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-sm text-gray-300">{c.jurisdiction}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </section>
            </main>
        </div>
    );
}
