'use client';

import { useQuery } from '@tanstack/react-query';
import { metricsApi } from '@/lib/api';
import { StatCard } from '@/components/stat-card';
import {
  Users,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Globe,
  Clock,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  Legend,
} from 'recharts';

export default function DashboardPage() {
  const { data: stats } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => metricsApi.dashboard(),
    refetchInterval: 30_000,
  });

  const { data: growth } = useQuery({
    queryKey: ['user-growth'],
    queryFn: () => metricsApi.userGrowth(30),
  });

  const { data: timeline } = useQuery({
    queryKey: ['event-timeline'],
    queryFn: () => metricsApi.eventTimeline(7),
  });

  const s = stats?.users;

  return (
    <div className="space-y-8 animate-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Real-time platform overview — refreshes every 30s
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        <StatCard
          title="Total Users"
          value={s?.total?.toLocaleString() ?? '—'}
          icon={Users}
          color="violet"
        />
        <StatCard
          title="Active Sessions"
          value={stats?.sessions?.active?.toLocaleString() ?? '—'}
          icon={Globe}
          color="blue"
        />
        <StatCard
          title="New Users (7d)"
          value={s?.new7d?.toLocaleString() ?? '—'}
          icon={Users}
          color="emerald"
          trend={s?.new7d > 0 ? 12 : 0}
          trendLabel="vs prev week"
        />
        <StatCard
          title="MFA Adoption"
          value={s ? `${s.mfaAdoptionRate.toFixed(1)}%` : '—'}
          icon={ShieldCheck}
          color="emerald"
        />
        <StatCard
          title="Audit Events (24h)"
          value={stats?.audit?.events24h?.toLocaleString() ?? '—'}
          icon={Activity}
          color="amber"
        />
        <StatCard
          title="Failed Logins (24h)"
          value={stats?.audit?.failedLogins24h?.toLocaleString() ?? '—'}
          icon={AlertTriangle}
          color="rose"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* User Growth */}
        <div className="card">
          <h2 className="text-sm font-semibold text-zinc-300 mb-4">User Growth (30d)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={growth ?? []}>
              <defs>
                <linearGradient id="growthGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="date" tick={{ fill: '#71717a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#71717a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#a1a1aa' }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#8b5cf6"
                strokeWidth={2}
                fill="url(#growthGrad)"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Event Timeline */}
        <div className="card">
          <h2 className="text-sm font-semibold text-zinc-300 mb-4">Auth Events (7d)</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={timeline ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="date" tick={{ fill: '#71717a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#71717a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }}
              />
              <Legend wrapperStyle={{ fontSize: 12, color: '#a1a1aa' }} />
              <Bar dataKey="success" fill="#10b981" radius={[3, 3, 0, 0]} />
              <Bar dataKey="failure" fill="#f43f5e" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
