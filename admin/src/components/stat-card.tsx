'use client';

import { clsx } from 'clsx';
import {
  TrendingUp,
  TrendingDown,
  Minus,
} from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  trend?: number;  // percent change
  trendLabel?: string;
  color?: 'violet' | 'blue' | 'emerald' | 'rose' | 'amber';
}

const colorMap = {
  violet: 'from-violet-500/20 to-violet-500/5 border-violet-500/20 text-violet-400',
  blue:   'from-blue-500/20   to-blue-500/5   border-blue-500/20   text-blue-400',
  emerald:'from-emerald-500/20 to-emerald-500/5 border-emerald-500/20 text-emerald-400',
  rose:   'from-rose-500/20   to-rose-500/5   border-rose-500/20   text-rose-400',
  amber:  'from-amber-500/20  to-amber-500/5  border-amber-500/20  text-amber-400',
};

export function StatCard({ title, value, icon: Icon, trend, trendLabel, color = 'violet' }: StatCardProps) {
  const col = colorMap[color];

  return (
    <div className={clsx(
      'rounded-xl border bg-gradient-to-br p-5 animate-in',
      col,
    )}>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm font-medium text-zinc-400">{title}</p>
        <div className={clsx('w-9 h-9 rounded-lg flex items-center justify-center', `bg-${color}-500/15`)}>
          <Icon className={clsx('w-4 h-4', `text-${color}-400`)} />
        </div>
      </div>
      <p className="text-3xl font-bold text-white tabular-nums">{value}</p>
      {trend !== undefined && (
        <div className="flex items-center gap-1 mt-2">
          {trend > 0 ? (
            <TrendingUp className="w-3 h-3 text-emerald-400" />
          ) : trend < 0 ? (
            <TrendingDown className="w-3 h-3 text-rose-400" />
          ) : (
            <Minus className="w-3 h-3 text-zinc-500" />
          )}
          <span className={clsx(
            'text-xs',
            trend > 0 ? 'text-emerald-400' : trend < 0 ? 'text-rose-400' : 'text-zinc-500',
          )}>
            {trend > 0 ? '+' : ''}{trend}% {trendLabel ?? ''}
          </span>
        </div>
      )}
    </div>
  );
}
