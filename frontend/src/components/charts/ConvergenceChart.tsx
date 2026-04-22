/**
 * Line chart showing detection quality vs number of dumps (N).
 */
import type { ConvergenceSweepResult } from '../../api/types';
import { EmptyState } from '@/components/common/EmptyState';
import { ConvergenceIcon } from '@/components/common/Icons';
import { chartTokens } from './tokens';

interface ConvergenceChartProps {
  data: ConvergenceSweepResult | null;
}

export function ConvergenceChart({ data }: ConvergenceChartProps) {
  if (!data || data.points.length === 0) {
    return (
      <EmptyState
        icon={<ConvergenceIcon />}
        title="No convergence data"
        description={
          <>
            Plots recall and false-positive rate as N sweeps from 1 to max. Produced by the experiment harness or by
            {" "}<code>memdiver consensus --convergence</code>.
          </>
        }
        secondary={{ label: "CLI quickstart", href: "/docs/quickstart/experiment.md" }}
        data-testid="convergence-empty"
      />
    );
  }

  const maxFP = Math.max(...data.points.map(p => p.aligned?.fp ?? p.variance.fp));
  const chartHeight = 200;
  const chartWidth = 600;
  const padding = { top: 20, right: 60, bottom: 40, left: 60 };
  const plotW = chartWidth - padding.left - padding.right;
  const plotH = chartHeight - padding.top - padding.bottom;

  const xScale = (n: number) => {
    const ns = data.points.map(p => p.n);
    const idx = ns.indexOf(n);
    return padding.left + (idx / (ns.length - 1)) * plotW;
  };

  const recallScale = (r: number) => padding.top + (1 - r) * plotH;
  const fpScale = (fp: number) => padding.top + (1 - fp / Math.max(maxFP, 1)) * plotH;

  const recallPath = data.points
    .filter(p => p.aligned?.recall != null)
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(p.n)} ${recallScale(p.aligned!.recall)}`)
    .join(' ');

  const fpPath = data.points
    .filter(p => p.aligned?.fp != null)
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(p.n)} ${fpScale(p.aligned!.fp)}`)
    .join(' ');

  const t = chartTokens();
  return (
    <div className="p-4">
      <h3 className="text-sm font-semibold mb-2" style={{ color: t.textPrimary }}>
        Convergence: Detection Quality vs Number of Dumps
      </h3>
      <div className="flex gap-4 text-xs mb-2" style={{ color: t.textSecondary }}>
        {data.first_detection_n && (
          <span>First detection: N={data.first_detection_n}</span>
        )}
        {data.first_decryption_n && (
          <span>First decryption: N={data.first_decryption_n}</span>
        )}
        {data.first_fp_target_n && (
          <span>FP target met: N={data.first_fp_target_n}</span>
        )}
      </div>
      <svg
        width={chartWidth}
        height={chartHeight}
        className="rounded"
        style={{ background: t.chartPlot }}
      >
        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map(v => (
          <line key={v} x1={padding.left} x2={chartWidth - padding.right}
                y1={recallScale(v)} y2={recallScale(v)}
                stroke={t.chartGrid} strokeDasharray="2,4" />
        ))}
        {/* Recall line (green) */}
        {recallPath && <path d={recallPath} fill="none" stroke={t.accentGreen} strokeWidth={2} />}
        {/* FP line (red) */}
        {fpPath && <path d={fpPath} fill="none" stroke={t.accentRed} strokeWidth={2} />}
        {/* Dots */}
        {data.points.map(p => p.aligned && (
          <g key={p.n}>
            <circle cx={xScale(p.n)} cy={recallScale(p.aligned.recall)}
                    r={3} fill={t.accentGreen} />
            <circle cx={xScale(p.n)} cy={fpScale(p.aligned.fp)}
                    r={3} fill={t.accentRed} />
          </g>
        ))}
        {/* X-axis labels */}
        {data.points.map(p => (
          <text key={p.n} x={xScale(p.n)} y={chartHeight - 5}
                fill={t.textMuted} fontSize={10} textAnchor="middle">
            {p.n}
          </text>
        ))}
        {/* Y-axis labels */}
        <text x={10} y={padding.top + plotH / 2} fill={t.accentGreen} fontSize={10}
              transform={`rotate(-90, 10, ${padding.top + plotH / 2})`} textAnchor="middle">
          Recall %
        </text>
        <text x={chartWidth - 5} y={padding.top + plotH / 2} fill={t.accentRed} fontSize={10}
              transform={`rotate(90, ${chartWidth - 5}, ${padding.top + plotH / 2})`} textAnchor="middle">
          False Positives
        </text>
        {/* First detection marker */}
        {data.first_detection_n && (
          <line x1={xScale(data.first_detection_n)} x2={xScale(data.first_detection_n)}
                y1={padding.top} y2={chartHeight - padding.bottom}
                stroke={t.accentYellow} strokeDasharray="4,2" strokeWidth={1} />
        )}
      </svg>
      <div className="flex gap-4 mt-2 text-xs">
        <span className="flex items-center gap-1">
          <span className="w-3 h-0.5 inline-block" style={{ background: t.accentGreen }} /> Recall
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-0.5 inline-block" style={{ background: t.accentRed }} /> False Positives
        </span>
        {data.first_detection_n && (
          <span className="flex items-center gap-1">
            <span className="w-3 h-0.5 inline-block border-dashed" style={{ background: t.accentYellow }} /> First Detection
          </span>
        )}
      </div>
    </div>
  );
}
