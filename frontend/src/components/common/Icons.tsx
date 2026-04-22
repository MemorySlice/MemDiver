import type { SVGProps } from "react";

const baseProps = {
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
  focusable: false,
};

type IconProps = Omit<SVGProps<SVGSVGElement>, "aria-hidden" | "focusable">;

export function ArchitectIcon(props: IconProps) {
  return (
    <svg {...baseProps} {...props}>
      <path d="M4 20V7l8-3 8 3v13" />
      <path d="M9 20v-6h6v6" />
      <path d="M4 13h16" />
    </svg>
  );
}

export function ExperimentIcon(props: IconProps) {
  return (
    <svg {...baseProps} {...props}>
      <path d="M9 3h6" />
      <path d="M10 3v6.5L5 19a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 19l-5-9.5V3" />
      <path d="M7.5 15h9" />
    </svg>
  );
}

export function LiveConsensusIcon(props: IconProps) {
  return (
    <svg {...baseProps} {...props}>
      <path d="M3 12h3l2-6 4 12 2-9 3 6h4" />
    </svg>
  );
}

export function ConsensusIcon(props: IconProps) {
  return (
    <svg {...baseProps} {...props}>
      <path d="M12 4 3 9l9 5 9-5-9-5z" />
      <path d="M3 14l9 5 9-5" />
      <path d="M3 19l9 5 9-5" />
    </svg>
  );
}

export function ConvergenceIcon(props: IconProps) {
  return (
    <svg {...baseProps} {...props}>
      <path d="M3 20h18" />
      <path d="M4 16l4-4 3 3 5-6 4 4" />
      <circle cx="8" cy="12" r="1" fill="currentColor" />
      <circle cx="11" cy="15" r="1" fill="currentColor" />
      <circle cx="16" cy="9" r="1" fill="currentColor" />
    </svg>
  );
}
