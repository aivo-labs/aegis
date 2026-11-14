import type { InspectionContext, RuleMatch } from '../types.js';

export interface IWafRule {
  readonly id: string;
  readonly name: string;
  readonly order: number;
  evaluate(ctx: InspectionContext, canonicalTarget: string): RuleMatch | null;
}
