import type { IWafRule } from './rule.interface.js';

export class WafRuleRegistry {
  private rules: IWafRule[] = [];

  public register(rule: IWafRule): this {
    this.rules.push(rule);
    this.rules.sort((a, b) => a.order - b.order);
    return this;
  }

  public getRules(): readonly IWafRule[] {
    return this.rules;
  }

  public clear(): void {
    this.rules = [];
  }
}
