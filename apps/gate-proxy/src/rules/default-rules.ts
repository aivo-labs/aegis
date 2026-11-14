import { WafRuleRegistry } from './registry.js';
import { ScannerRule } from './scanner.rule.js';
import { ZeroDayRule } from './zeroday.rule.js';
import { RceRule } from './rce.rule.js';
import { SsrfRule } from './ssrf.rule.js';
import { SqliRule } from './sqli.rule.js';
import { TraversalRule } from './traversal.rule.js';
import { SensitiveProbeRule } from './sensitive-probe.rule.js';
import { CmsProbeRule } from './cms-probe.rule.js';
import { XssRule } from './xss.rule.js';

export function createDefaultRuleRegistry(): WafRuleRegistry {
  const registry = new WafRuleRegistry();
  registry.register(new ScannerRule());
  registry.register(new ZeroDayRule());
  registry.register(new RceRule());
  registry.register(new SsrfRule());
  registry.register(new SqliRule());
  registry.register(new TraversalRule());
  registry.register(new SensitiveProbeRule());
  registry.register(new CmsProbeRule());
  registry.register(new XssRule());
  return registry;
}
