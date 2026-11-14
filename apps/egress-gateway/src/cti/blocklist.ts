export const DEFAULT_CROWDSEC_BLOCKLIST = [
  'c2-beacon.random-domain.top',
  'malware-exfil.badsite.xyz',
  'ransomware-key-exchange.cc',
  'phishing-verify-account.click',
  'revshell-callback.darknet-c2.top',
  'cobaltstrike-beacon.evil-infra.ru',
  'xmrig-pool.crypto-drain.xyz',
  'exfil-tunnel.shadow-drop.cc'
];

export const EGRESS_EXFIL_REGEX = /(?:revshell|reverse-shell|c2-beacon|malware-exfil|ransomware|cobaltstrike|xmrig|meterpreter|shell-callback|dnscat|iodine|exfiltrat)/i;

export interface ICtiBlocklistManager {
  isBlocked(domain: string): boolean;
  matchesExfilPattern(fqdn: string): boolean;
  addDomain(domain: string): void;
  removeDomain(domain: string): void;
  getAllDomains(): string[];
}

export class CtiBlocklistManager implements ICtiBlocklistManager {
  private readonly blocklist: Set<string>;

  constructor(initialDomains: string[] = DEFAULT_CROWDSEC_BLOCKLIST) {
    this.blocklist = new Set(initialDomains.map(d => d.toLowerCase()));
  }

  public isBlocked(domain: string): boolean {
    if (!domain) return false;
    return this.blocklist.has(domain.toLowerCase().trim());
  }

  public matchesExfilPattern(fqdn: string): boolean {
    return EGRESS_EXFIL_REGEX.test(fqdn);
  }

  public addDomain(domain: string): void {
    if (domain) {
      this.blocklist.add(domain.toLowerCase().trim());
    }
  }

  public removeDomain(domain: string): void {
    if (domain) {
      this.blocklist.delete(domain.toLowerCase().trim());
    }
  }

  public getAllDomains(): string[] {
    return Array.from(this.blocklist);
  }
}
