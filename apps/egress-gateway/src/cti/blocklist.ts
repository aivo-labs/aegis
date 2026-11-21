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

/**
 * Verrou n°5-Bis (v1.3 « Anti-Artex ») : Infrastructures de callback OAST (Out-of-Band Application Security Testing)
 * utilisées par les agents de pentest IA (ARTEX, Nuclei/Interactsh, Burp Collaborator) pour valider
 * les vulnérabilités aveugles (Blind SSRF, Blind RCE, Blind XXE, Log4Shell).
 */
export const OAST_CALLBACK_SUFFIXES = [
  'interact.sh',
  'interactsh.com',
  'oast.pro',
  'oast.live',
  'oast.site',
  'oast.online',
  'oast.fun',
  'oast.me',
  'burpcollaborator.net',
  'oastify.com',
  'canarytokens.com',
  'webhook.site',
  'requestbin.com',
  'requestbin.net',
  'pipedream.net',
  'beeceptor.com',
  'hookbin.com',
  'dnslog.cn',
  'ceye.io'
];

/**
 * Verrou n°5-Bis (v1.3 « Anti-Artex ») : Relais et tunnels « Living-off-the-Trusted-Cloud » (LOTC)
 * détournés en post-exploitation pour exfiltrer des secrets depuis un serveur de production.
 */
export const LOTC_EXFIL_SUFFIXES = [
  'ngrok-free.app',
  'ngrok.io',
  'ngrok.app',
  'trycloudflare.com',
  'loca.lt',
  'serveo.net',
  'localhost.run',
  'transfer.sh',
  'temp.sh',
  '0x0.st',
  'file.io'
];

export const EGRESS_EXFIL_REGEX = /(?:revshell|reverse-shell|c2-beacon|malware-exfil|ransomware|cobaltstrike|xmrig|meterpreter|shell-callback|dnscat|iodine|exfiltrat)/i;

export interface OastLotcMatch {
  matched: boolean;
  category?: 'OAST_BLIND_CALLBACK' | 'LOTC_EXFIL_TUNNEL';
  matchedSuffix?: string;
}

export interface ICtiBlocklistManager {
  isBlocked(domain: string): boolean;
  matchesExfilPattern(fqdn: string): boolean;
  isOastOrLotcRelay?(fqdn: string): OastLotcMatch;
  addDomain(domain: string): void;
  removeDomain(domain: string): void;
  getAllDomains(): string[];
}

export class CtiBlocklistManager implements ICtiBlocklistManager {
  private readonly blocklist: Set<string>;

  constructor(initialDomains: string[] = DEFAULT_CROWDSEC_BLOCKLIST) {
    this.blocklist = new Set(initialDomains.map(d => d.toLowerCase()));
  }

  public isOastOrLotcRelay(fqdn: string): OastLotcMatch {
    if (!fqdn) return { matched: false };
    const clean = fqdn.toLowerCase().replace(/\.$/, '').trim();

    for (const suffix of OAST_CALLBACK_SUFFIXES) {
      if (clean === suffix || clean.endsWith(`.${suffix}`)) {
        return {
          matched: true,
          category: 'OAST_BLIND_CALLBACK',
          matchedSuffix: suffix
        };
      }
    }

    for (const suffix of LOTC_EXFIL_SUFFIXES) {
      if (clean === suffix || clean.endsWith(`.${suffix}`)) {
        return {
          matched: true,
          category: 'LOTC_EXFIL_TUNNEL',
          matchedSuffix: suffix
        };
      }
    }

    return { matched: false };
  }

  public isBlocked(domain: string): boolean {
    if (!domain) return false;
    const clean = domain.toLowerCase().replace(/\.$/, '').trim();
    if (this.blocklist.has(clean)) return true;
    return this.isOastOrLotcRelay(clean).matched;
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

