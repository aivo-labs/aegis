export interface IIpReputationManager {
  isBanned(ip: string): boolean;
  ban(ip: string): void;
  unban(ip: string): void;
  clear(): void;
  getAll(): string[];
  setAll(ips: string[]): void;
  size(): number;
}

export class IpReputationManager implements IIpReputationManager {
  private readonly bannedIps = new Set<string>();

  public isBanned(ip: string): boolean {
    if (!ip) return false;
    return this.bannedIps.has(ip);
  }

  public ban(ip: string): void {
    if (ip && typeof ip === 'string') {
      this.bannedIps.add(ip.trim());
    }
  }

  public unban(ip: string): void {
    if (ip) {
      this.bannedIps.delete(ip.trim());
    }
  }

  public clear(): void {
    this.bannedIps.clear();
  }

  public getAll(): string[] {
    return Array.from(this.bannedIps);
  }

  public setAll(ips: string[]): void {
    this.bannedIps.clear();
    for (const ip of ips) {
      this.ban(ip);
    }
  }

  public size(): number {
    return this.bannedIps.size;
  }
}
