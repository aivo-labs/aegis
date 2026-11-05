import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  site: 'https://aegis.aivo.fr',
  base: '/docs',
  integrations: [
    starlight({
      title: 'Aegis Docs',
      logo: {
        src: './src/assets/logo.svg',
        alt: 'Aegis Logo',
        replacesTitle: false,
      },
      description: 'Official Aegis Documentation: Zero-Trust SOC & ESG Hardware Telemetry Compliant with RGESN / ANSSI / EFRAG.',
      defaultLocale: 'root',
      locales: {
        root: {
          label: '🇬🇧 English',
          lang: 'en',
        },
        fr: {
          label: '🇫🇷 Français',
          lang: 'fr',
        },
      },
      social: {
        github: 'https://github.com/aivo-labs/aegis',
      },
      editLink: {
        baseUrl: 'https://github.com/aivo-labs/aegis/edit/main/apps/docs/',
      },
      customCss: [
        './src/styles/custom.css',
      ],
      sidebar: [
        {
          label: '🚀 Welcome',
          translations: {
            fr: '🚀 Bienvenue',
          },
          items: [
            { label: 'Introduction & Vision', link: '/docs/' },
            { label: 'Quickstart (2 min)', translations: { fr: 'Démarrage Rapide (2 min)' }, slug: 'quickstart' },
          ],
        },
        {
          label: '📦 Deployment Guides',
          translations: {
            fr: '📦 Guides de Déploiement',
          },
          items: [
            { label: 'Single-Server & VPS (Docker / Dokploy)', translations: { fr: 'Mono-Serveur & VPS (Docker / Dokploy)' }, slug: 'guides/vps' },
            { label: 'Bare-Metal Dedicated Server (Hardware RAPL)', translations: { fr: 'Serveur Dédié Bare-Metal (RAPL Physique)' }, slug: 'guides/baremetal' },
            { label: 'Kubernetes Cluster (Helm & Kepler eBPF)', translations: { fr: 'Cluster Kubernetes (Helm & Kepler eBPF)' }, slug: 'guides/kubernetes' },
            { label: 'Standalone Client Agent (1-Click Script)', translations: { fr: 'Agent Client Seul (Script 1-Clic)' }, slug: 'guides/agent' },
          ],
        },
        {
          label: '🛡️ Zero-Trust Security',
          translations: {
            fr: '🛡️ Sécurité Zero-Trust',
          },
          items: [
            { label: 'Ingress PEP Gateway (WAF & Scanners)', translations: { fr: 'Passerelle Ingress PEP (WAF & Scanners)' }, slug: 'security/ingress-pep' },
            { label: 'Egress Gateway (CoreDNS & Nimble 9B)', translations: { fr: 'Passerelle Egress (CoreDNS & Nimble 9B)' }, slug: 'security/egress-gateway' },
          ],
        },
        {
          label: '⚡ Energy & ESG Compliance',
          translations: {
            fr: '⚡ Énergie & Conformité ESG',
          },
          items: [
            { label: 'Physical Metering & VS Standard (EFRAG)', translations: { fr: 'Mesure Physique & Norme VS (EFRAG)' }, slug: 'esg/telemetry' },
          ],
        },
        {
          label: '🧪 Pentest & Testbench',
          translations: {
            fr: '🧪 Pentest & Banc d\'Essai',
          },
          items: [
            { label: 'Attack Simulation & Live Testing', translations: { fr: 'Simulation d\'Attaques & Tests Live' }, slug: 'pentest/banc-essai' },
          ],
        },
      ],
    }),
  ],
});
