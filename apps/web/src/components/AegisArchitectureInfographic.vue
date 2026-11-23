<template>
  <section class="relative py-20 md:py-28 border-b border-slate-800/80 overflow-hidden bg-[#080d18]">
    <!-- Grille subtile d'arrière-plan -->
    <div class="absolute inset-0 bg-[linear-gradient(to_right,#10b9810a_1px,transparent_1px),linear-gradient(to_bottom,#10b9810a_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none"></div>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 space-y-12">
      
      <!-- En-tête de section -->
      <div class="max-w-3xl mx-auto text-center space-y-3">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-xs font-mono text-emerald-300">
          <span>{{ isFr ? 'ARCHITECTURE DE PROTECTION & MESURE UNIFIÉE' : 'UNIFIED PROTECTION & MEASUREMENT ARCHITECTURE' }}</span>
        </div>
        <h2 class="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
          {{ isFr ? 'Un Dôme Zero-Trust transparent au-dessus de votre SI' : 'A Transparent Zero-Trust Dome over your Infrastructure' }}
        </h2>
        <p class="text-sm sm:text-base text-slate-300 leading-relaxed">
          {{ isFr 
            ? 'Trois modules autonomes et complémentaires qui filtrent les flux entrants, verrouillent les exfiltrations sortantes et mesurent la consommation électrique réelle de vos serveurs.' 
            : 'Three autonomous, complementary modules that filter inbound traffic, lock down outbound exfiltration, and measure real server hardware power consumption.' }}
        </p>
      </div>

      <!-- SCÈNE VISUELLE : BLUEPRINT ARCHITECTURE AEGIS (VIDÉO MP4 / FALLBACK GIF) -->
      <div class="relative rounded-3xl bg-slate-950/80 border border-slate-800/90 p-3 sm:p-5 shadow-2xl overflow-hidden max-w-5xl mx-auto">
        <div class="relative w-full overflow-hidden rounded-2xl border border-slate-800/80 bg-[#060a12]">
          <video
            :key="isFr ? 'blueprint-fr' : 'blueprint-en'"
            class="w-full h-auto block object-cover"
            autoplay
            loop
            muted
            playsinline
            preload="metadata"
            :aria-label="isFr ? 'Blueprint animé de l\'architecture Aegis' : 'Animated Aegis Architecture Blueprint'"
          >
            <source
              :src="isFr ? '/assets/blueprint/aegis-blueprint-fr.mp4' : '/assets/blueprint/aegis-blueprint-en.mp4'"
              type="video/mp4"
            />
            <img
              :src="isFr ? '/assets/blueprint/aegis-blueprint-fr.gif' : '/assets/blueprint/aegis-blueprint-en.gif'"
              :alt="isFr ? 'Blueprint Architecture Aegis' : 'Aegis Architecture Blueprint'"
              class="w-full h-auto block"
              loading="lazy"
            />
          </video>
        </div>
      </div>

      <!-- SÉLECTEUR D'INTERCALAIRES & FICHE EXPLICATIVE FUSIONNÉE -->
      <div class="relative w-full max-w-5xl mx-auto pt-4">
        
        <!-- Version Mobile : Sélecteur segmenté horizontal ergonomique à portée de pouce -->
        <div class="flex md:hidden p-1.5 rounded-2xl bg-slate-950/90 border border-slate-800 gap-1.5 mb-3 shadow-xl">
          <button
            type="button"
            @click="activeModule = 'gate'"
            :class="[
              'flex-1 flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all cursor-pointer font-mono text-center',
              activeModule === 'gate'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-md'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            ]"
          >
            <span class="text-base">🛡️</span>
            <span class="text-xs font-bold mt-0.5">Gate</span>
            <span class="text-[10px] opacity-75">&lt; 1.5 ms</span>
          </button>

          <button
            type="button"
            @click="activeModule = 'egress'"
            :class="[
              'flex-1 flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all cursor-pointer font-mono text-center',
              activeModule === 'egress'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold shadow-md'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            ]"
          >
            <span class="text-base">🦅</span>
            <span class="text-xs font-bold mt-0.5">Egress</span>
            <span class="text-[10px] opacity-75">Sinkhole</span>
          </button>

          <button
            type="button"
            @click="activeModule = 'green'"
            :class="[
              'flex-1 flex flex-col items-center justify-center py-2 px-1 rounded-xl transition-all cursor-pointer font-mono text-center',
              activeModule === 'green'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold shadow-md'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            ]"
          >
            <span class="text-base">🌿</span>
            <span class="text-xs font-bold mt-0.5">Green</span>
            <span class="text-[10px] opacity-75">RAPL</span>
          </button>
        </div>

        <!-- SÉLECTEUR ORDINATEUR : LES 3 ONGLETS AVEC HAUTEUR STRICTEMENT ÉGALE ET TITRE SUR 2 LIGNES CENTRÉ -->
        <div class="hidden md:grid md:grid-cols-3 gap-2 md:gap-3 items-stretch">
          
          <!-- Intercalaire 1 : Aegis Gate -->
          <button
            type="button"
            @click="activeModule = 'gate'"
            :class="[
              'w-full text-center p-4 sm:p-5 rounded-t-2xl transition-all cursor-pointer relative h-28 flex flex-col justify-between',
              activeModule === 'gate'
                ? 'bg-slate-900 border-t-2 border-x border-cyan-400 text-white z-20 shadow-[0_-8px_20px_-5px_rgba(6,182,212,0.25)]'
                : 'bg-slate-950/70 hover:bg-slate-900/60 border-t border-x border-slate-800/80 text-slate-400 hover:text-slate-200 z-0 opacity-80 hover:opacity-100 rounded-b-xl md:rounded-b-none'
            ]"
          >
            <div 
              v-if="activeModule === 'gate'"
              class="absolute -top-[2px] inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
            ></div>

            <div class="flex items-center justify-between font-mono text-xs w-full">
              <span :class="['font-bold tracking-wider', activeModule === 'gate' ? 'text-cyan-400' : 'text-slate-400']">
                MODULE 01 • INGRESS
              </span>
              <span :class="['px-2 py-0.5 rounded text-[11px] font-semibold border', activeModule === 'gate' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' : 'bg-slate-800/80 text-slate-400 border-slate-700/60']">
                &lt; 1.5 ms
              </span>
            </div>

            <div class="flex flex-col items-center justify-center text-center my-auto">
              <div class="text-base sm:text-lg font-extrabold text-white flex items-center justify-center gap-1.5">
                <span>🛡️</span>
                <span>Aegis Gate</span>
              </div>
              <div class="text-xs sm:text-sm font-semibold text-slate-300 mt-0.5">
                WAF &amp; Virtual Patching
              </div>
            </div>
          </button>

          <!-- Intercalaire 2 : Aegis Egress -->
          <button
            type="button"
            @click="activeModule = 'egress'"
            :class="[
              'w-full text-center p-4 sm:p-5 rounded-t-2xl transition-all cursor-pointer relative h-28 flex flex-col justify-between',
              activeModule === 'egress'
                ? 'bg-slate-900 border-t-2 border-x border-amber-400 text-white z-20 shadow-[0_-8px_20px_-5px_rgba(245,158,11,0.25)]'
                : 'bg-slate-950/70 hover:bg-slate-900/60 border-t border-x border-slate-800/80 text-slate-400 hover:text-slate-200 z-0 opacity-80 hover:opacity-100 rounded-b-xl md:rounded-b-none'
            ]"
          >
            <div 
              v-if="activeModule === 'egress'"
              class="absolute -top-[2px] inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-amber-400 to-transparent"
            ></div>

            <div class="flex items-center justify-between font-mono text-xs w-full">
              <span :class="['font-bold tracking-wider', activeModule === 'egress' ? 'text-amber-400' : 'text-slate-400']">
                MODULE 02 • EGRESS
              </span>
              <span :class="['px-2 py-0.5 rounded text-[11px] font-semibold border', activeModule === 'egress' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-800/80 text-slate-400 border-slate-700/60']">
                Zero-Exfil
              </span>
            </div>

            <div class="flex flex-col items-center justify-center text-center my-auto">
              <div class="text-base sm:text-lg font-extrabold text-white flex items-center justify-center gap-1.5">
                <span>🦅</span>
                <span>Aegis Egress</span>
              </div>
              <div class="text-xs sm:text-sm font-semibold text-slate-300 mt-0.5">
                {{ isFr ? 'Sinkhole & IA Locale' : 'Sinkhole & Local AI' }}
              </div>
            </div>
          </button>

          <!-- Intercalaire 3 : Aegis Green -->
          <button
            type="button"
            @click="activeModule = 'green'"
            :class="[
              'w-full text-center p-4 sm:p-5 rounded-t-2xl transition-all cursor-pointer relative h-28 flex flex-col justify-between',
              activeModule === 'green'
                ? 'bg-slate-900 border-t-2 border-x border-emerald-400 text-white z-20 shadow-[0_-8px_20px_-5px_rgba(16,185,129,0.25)]'
                : 'bg-slate-950/70 hover:bg-slate-900/60 border-t border-x border-slate-800/80 text-slate-400 hover:text-slate-200 z-0 opacity-80 hover:opacity-100 rounded-b-xl md:rounded-b-none'
            ]"
          >
            <div 
              v-if="activeModule === 'green'"
              class="absolute -top-[2px] inset-x-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-400 to-transparent"
            ></div>

            <div class="flex items-center justify-between font-mono text-xs w-full">
              <span :class="['font-bold tracking-wider', activeModule === 'green' ? 'text-emerald-400' : 'text-slate-400']">
                MODULE 03 • GREEN IT
              </span>
              <span :class="['px-2 py-0.5 rounded text-[11px] font-semibold border', activeModule === 'green' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-slate-800/80 text-slate-400 border-slate-700/60']">
                RAPL
              </span>
            </div>

            <div class="flex flex-col items-center justify-center text-center my-auto">
              <div class="text-base sm:text-lg font-extrabold text-white flex items-center justify-center gap-1.5">
                <span>🌿</span>
                <span>Aegis Green</span>
              </div>
              <div class="text-xs sm:text-sm font-semibold text-slate-300 mt-0.5">
                {{ isFr ? 'Télémétrie Matérielle' : 'Hardware Telemetry' }}
              </div>
            </div>
          </button>

        </div>

        <!-- CARTE EXPLICATIVE DÉTAILLÉE : DIRECTEMENT RELIÉE À L'INTERCALAIRE ACTIF -->
        <div 
          :class="[
            'bg-slate-900 border border-slate-800 rounded-b-2xl md:rounded-tr-2xl shadow-2xl relative z-10 -mt-px overflow-hidden transition-all',
            activeModule === 'gate' ? 'md:rounded-tl-none border-t-cyan-500/30' : '',
            activeModule === 'egress' ? 'border-t-amber-500/30' : '',
            activeModule === 'green' ? 'md:rounded-tr-none border-t-emerald-500/30' : ''
          ]"
        >
          
          <!-- 1. En-tête explicatif détaillé du module actif -->
          <div class="p-6 sm:p-8 border-b border-slate-800/80 bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950/60">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div class="space-y-2">
                <div class="flex flex-wrap items-center gap-2.5">
                  <span class="text-2xl">{{ currentModuleData.icon }}</span>
                  <h3 class="text-xl sm:text-2xl font-extrabold text-white">
                    {{ currentModuleData.title }}
                  </h3>
                  <span :class="['px-2.5 py-0.5 rounded-full text-xs font-mono font-bold border', currentModuleData.badgeClass]">
                    {{ currentModuleData.tag }}
                  </span>
                </div>

                <!-- Sous-titre en petite police italique juste en dessous du titre -->
                <p class="text-xs sm:text-sm text-emerald-400/90 italic font-sans font-medium">
                  {{ currentModuleData.subtitle }}
                </p>

                <!-- Description détaillée -->
                <p class="text-sm text-slate-300 leading-relaxed max-w-3xl pt-1">
                  {{ currentModuleData.detailedDescription }}
                </p>
              </div>

              <!-- Métriques clés d'empreinte -->
              <div class="flex sm:flex-col items-center sm:items-end justify-between gap-2 shrink-0 bg-slate-950/70 p-3 sm:p-4 rounded-xl border border-slate-800 text-xs font-mono">
                <div class="text-slate-400">
                  {{ isFr ? 'Empreinte RAM :' : 'RAM Footprint:' }} <strong class="text-emerald-400 font-bold">{{ currentRamSpec }}</strong>
                </div>
                <div class="text-slate-400">
                  {{ isFr ? 'Impact latence :' : 'Latency Impact:' }} <strong class="text-cyan-400 font-bold">{{ currentLatencySpec }}</strong>
                </div>
              </div>
            </div>
          </div>

          <!-- 2. ZONE SCHÉMA ASCII (CENTRÉ JUSTE EN DESSOUS DE LA DESCRIPTION ET AU-DESSUS DES 3 BLOCS) -->
          <div class="p-6 sm:p-8 bg-slate-950/70 border-b border-slate-800/80 flex flex-col items-center text-center space-y-5">
            
            <!-- Bouton Centré pour afficher/masquer le schéma ASCII -->
            <button
              type="button"
              @click="showAscii = !showAscii"
              class="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white border border-slate-700 hover:border-slate-600 transition-all cursor-pointer font-semibold shadow-md text-xs font-mono"
            >
              <span>{{ showAscii 
                ? (isFr ? '▼ Masquer le schéma technique (ASCII)' : '▼ Hide technical diagram (ASCII)') 
                : (isFr ? '▶ Afficher le schéma technique détaillé (ASCII)' : '▶ Show detailed technical diagram (ASCII)') }}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {{ showAscii ? (isFr ? 'Replier' : 'Collapse') : (isFr ? 'Interactif' : 'Interactive') }}
              </span>
            </button>

            <!-- CONTENU DÉPLIÉ DU SCHÉMA AVEC SÉLECTEUR DE DIMENSIONNEMENT CENTRÉ AU-DESSUS DU DIAGRAMME -->
            <div 
              v-if="showAscii"
              class="w-full space-y-4 text-left animate-fadeIn pt-2"
            >
              <!-- Dimensionnement d'infrastructure CENTRÉ au-dessus du diagramme -->
              <div class="flex flex-col sm:flex-row items-center justify-center gap-2.5 pb-2 text-xs font-mono">
                <span class="text-slate-400 font-semibold">{{ isFr ? 'Dimensionnement :' : 'Sizing:' }}</span>
                <div class="flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
                  <button
                    type="button"
                    @click="companySize = 'vps'"
                    :class="[
                      'px-3 py-1.5 rounded-lg transition-all cursor-pointer text-xs font-mono',
                      companySize === 'vps'
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold'
                        : 'text-slate-400 hover:text-slate-200 border border-transparent'
                    ]"
                  >
                    {{ isFr ? 'TPE/PME (VPS)' : 'SMB / Startup (VPS)' }}
                  </button>

                  <button
                    type="button"
                    @click="companySize = 'baremetal'"
                    :class="[
                      'px-3 py-1.5 rounded-lg transition-all cursor-pointer text-xs font-mono',
                      companySize === 'baremetal'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold'
                        : 'text-slate-400 hover:text-slate-200 border border-transparent'
                    ]"
                  >
                    {{ isFr ? 'ETI (Bare-Metal)' : 'Mid-Market (Bare-Metal)' }}
                  </button>

                  <button
                    type="button"
                    @click="companySize = 'k8s'"
                    :class="[
                      'px-3 py-1.5 rounded-lg transition-all cursor-pointer text-xs font-mono',
                      companySize === 'k8s'
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold'
                        : 'text-slate-400 hover:text-slate-200 border border-transparent'
                    ]"
                  >
                    {{ isFr ? 'Grand Compte (K8s)' : 'Enterprise (K8s)' }}
                  </button>
                </div>
              </div>

              <!-- Bloc Terminal ASCII -->
              <div class="border border-slate-800 rounded-2xl overflow-hidden shadow-2xl bg-slate-950">
                <div class="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
                  <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span class="text-white font-bold">{{ currentSchemaTitle }}</span>
                  </div>
                  <button 
                    type="button" 
                    @click="copyAscii" 
                    class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 border border-slate-700 transition-all cursor-pointer text-[11px] flex items-center gap-1"
                  >
                    <span>{{ copied ? '✓' : '📋' }}</span>
                    <span>{{ copied ? (isFr ? 'Copié !' : 'Copied!') : (isFr ? 'Copier ASCII' : 'Copy ASCII') }}</span>
                  </button>
                </div>

                <div class="p-4 sm:p-5 bg-[#090d16] font-mono text-xs overflow-x-auto text-slate-300 leading-relaxed">
                  <pre class="text-cyan-300/90 whitespace-pre font-mono select-all">{{ currentAsciiDiagram }}</pre>
                </div>
              </div>
            </div>

          </div>

          <!-- 3. GRILLE DES 3 BLOCS TECHNIQUES (INTERCEPTION, CONFORMITÉ, FRUGALITÉ) -->
          <div class="p-6 sm:p-8 bg-slate-900/60 grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            
            <!-- Bloc 1 : Interception & Décision -->
            <div class="space-y-2.5 p-4 rounded-xl bg-slate-950/60 border border-slate-800/70">
              <div class="font-bold text-white flex items-center gap-2 font-mono text-xs">
                <span :class="currentModuleData.stepColor">01.</span>
                <span>{{ isFr ? 'Interception & Décision' : 'Interception & Decision' }}</span>
              </div>
              <p class="text-slate-300 leading-relaxed">
                {{ currentCardSpecs.interception }}
              </p>
            </div>

            <!-- Bloc 2 : Conformité & Métriques -->
            <div class="space-y-2.5 p-4 rounded-xl bg-slate-950/60 border border-slate-800/70">
              <div class="font-bold text-white flex items-center gap-2 font-mono text-xs">
                <span :class="currentModuleData.stepColor">02.</span>
                <span>{{ isFr ? 'Conformité & Métriques' : 'Compliance & Metrics' }}</span>
              </div>
              <p class="text-slate-300 leading-relaxed">
                {{ currentCardSpecs.compliance }}
              </p>
            </div>

            <!-- Bloc 3 : Frugalité & Empreinte Réelle (Remplace Déploiement Express) -->
            <div class="space-y-2.5 p-4 rounded-xl bg-slate-950/60 border border-slate-800/70 flex flex-col justify-between">
              <div>
                <div class="font-bold text-white flex items-center gap-2 font-mono text-xs mb-2">
                  <span :class="currentModuleData.stepColor">03.</span>
                  <span>{{ currentCardSpecs.frugalityTitle }}</span>
                </div>
                <p class="text-slate-300 leading-relaxed">
                  {{ currentCardSpecs.frugality }}
                </p>
              </div>
              <div class="mt-2 text-[10px] text-emerald-400/90 font-mono">
                {{ currentCardSpecs.frugalitySub }}
              </div>
            </div>

          </div>

          <!-- 4. Pied de fiche explicative : Garanties et lien documentation -->
          <div class="px-6 py-4 bg-slate-950 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
            <div class="flex flex-wrap items-center gap-2 text-slate-400">
              <span>{{ isFr ? 'Garanties :' : 'Guarantees:' }}</span>
              <span class="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">OWASP Top 10</span>
              <span class="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">{{ isFr ? 'Durcissement ANSSI' : 'ANSSI Hardening' }}</span>
              <span class="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">{{ isFr ? 'Norme VS EFRAG' : 'EFRAG VS Standard' }}</span>
            </div>

            <a 
              :href="currentDocLink" 
              class="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1.5 font-semibold hover:underline"
            >
              <span>{{ isFr ? 'Consulter le guide technique dans la doc' : 'Read technical guide in documentation' }}</span>
              <span>➔</span>
            </a>
          </div>

        </div>

      </div>

    </div>
  </section>
</template>

<script setup>
import { ref, computed } from 'vue';
import AegisLogo from './soc/AegisLogo.vue';

const props = defineProps({
  lang: {
    type: String,
    default: 'en'
  }
});

const isFr = computed(() => props.lang === 'fr');

const activeModule = ref('gate'); // 'gate' | 'egress' | 'green'
const companySize = ref('vps');   // 'vps' | 'baremetal' | 'k8s'
const showAscii = ref(false);     // Affichable à la demande
const copied = ref(false);

const modulesInfo = computed(() => {
  if (isFr.value) {
    return {
      gate: {
        icon: '🛡️',
        title: 'Aegis Gate (WAF & Virtual Patching)',
        subtitle: 'Inspection in-line, OWASP Top 10, anti-scans & latence < 1.5 ms',
        tag: 'INGRESS PEP',
        badgeClass: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
        stepColor: 'text-cyan-400 font-bold',
        detailedDescription: 'Inspecte chaque requête entrante (décodage multi-passes URL/SQL, anti-overflow HTTP 413) et bloque les scans automatisés (wp-login.php, .env) ainsi que les exploits RCE avant qu\'ils n\'atteignent votre serveur d\'application.',
      },
      egress: {
        icon: '🦅',
        title: 'Aegis Egress (Sinkhole & IA Locale)',
        subtitle: 'CoreDNS durci, sinkhole 0.0.0.0 & modèle SLM Nimble 9B local',
        tag: 'EGRESS & SINKHOLE',
        badgeClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
        stepColor: 'text-amber-400 font-bold',
        detailedDescription: 'Analyse l\'entropie de Shannon et les requêtes DNS/TCP sortantes pour couper net les callbacks Command & Control (C2), le tunneling DNS et les téléchargements de malwares post-exploitation via le modèle SLM Nimble 9B Air-Gapped.',
      },
      green: {
        icon: '🌿',
        title: 'Aegis Green (Télémétrie Matérielle)',
        subtitle: 'Watts/Joules réels /sys, PUE datacenters & Norme VS EFRAG',
        tag: 'GREEN IT & RAPL',
        badgeClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
        stepColor: 'text-emerald-400 font-bold',
        detailedDescription: 'Lit directement les registres matériels Linux RAPL (/sys/class/powercap) en Watts et Joules réels et audite l\'EcoIndex v3 de vos pages web pour certifier votre sobriété numérique selon la norme européenne VS (EFRAG 2026).',
      }
    };
  }
  return {
    gate: {
      icon: '🛡️',
      title: 'Aegis Gate (WAF & Virtual Patching)',
      subtitle: 'In-line inspection, OWASP Top 10, anti-scanners & latency < 1.5 ms',
      tag: 'INGRESS PEP',
      badgeClass: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
      stepColor: 'text-cyan-400 font-bold',
      detailedDescription: 'Inspects every inbound request (multi-pass URL/SQL decoding, anti-overflow HTTP 413) and blocks automated scanning tools (wp-login.php, .env) and RCE payloads before reaching your application.',
    },
    egress: {
      icon: '🦅',
      title: 'Aegis Egress (Sinkhole & Local AI)',
      subtitle: 'Hardened CoreDNS, 0.0.0.0 sinkhole & local Nimble 9B SLM',
      tag: 'EGRESS & SINKHOLE',
      badgeClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      stepColor: 'text-amber-400 font-bold',
      detailedDescription: 'Analyzes Shannon entropy and outbound DNS/TCP requests to drop Command & Control (C2) callbacks, DNS tunneling, and post-exploit stagers using the local Nimble 9B Air-Gapped SLM.',
    },
    green: {
      icon: '🌿',
      title: 'Aegis Green (Hardware Telemetry)',
      subtitle: 'Real /sys Watts/Joules, datacenter PUE & EFRAG VS standard',
      tag: 'GREEN IT & RAPL',
      badgeClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      stepColor: 'text-emerald-400 font-bold',
      detailedDescription: 'Directly reads Linux RAPL hardware energy registers (/sys/class/powercap) in true Watts and Joules and continuously computes EcoIndex v3 scores for verifiable EFRAG VS (2026) compliance.',
    }
  };
});

const currentModuleData = computed(() => modulesInfo.value[activeModule.value]);

const currentSchemaTitle = computed(() => {
  const modNames = isFr.value ? {
    gate: 'Aegis Gate — Ingress PEP WAF',
    egress: 'Aegis Egress — DNS & IA Nimble 9B',
    green: 'Aegis Green — Télémétrie Énergétique RAPL',
  } : {
    gate: 'Aegis Gate — Ingress PEP WAF',
    egress: 'Aegis Egress — DNS & Nimble 9B AI',
    green: 'Aegis Green — RAPL Hardware Telemetry',
  };
  const sizeNames = isFr.value ? {
    vps: 'Mono-Serveur / VPS (Docker Compose)',
    baremetal: 'Serveur Dédié Bare-Metal (Accès direct /sys)',
    k8s: 'Cluster Kubernetes (Helm & Kepler eBPF par Namespace)',
  } : {
    vps: 'Single-Server / VPS (Docker Compose)',
    baremetal: 'Bare-Metal Dedicated (Direct /sys access)',
    k8s: 'Kubernetes Cluster (Helm & Kepler eBPF by Namespace)',
  };
  return `${modNames[activeModule.value]} • ${sizeNames[companySize.value]}`;
});

const currentRamSpec = computed(() => {
  if (activeModule.value === 'gate') return isFr.value ? '< 25 Mo RAM' : '< 25 MB RAM';
  if (activeModule.value === 'egress') return isFr.value ? '< 35 Mo RAM (+ Nimble 9B)' : '< 35 MB RAM (+ Nimble 9B)';
  return isFr.value ? '< 15 Mo RAM' : '< 15 MB RAM';
});

const currentLatencySpec = computed(() => {
  if (activeModule.value === 'gate') return '< 1.5 ms';
  if (activeModule.value === 'egress') return isFr.value ? '< 4.2 ms (DNS) / < 45 ms (IA)' : '< 4.2 ms (DNS) / < 45 ms (AI)';
  return isFr.value ? 'Télémétrie passive 0 ms impact' : 'Passive telemetry 0 ms impact';
});

const currentDocLink = computed(() => {
  const prefix = isFr.value ? '/docs/fr' : '/docs';
  if (activeModule.value === 'gate') return `${prefix}/security/ingress-pep/`;
  if (activeModule.value === 'egress') return `${prefix}/security/egress-gateway/`;
  return `${prefix}/esg/telemetry/`;
});

const currentAsciiDiagram = computed(() => {
  // 1. KUBERNETES COMBINED ATTRIBUTION PAR NAMESPACE
  if (companySize.value === 'k8s') {
    return `[ CLIENT EXTERNE / BOTNET ]
               │
               ▼  (Port 80 / 443 Ingress)
┌──────────────┴─────────────────────────────────────────────────────────────────────────┐
│ ⎈ CLUSTER KUBERNETES (NAMESPACE aegis-system)                                          │
│                                                                                        │
│   ┌───────────────────────────────┐        ┌────────────────────────────────────────┐  │
│   │  Aegis Gate PEP (Envoy / WAF) │ ──▶─── │  Pod Métier Protégé (Ingress OK 200)   │  │
│   │  Rejets Nikto/SQLi/RCE (403)  │        │  (Service target-service:80)           │  │
│   └──────────────┬────────────────┘        └───────────────────┬────────────────────┘  │
│                  │ (Audit Ingress)                             │ (Requête Sortante)    │
│                  ▼                                             ▼                       │
│   ┌───────────────────────────────┐        ┌────────────────────────────────────────┐  │
│   │   Aegis Egress CoreDNS :53    │ ◀──────┤  CoreDNS Sinkhole (Interception C2)    │  │
│   │   Analyse IA System One Local │        │  Nimble 9B Air-Gapped (0 token Cloud)  │  │
│   └──────────────┬────────────────┘        └────────────────────────────────────────┘  │
│                  │                                                                     │
│                  ▼ (Télémétrie eBPF par Namespace)                                     │
│   ┌─────────────────────────────────────────────────────────────────────────────────┐  │
│   │  SONDE KEPLER eBPF DAEMONSET (Attribution Énergétique Granulaire)               │  │
│   │  • Namespace "production"  ──▶ 142.5 Joules/s (Watts) [SLA Limit: 200W]        │  │
│   │  • Namespace "staging"     ──▶  38.2 Joules/s (Watts) [SLA Limit:  80W]        │  │
│   │  • Namespace "monitoring"  ──▶  19.1 Joules/s (Watts) [SLA Limit:  40W]        │  │
│   └────────────────────────────────────────┬────────────────────────────────────────┘  │
└────────────────────────────────────────────┼───────────────────────────────────────────┘
                                             ▼
                 [ PUSH API SÉCURISÉ /api/v1/telemetry/push ]
                 [ COCKPIT ESG NORME VS (EFRAG) & SOC UNIFIÉ ]`;
  }

  // 2. BARE-METAL SERVEUR DÉDIÉ
  if (companySize.value === 'baremetal') {
    return `[ RÉSEAU PHYSIQUE ] ──▶ [ INTERFACE HÔTE (eth0 / hostNetwork) ]
                                      │
        ┌─────────────────────────────┴─────────────────────────────┐
        │ SERVEUR DÉDIÉ BARE-METAL (ACCÈS DIRECT REGISTRES RAPL)    │
        │                                                           │
        │   ┌───────────────────────────┐                           │
        │   │ Aegis Gate PEP (:8000)    │ ──▶ Filtrage in-line      │
        │   │ Interception OWASP & LFI  │     < 0.8 ms de surcoût   │
        │   └─────────────┬─────────────┘                           │
        │                 ▼                                         │
        │   ┌───────────────────────────┐                           │
        │   │ Aegis Egress DNS (:5053)  │ ──▶ Moteur Nimble 9B      │
        │   │ Cache local CrowdSec CTI  │     Bloquage Ransomware   │
        │   └─────────────┬─────────────┘                           │
        │                 ▼                                         │
        │   ┌───────────────────────────────────────────────────┐   │
        │   │ SONDE RUST PHYSIQUE (/sys/class/powercap/intel-rapl)  │
        │   │ Compteur matériel CPU + DRAM physique (0 émulation)│  │
        │   └─────────────────────────┬─────────────────────────┘   │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
             [ AUDIT CERTIFIABLE SCOPES 1 & 2 POUR COMMISSAIRES RSE ]`;
  }

  // 3. MONO-SERVEUR / VPS
  if (activeModule.value === 'gate') {
    return `[ REQUÊTE ENTRANTE (Ingress) ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│  Aegis Gate PEP / WAF (Port 8000 - Frugal < 25 Mo RAM) │
│  Analyse in-line des en-têtes, query params et payload │
└──────────────────────────┬─────────────────────────────┘
              ┌────────────┴────────────┐
              ▼                         ▼
   [ MENACE DÉTECTÉE ]         [ TRAFIC CONFORME ]
   • Nikto/SQLmap UA           • Navigateurs réels
   • Injection SQL UNION       • Requêtes API authentifiées
   • Traversal ../etc/passwd   • Latence ajoutée < 1.5 ms
              │                         │
              ▼                         ▼
   [ 403 FORBIDDEN ]           [ REVERSE-PROXY VERS APP ]
   (Payload bloqué net)        Web (:4321) / Backend (:8080)
              │                         │
              └────────────┬────────────┘
                           ▼
          [ LOG D'AUDIT SOUVERAIN TIMESCALEDB ]
          [ ALIMENTATION DU KANBAN DE TRIAGE EN DIRECT ]`;
  }

  if (activeModule.value === 'egress') {
    return `[ APPLICATION INTERNE / CONTAINER ]
               │
               ▼  (Requête DNS sortante UDP 53)
┌────────────────────────────────────────────────────────┐
│  Aegis Egress Gateway (Port 5053 - CoreDNS durci)      │
└──────────────────────────┬─────────────────────────────┘
              ┌────────────┴────────────┐
              ▼                         ▼
   [ DOMAINE CTI CONNU ]       [ FQDN INCONNU / DGA ]
   Blacklist CrowdSec CTI      Analyse d'entropie Shannon
              │                         │
              │                         ▼
              │                [ SYSTEM ONE LOCAL IA ]
              │                Nimble 9B (Ollama Air-Gapped)
              │                Décision d'intention < 45 ms
              │                         │
              └────────────┬────────────┘
                           ▼
          ┌────────────────┴────────────────┐
          ▼                                 ▼
   [ ACTION: BLOCK ]                 [ ACTION: ALLOW ]
   Sinkhole 0.0.0.0                  Résolution DNS chiffrée
   Alerte exfiltration C2            Sortie autorisée`;
  }

  // Green / VPS
  return `[ HÔTE VIRTUELISÉ (KVM / VPS) ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│  Aegis Telemetry Agent (Rust < 15 Mo RAM, 0% CPU idle) │
│  Lecture passive /proc/stat & /sys toutes les 5 sec    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│  Normalisation Énergétique & Calcul d'Impact           │
│  • PUE Datacenter appliqué (ex: 1.15 Scaleway/OVH)     │
│  • Conversion continue Watts ──▶ Joules cumulés        │
│  • Facteur d'émission temps réel RTE EcoWatt           │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│  Rapport RSE Conforme Norme VS (EFRAG 2026)            │
│  • Données physiques auditables (pas de ratios €/$ )  │
│  • Export certifiable pour auditeurs CSRD & DSI        │
└────────────────────────────────────────────────────────┘`;
});

const currentCardSpecs = computed(() => {
  const frugalityTitle = isFr.value ? 'Frugalité & Empreinte Réelle' : 'Frugality & Physical Footprint';

  if (isFr.value) {
    if (activeModule.value === 'gate') {
      return {
        interception: 'Détection par expressions régulières compilées en mémoire et vérification d\'en-têtes. Bloque instantanément scanners automatisés (Nikto, Nuclei, sqlmap), injections SQL et traversées de répertoires.',
        compliance: 'Conforme aux recommandations de durcissement ANSSI et au guide OWASP Top 10. Taux de faux positifs mesuré inférieur à 3%.',
        frugalityTitle,
        frugality: 'Conteneur ultra-léger (< 25 Mo de RAM), écrit en Go et TypeScript compilé. Zéro runtime lourd Java ou Python, évaluation des règles d\'entropie et WAF sous 1.5 ms avec moins de 1% d\'utilisation CPU.',
        frugalitySub: '• Sobriété Numérique RGESN 4.15 • CPU < 1%'
      };
    }
    if (activeModule.value === 'egress') {
      return {
        interception: 'Filtrage sortant DNS couplé à un cache CTI et au modèle SLM Nimble 9B. Détecte les domaines à haute entropie générés par malware (DGA) et les canaux de commande & contrôle (C2).',
        compliance: 'Zero-Log sur la vie privée des employés. 0 token transmis à des tiers américains (protection totale contre le Cloud Act).',
        frugalityTitle,
        frugality: 'CoreDNS durci ultra-rapide (< 4.2 ms) couplé au SLM Nimble 9B local quantifié en 4-bit. Zéro fuite de télémétrie vers des API cloud tierces, consommation maîtrisée sous 35 Mo (ou 5.8 Go VRAM avec IA locale).',
        frugalitySub: '• 100% Hors-Ligne • Protection Cloud Act'
      };
    }
    return {
      interception: 'Sonde matérielle en Rust prélevant les Joules bruts via RAPL (Running Average Power Limit) ou Kepler eBPF sous Linux. Aucun ralentissement de vos applications.',
      compliance: 'Conforme à la norme européenne VS (EFRAG) pour l\'ESG et au RGESN 2024 pour l\'éco-conception logicielle.',
      frugalityTitle,
      frugality: 'Agent Rust compilé statiquement (< 15 Mo de RAM). Lecture directe des registres matériels Intel/AMD RAPL (/sys/class/powercap) sans aucune surcharge (0.05% CPU). Données physiques réelles opposables aux auditeurs RSE.',
      frugalitySub: '• Registres Physiques RAPL • Zéro ratio théorique'
    };
  }

  // English
  if (activeModule.value === 'gate') {
    return {
      interception: 'In-memory compiled regex pattern matching and header sanitization. Instantly blocks automated scanning tools (Nikto, Nuclei, sqlmap), SQL injections, and directory traversals.',
      compliance: 'Compliant with ANSSI hardening standards and OWASP Top 10 guidelines. Empirically measured false-positive rate under 3%.',
      frugalityTitle,
      frugality: 'Ultra-frugal container (< 25 MB RAM), engineered with Go and compiled TypeScript. Zero heavy Java or Python runtimes, evaluating entropy and WAF rules in under 1.5 ms with sub-1% CPU load.',
      frugalitySub: '• RGESN 4.15 Eco-Design • CPU < 1%'
    };
  }
  if (activeModule.value === 'egress') {
    return {
      interception: 'Outbound DNS filtering backed by local CTI cache and Nimble 9B SLM. Detects algorithmic high-entropy domains (DGA) and Command & Control (C2) callbacks.',
      compliance: 'Zero-Log employee privacy design. 0 tokens sent to third-party US cloud providers (strict isolation against US Cloud Act).',
      frugalityTitle,
      frugality: 'Hardened sub-millisecond CoreDNS (< 4.2 ms) coupled with local 4-bit quantized Nimble 9B SLM. Zero telemetry sent to external cloud APIs, memory strictly contained under 35 MB (or 5.8 GB VRAM with local AI).',
      frugalitySub: '• 100% Offline • Cloud Act Immunity'
    };
  }
  return {
    interception: 'Lightweight Rust hardware daemon polling raw Joules via RAPL (Running Average Power Limit) or Linux Kepler eBPF. Zero runtime overhead on running applications.',
    compliance: 'Fully aligned with European EFRAG VS standards for ESG reporting and RGESN guidelines for software eco-design.',
    frugalityTitle,
    frugality: 'Statically-compiled Rust agent (< 15 MB RAM). Direct hardware sampling from Intel/AMD RAPL registers (/sys/class/powercap) with near-zero overhead (0.05% CPU). Physical, audit-grade Joules for CSRD reports.',
    frugalitySub: '• Physical RAPL MSRs • Zero statistical guesses'
  };
});

function copyAscii() {
  if (!currentAsciiDiagram.value) return;
  navigator.clipboard.writeText(currentAsciiDiagram.value).then(() => {
    copied.value = true;
    setTimeout(() => {
      copied.value = false;
    }, 2000);
  });
}
</script>

<style scoped>
@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-fadeIn {
  animation: fadeIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
</style>
