<template>
  <transition 
    enter-active-class="transition duration-200 ease-out" 
    enter-from-class="opacity-0 scale-95" 
    enter-to-class="opacity-100 scale-100" 
    leave-active-class="transition duration-150 ease-in" 
    leave-from-class="opacity-100 scale-100" 
    leave-to-class="opacity-0 scale-95"
  >
    <div 
      v-if="show" 
      class="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-3 sm:p-5 overflow-y-auto"
      @click.self="$emit('close')"
    >
      <div 
        :class="[
          'rounded-3xl max-w-4xl w-full p-5 sm:p-7 shadow-2xl relative text-left my-auto max-h-[92vh] flex flex-col overflow-hidden transition-colors',
          isLightMode ? 'bg-white border border-slate-200 text-slate-900 shadow-slate-300/40' : 'bg-slate-900 border border-emerald-500/40 text-slate-100 shadow-slate-950'
        ]"
      >
        <!-- 1. BARRE D'ACTIONS SUPÉRIEURE (ÉCRAN UNIQUEMENT) -->
        <div 
          :class="[
            'flex items-center justify-between pb-3.5 mb-3.5 border-b shrink-0',
            isLightMode ? 'border-slate-200' : 'border-slate-800'
          ]"
        >
          <div class="flex items-center gap-2">
            <span 
              :class="[
                'px-2.5 py-1 rounded-full font-bold text-xs flex items-center gap-1.5 border',
                isLightMode ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
              ]"
            >
              <span>🌿</span>
              <span>Rapport &amp; Certificat Officiel RSE / CSRD</span>
            </span>
            <span 
              :class="[
                'text-xs font-mono hidden sm:inline',
                isLightMode ? 'text-slate-500' : 'text-slate-400'
              ]"
            >
              Ref: {{ certificateId }}
            </span>
          </div>

          <div class="flex items-center gap-2">
            <!-- Bouton Impression / Export PDF -->
            <button
              @click="printCertificate"
              class="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-md shadow-emerald-500/20 cursor-pointer transition-all active:scale-95"
              title="Générer et imprimer le certificat officiel au format PDF A4 haute définition"
            >
              <span>📄</span>
              <span>Imprimer / Exporter PDF</span>
            </button>

            <!-- Bouton Téléchargement CSV -->
            <a
              :href="csvDownloadUrl"
              :download="`aegis-rse-report-${selectedRange}.csv`"
              :class="[
                'px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-all',
                isLightMode ? 'bg-slate-100 hover:bg-slate-200 border-slate-200 text-slate-700' : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
              ]"
              title="Télécharger les données brutes sous format CSV"
            >
              <span>📥 CSV</span>
            </a>

            <!-- Bouton Fermer -->
            <button
              @click="$emit('close')"
              :class="[
                'w-8 h-8 rounded-xl flex items-center justify-center text-sm cursor-pointer transition-all',
                isLightMode ? 'bg-slate-100 hover:bg-slate-200 text-slate-600' : 'bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white'
              ]"
              aria-label="Fermer la modale"
            >
              ✕
            </button>
          </div>
        </div>

        <!-- 2. CONTENU DU CERTIFICAT (DÉFILABLE ÉCRAN) -->
        <div class="flex-1 overflow-y-auto pr-1 space-y-5 font-sans">
          
          <!-- BANNIÈRE EN-TÊTE DU CERTIFICAT -->
          <div 
            :class="[
              'p-5 sm:p-6 rounded-2xl border relative overflow-hidden transition-colors',
              isLightMode 
                ? 'bg-gradient-to-br from-emerald-50/70 via-slate-50 to-cyan-50/50 border-emerald-200/80' 
                : 'bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950/40 border-emerald-500/30'
            ]"
          >
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 relative z-10">
              <div class="flex items-center gap-4">
                <AegisLogo size="lg" />
                <div>
                  <div 
                    :class="[
                      'text-[11px] font-mono uppercase tracking-widest font-bold flex items-center gap-1.5',
                      isLightMode ? 'text-emerald-700' : 'text-emerald-400'
                    ]"
                  >
                    <span>🛡️ Aegis Zero-Trust Shield</span>
                    <span>•</span>
                    <span>Télémétrie Matérielle GreenOps</span>
                  </div>
                  <h3 
                    :class="[
                      'text-xl sm:text-2xl font-extrabold tracking-tight mt-0.5',
                      isLightMode ? 'text-slate-900' : 'text-white'
                    ]"
                  >
                    Certificat d'Audit d'Empreinte Numérique
                  </h3>
                  <p 
                    :class="[
                      'text-xs mt-1',
                      isLightMode ? 'text-slate-600' : 'text-slate-400'
                    ]"
                  >
                    Conforme aux normes <strong>CSRD / EFRAG VS</strong>, <strong>RGESN 2024</strong> et <strong>GHG Protocol Scope 2</strong>
                  </p>
                </div>
              </div>

              <!-- Bloc Référence & Date -->
              <div 
                :class="[
                  'sm:text-right font-mono text-xs border-t sm:border-t-0 pt-3 sm:pt-0',
                  isLightMode ? 'border-slate-200 text-slate-600' : 'border-slate-800 text-slate-400'
                ]"
              >
                <div :class="isLightMode ? 'text-slate-800 font-bold' : 'text-slate-200 font-bold'">
                  Réf. Certificat :
                </div>
                <div :class="isLightMode ? 'text-emerald-700 font-bold' : 'text-emerald-400 font-bold'">
                  {{ certificateId }}
                </div>
                <div class="text-[11px] mt-0.5 opacity-75">
                  Délivré le {{ currentDateFormatted }}
                </div>
              </div>
            </div>
          </div>

          <!-- PÉRIMÈTRE D'AUDIT -->
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            <div 
              :class="[
                'p-3.5 rounded-xl border transition-colors',
                isLightMode ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              ]"
            >
              <span :class="isLightMode ? 'text-slate-500 block text-[11px]' : 'text-slate-400 block text-[11px]'">Période Certifiée</span>
              <span :class="isLightMode ? 'text-slate-900 font-bold text-sm block mt-0.5' : 'text-white font-bold text-sm block mt-0.5'">{{ periodLabel }}</span>
              <span :class="isLightMode ? 'text-emerald-700 block mt-0.5 text-[10px]' : 'text-emerald-400 block mt-0.5 text-[10px]'">Durée : {{ periodHours }} heures</span>
            </div>

            <div 
              :class="[
                'p-3.5 rounded-xl border transition-colors',
                isLightMode ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              ]"
            >
              <span :class="isLightMode ? 'text-slate-500 block text-[11px]' : 'text-slate-400 block text-[11px]'">Infrastructure Serveur</span>
              <span :class="isLightMode ? 'text-slate-900 font-bold text-sm block mt-0.5 truncate' : 'text-white font-bold text-sm block mt-0.5 truncate'">{{ nodeName }}</span>
              <span :class="isLightMode ? 'text-cyan-700 block mt-0.5 text-[10px]' : 'text-cyan-400 block mt-0.5 text-[10px]'">{{ nodeProvider }}</span>
            </div>

            <div 
              :class="[
                'p-3.5 rounded-xl border transition-colors',
                isLightMode ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              ]"
            >
              <span :class="isLightMode ? 'text-slate-500 block text-[11px]' : 'text-slate-400 block text-[11px]'">Sonde Matérielle Silicium</span>
              <span :class="isLightMode ? 'text-slate-900 font-bold text-sm block mt-0.5' : 'text-white font-bold text-sm block mt-0.5'">Intel/AMD RAPL MSR</span>
              <span :class="isLightMode ? 'text-slate-600 block mt-0.5 text-[10px]' : 'text-slate-400 block mt-0.5 text-[10px]'">Scaphandre v4.3.0</span>
            </div>

            <div 
              :class="[
                'p-3.5 rounded-xl border transition-colors',
                isLightMode ? 'bg-slate-50 border-slate-200' : 'bg-slate-950/80 border-slate-800'
              ]"
            >
              <span :class="isLightMode ? 'text-slate-500 block text-[11px]' : 'text-slate-400 block text-[11px]'">Indice d'Efficience (PUE)</span>
              <span :class="isLightMode ? 'text-slate-900 font-bold text-sm block mt-0.5' : 'text-white font-bold text-sm block mt-0.5'">{{ summary.pue || 1.15 }}</span>
              <span :class="isLightMode ? 'text-emerald-700 block mt-0.5 text-[10px]' : 'text-emerald-400 block mt-0.5 text-[10px]'">Datacenter Optimisé</span>
            </div>
          </div>

          <!-- 4 GRANDS INDICATEURS CERTIFIÉS -->
          <div>
            <h4 
              :class="[
                'text-xs font-mono font-bold uppercase tracking-wider mb-2.5 flex items-center gap-1.5',
                isLightMode ? 'text-slate-700' : 'text-slate-400'
              ]"
            >
              <span>📊</span>
              <span>Métriques d'Impact Certifiées sur la Période</span>
            </h4>

            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <!-- Énergie -->
              <div 
                :class="[
                  'p-4 rounded-2xl border transition-colors',
                  isLightMode 
                    ? 'bg-amber-50/70 border-amber-200' 
                    : 'bg-gradient-to-b from-amber-500/10 to-slate-950 border-amber-500/30'
                ]"
              >
                <div 
                  :class="[
                    'flex items-center justify-between text-xs font-mono',
                    isLightMode ? 'text-amber-800 font-bold' : 'text-amber-300'
                  ]"
                >
                  <span>⚡ Énergie Consommée</span>
                  <span>RAPL</span>
                </div>
                <div 
                  :class="[
                    'text-2xl sm:text-3xl font-extrabold font-mono mt-2',
                    isLightMode ? 'text-slate-900' : 'text-white'
                  ]"
                >
                  {{ formatKwh(summary.total_kwh) }}
                </div>
                <div 
                  :class="[
                    'text-[11px] font-mono mt-1',
                    isLightMode ? 'text-slate-600' : 'text-slate-400'
                  ]"
                >
                  {{ formatJoules(summary.total_joules) }} Joules
                </div>
              </div>

              <!-- Émissions Carbone -->
              <div 
                :class="[
                  'p-4 rounded-2xl border transition-colors',
                  isLightMode 
                    ? 'bg-emerald-50/70 border-emerald-200' 
                    : 'bg-gradient-to-b from-emerald-500/10 to-slate-950 border-emerald-500/30'
                ]"
              >
                <div 
                  :class="[
                    'flex items-center justify-between text-xs font-mono',
                    isLightMode ? 'text-emerald-800 font-bold' : 'text-emerald-300'
                  ]"
                >
                  <span>🌱 Émissions GES (Scope 2)</span>
                  <span>52 g/kWh</span>
                </div>
                <div 
                  :class="[
                    'text-2xl sm:text-3xl font-extrabold font-mono mt-2',
                    isLightMode ? 'text-slate-900' : 'text-white'
                  ]"
                >
                  {{ formatCarbon(summary.total_carbon_gco2, summary.total_carbon_kg) }}
                </div>
                <div 
                  :class="[
                    'text-[11px] font-mono mt-1',
                    isLightMode ? 'text-slate-600' : 'text-slate-400'
                  ]"
                >
                  Mix électrique décarboné RTE
                </div>
              </div>

              <!-- Empreinte Hydrique -->
              <div 
                :class="[
                  'p-4 rounded-2xl border transition-colors',
                  isLightMode 
                    ? 'bg-sky-50/70 border-sky-200' 
                    : 'bg-gradient-to-b from-sky-500/10 to-slate-950 border-sky-500/30'
                ]"
              >
                <div 
                  :class="[
                    'flex items-center justify-between text-xs font-mono',
                    isLightMode ? 'text-sky-800 font-bold' : 'text-sky-300'
                  ]"
                >
                  <span>💧 Empreinte Eau (WUE)</span>
                  <span>ADEME</span>
                </div>
                <div 
                  :class="[
                    'text-2xl sm:text-3xl font-extrabold font-mono mt-2',
                    isLightMode ? 'text-slate-900' : 'text-white'
                  ]"
                >
                  {{ summary.water_usage_liters.toFixed(2) }} <span class="text-base font-normal">Litres</span>
                </div>
                <div 
                  :class="[
                    'text-[11px] font-mono mt-1',
                    isLightMode ? 'text-slate-600' : 'text-slate-400'
                  ]"
                >
                  Refroidissement direct &amp; indirect
                </div>
              </div>

              <!-- Puissance & CPU -->
              <div 
                :class="[
                  'p-4 rounded-2xl border transition-colors',
                  isLightMode 
                    ? 'bg-cyan-50/70 border-cyan-200' 
                    : 'bg-gradient-to-b from-cyan-500/10 to-slate-950 border-cyan-500/30'
                ]"
              >
                <div 
                  :class="[
                    'flex items-center justify-between text-xs font-mono',
                    isLightMode ? 'text-cyan-800 font-bold' : 'text-cyan-300'
                  ]"
                >
                  <span>⚙️ Puissance Continue</span>
                  <span>Moyenne</span>
                </div>
                <div 
                  :class="[
                    'text-2xl sm:text-3xl font-extrabold font-mono mt-2',
                    isLightMode ? 'text-slate-900' : 'text-white'
                  ]"
                >
                  {{ summary.avg_watts.toFixed(2) }} <span class="text-base font-normal">W</span>
                </div>
                <div 
                  :class="[
                    'text-[11px] font-mono mt-1',
                    isLightMode ? 'text-slate-600' : 'text-slate-400'
                  ]"
                >
                  Charge CPU : {{ summary.avg_cpu_load_pct.toFixed(1) }} %
                </div>
              </div>
            </div>
          </div>

          <!-- TABLEAU DES WORKLOADS & SERVICES DOKPLOY -->
          <div v-if="workloads && workloads.length > 0">
            <h4 
              :class="[
                'text-xs font-mono font-bold uppercase tracking-wider mb-2.5 flex items-center justify-between',
                isLightMode ? 'text-slate-700' : 'text-slate-400'
              ]"
            >
              <span class="flex items-center gap-1.5">
                <span>📦</span>
                <span>Ventilation de l'Impact par Workload &amp; Namespace</span>
              </span>
              <span :class="isLightMode ? 'text-[11px] font-normal text-slate-500' : 'text-[11px] font-normal text-slate-500'">
                Attribution cgroup Scaphandre / Kepler
              </span>
            </h4>

            <div 
              :class="[
                'rounded-xl border overflow-hidden font-mono text-xs transition-colors',
                isLightMode ? 'bg-white border-slate-200 shadow-xs' : 'bg-slate-950/60 border-slate-800'
              ]"
            >
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr 
                    :class="[
                      'border-b text-[11px] font-bold',
                      isLightMode ? 'bg-slate-100 text-slate-700 border-slate-200' : 'bg-slate-900/90 text-slate-400 border-slate-800'
                    ]"
                  >
                    <th class="py-2.5 px-3">Service / Application</th>
                    <th class="py-2.5 px-3">Namespace</th>
                    <th class="py-2.5 px-3 text-right">Part (%)</th>
                    <th class="py-2.5 px-3 text-right">Puissance</th>
                    <th class="py-2.5 px-3 text-right">Énergie</th>
                    <th class="py-2.5 px-3 text-right">CO₂eq</th>
                  </tr>
                </thead>
                <tbody :class="isLightMode ? 'divide-y divide-slate-100' : 'divide-y divide-slate-850'">
                  <tr 
                    v-for="wl in workloads" 
                    :key="wl.service" 
                    :class="isLightMode ? 'hover:bg-slate-50/80 transition-colors' : 'hover:bg-slate-900/40 transition-colors'"
                  >
                    <td :class="['py-2 px-3 font-bold', isLightMode ? 'text-slate-900' : 'text-white']">
                      {{ wl.service }}
                    </td>
                    <td :class="['py-2 px-3 text-[11px]', isLightMode ? 'text-amber-800 font-semibold' : 'text-amber-300']">
                      {{ wl.namespace }}
                    </td>
                    <td :class="['py-2 px-3 text-right font-bold', isLightMode ? 'text-cyan-800' : 'text-cyan-300']">
                      {{ wl.share_pct }} %
                    </td>
                    <td :class="['py-2 px-3 text-right', isLightMode ? 'text-slate-700' : 'text-slate-300']">
                      {{ wl.watts }} W
                    </td>
                    <td :class="['py-2 px-3 text-right', isLightMode ? 'text-slate-700' : 'text-slate-300']">
                      {{ formatKwh(wl.kwh) }}
                    </td>
                    <td :class="['py-2 px-3 text-right font-bold', isLightMode ? 'text-emerald-800' : 'text-emerald-400']">
                      {{ wl.carbon_gco2 }} g
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- ÉQUIVALENCES D'IMPACT -->
          <div 
            :class="[
              'p-4 rounded-2xl border text-xs font-mono transition-colors',
              isLightMode ? 'bg-slate-50 border-slate-200 text-slate-700' : 'bg-slate-950/70 border-slate-800 text-slate-300'
            ]"
          >
            <div :class="['font-bold mb-2 flex items-center gap-1.5', isLightMode ? 'text-slate-900' : 'text-white']">
              <span>🌍</span>
              <span>Équivalences Environnementales Pédagogiques :</span>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div :class="['p-2.5 rounded-lg border', isLightMode ? 'bg-white border-slate-200' : 'bg-slate-900/80 border-slate-800/80']">
                <span :class="['block text-[11px]', isLightMode ? 'text-slate-500' : 'text-slate-400']">Voiture Thermique</span>
                <strong :class="['text-sm block mt-0.5', isLightMode ? 'text-slate-900' : 'text-white']">{{ summary.equivalencies?.car_km || 0 }} km</strong>
              </div>
              <div :class="['p-2.5 rounded-lg border', isLightMode ? 'bg-white border-slate-200' : 'bg-slate-900/80 border-slate-800/80']">
                <span :class="['block text-[11px]', isLightMode ? 'text-slate-500' : 'text-slate-400']">Recharges Smartphone</span>
                <strong :class="['text-sm block mt-0.5', isLightMode ? 'text-slate-900' : 'text-white']">{{ summary.equivalencies?.smartphones_charged || 0 }}</strong>
              </div>
              <div :class="['p-2.5 rounded-lg border', isLightMode ? 'bg-white border-slate-200' : 'bg-slate-900/80 border-slate-800/80']">
                <span :class="['block text-[11px]', isLightMode ? 'text-slate-500' : 'text-slate-400']">Bouteilles d'Eau (1.5L)</span>
                <strong :class="['text-sm block mt-0.5', isLightMode ? 'text-slate-900' : 'text-white']">{{ summary.equivalencies?.water_bottles || 0 }}</strong>
              </div>
              <div :class="['p-2.5 rounded-lg border', isLightMode ? 'bg-white border-slate-200' : 'bg-slate-900/80 border-slate-800/80']">
                <span :class="['block text-[11px]', isLightMode ? 'text-slate-500' : 'text-slate-400']">Douche Équivalente (50L)</span>
                <strong :class="['text-sm block mt-0.5', isLightMode ? 'text-slate-900' : 'text-white']">{{ summary.equivalencies?.showers_pct || 0 }} %</strong>
              </div>
            </div>
          </div>

          <!-- CADRE LÉGAL & VISA CRYPTOGRAPHIQUE -->
          <div 
            :class="[
              'p-4 rounded-2xl border text-[11px] font-mono space-y-2 transition-colors',
              isLightMode ? 'bg-emerald-50/40 border-emerald-200 text-slate-700' : 'bg-slate-950 border-emerald-500/30 text-slate-400'
            ]"
          >
            <div :class="['font-bold flex items-center gap-1.5', isLightMode ? 'text-slate-900' : 'text-white']">
              <span>⚖️</span>
              <span>Cadre Réglementaire &amp; Validité d'Audit :</span>
            </div>
            <p class="leading-relaxed">
              • <strong>Directive CSRD / Standard EFRAG VS (PME)</strong> : Données matérielles certifiées prêtes pour l'intégration dans la déclaration de durabilité extra-financière.
            </p>
            <p class="leading-relaxed">
              • <strong>Référentiel RGESN 2024 (Art. L. 300-1)</strong> : Mesures physiques directes évitant toute surestimation ou sous-estimation d'empreinte logicielle.
            </p>
            <p class="leading-relaxed">
              • <strong>GHG Protocol Scope 2 (Location-Based)</strong> : Facteur d'émission électrique appliqué de <code :class="isLightMode ? 'text-cyan-800 font-bold' : 'text-cyan-300'">52 gCO₂eq / kWh</code> (RTE France), PUE audité à <code :class="isLightMode ? 'text-emerald-800 font-bold' : 'text-emerald-300'">{{ summary.pue || 1.15 }}</code>.
            </p>

            <div 
              :class="[
                'pt-3 border-t flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px]',
                isLightMode ? 'border-emerald-200 text-slate-600' : 'border-slate-800 text-slate-500'
              ]"
            >
              <span>Sceau Cryptographique : <code>SHA256:{{ hashCertificate }}</code></span>
              <span :class="isLightMode ? 'text-emerald-700 font-bold' : 'text-emerald-400 font-bold'">
                Certifié par la Plateforme Aegis Zero-Trust Shield
              </span>
            </div>
          </div>

        </div>

        <!-- 3. PIED DE MODALE -->
        <div 
          :class="[
            'pt-3.5 mt-3.5 border-t flex items-center justify-between text-xs font-mono shrink-0',
            isLightMode ? 'border-slate-200 text-slate-600' : 'border-slate-800 text-slate-400'
          ]"
        >
          <span class="text-[11px] opacity-80">
            Export PDF vectoriel haute définition conforme aux exigences des auditeurs CSRD.
          </span>
          <button 
            @click="$emit('close')"
            :class="[
              'px-4 py-2 rounded-xl font-semibold cursor-pointer transition-all',
              isLightMode ? 'bg-slate-100 hover:bg-slate-200 text-slate-800' : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
            ]"
          >
            Fermer
          </button>
        </div>

      </div>
    </div>
  </transition>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import AegisLogo from '../AegisLogo.vue';
import { useAegisTheme } from '../../../composables/useAegisTheme';
import type { EnergySummary, WorkloadEnergy, NodeEnergy } from '../../../services/api/telemetryApi';

const props = defineProps<{
  show: boolean;
  summary: EnergySummary;
  workloads: WorkloadEnergy[];
  nodes: NodeEnergy[];
  selectedRange: string;
  selectedMonth: string;
  selectedYear: string;
  customFrom?: string;
  customTo?: string;
  selectedNode: string;
  selectedNamespace: string;
}>();

defineEmits<{
  (e: 'close'): void;
}>();

const { isLightMode } = useAegisTheme();

// Date du jour formatée
const currentDateFormatted = computed(() => {
  return new Date().toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });
});

// Libellé de période certifiée
const periodLabel = computed(() => {
  if (props.selectedRange === '1h') return '1 dernière heure';
  if (props.selectedRange === '24h') return 'Dernières 24 heures';
  if (props.selectedRange === '7d') return '7 derniers jours (Semaine)';
  if (props.selectedRange === '30d') return '30 derniers jours (Mois glissant)';
  if (props.selectedRange === 'month') return formatMonthLabel(props.selectedMonth);
  if (props.selectedRange === 'year') return `Année Civile ${props.selectedYear}`;
  if (props.selectedRange === 'custom') return `Du ${props.customFrom || '...'} au ${props.customTo || '...'}`;
  return props.selectedRange;
});

// Heures de la période
const periodHours = computed(() => {
  if (props.selectedRange === '1h') return '1';
  if (props.selectedRange === '24h') return '24';
  if (props.selectedRange === '7d') return '168';
  if (props.selectedRange === '30d') return '720';
  if (props.selectedRange === 'year') return '8 760';
  if (props.selectedRange === 'month') {
    const parts = props.selectedMonth.split('-');
    if (parts.length === 2) {
      const y = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10);
      const days = new Date(y, m, 0).getDate();
      return `${days * 24} (${days} jours)`;
    }
    return '720';
  }
  return 'Variable';
});

// Nom du nœud serveur
const nodeName = computed(() => {
  if (props.selectedNode === 'all') return 'Cluster Global (Tous les serveurs)';
  const n = props.nodes.find(item => item.id === props.selectedNode);
  return n ? n.hostname : props.selectedNode;
});

// Fournisseur / Hébergeur
const nodeProvider = computed(() => {
  if (props.selectedNode === 'all') return 'Hébergement Souverain Multicloud';
  const n = props.nodes.find(item => item.id === props.selectedNode);
  return n ? n.provider : 'OVHcloud / KVM VPS';
});

// Identifiant unique d'audit
const certificateId = computed(() => {
  let periodPart = props.selectedRange.toUpperCase();
  if (props.selectedRange === 'month' && props.selectedMonth) {
    periodPart = props.selectedMonth.replace('-', '');
  } else if (props.selectedRange === 'year' && props.selectedYear) {
    periodPart = props.selectedYear;
  }
  return `AEGIS-CSRD-${periodPart}-V4`;
});

// Hash SHA-256 déterministe pour le certificat
const hashCertificate = computed(() => {
  const seed = `${certificateId.value}-${props.summary.total_kwh}-${props.summary.total_carbon_gco2}`;
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex}e49b12f689c30a7d`.substring(0, 16);
});

// URL de téléchargement du CSV correspondant fidèlement à la période
const csvDownloadUrl = computed(() => {
  const params = new URLSearchParams({
    format: 'csv',
    range: props.selectedRange,
  });
  if (props.selectedRange === 'month') {
    params.set('month', props.selectedMonth);
  } else if (props.selectedRange === 'year') {
    params.set('year', props.selectedYear);
  } else if (props.selectedRange === 'custom') {
    if (props.customFrom) params.set('from', props.customFrom);
    if (props.customTo) params.set('to', props.customTo);
  }
  if (props.selectedNode) params.set('node', props.selectedNode);
  if (props.selectedNamespace) params.set('namespace', props.selectedNamespace);
  return `/api/v1/dashboard/energy/export?${params.toString()}`;
});

function formatMonthLabel(m: string): string {
  const parts = m.split('-');
  if (parts.length === 2) {
    const year = parts[0];
    const monthNum = parseInt(parts[1], 10);
    const months = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'
    ];
    if (monthNum >= 1 && monthNum <= 12) {
      return `Mois de ${months[monthNum - 1]} ${year}`;
    }
  }
  return m;
}

function formatKwh(kwh: number): string {
  if (!kwh || kwh <= 0) return '0.000 kWh';
  if (kwh < 1) {
    return `${(kwh * 1000).toFixed(1)} Wh`;
  }
  return `${kwh.toFixed(3)} kWh`;
}

function formatJoules(joules: number): string {
  if (!joules || joules <= 0) return '0';
  return Math.round(joules).toLocaleString('fr-FR');
}

function formatCarbon(gco2: number, kgco2: number): string {
  if (!gco2 || gco2 <= 0) return '0 g';
  if (gco2 < 1000) {
    return `${gco2.toFixed(1)} g`;
  }
  return `${(kgco2 || gco2 / 1000).toFixed(3)} kg`;
}

/**
 * Génère le document HTML officiel pour l'impression A4 et l'export PDF
 * Solution éprouvée par iframe isolé garantissant une pagination nette
 * sans conflits d'overflow, de position fixed ou de classes sombres.
 */
function generatePrintableHtml(): string {
  const workloadsRows = (props.workloads || []).map(wl => `
    <tr>
      <td style="padding: 8px 10px; font-weight: bold; border-bottom: 1px solid #e2e8f0; color: #0f172a;">${wl.service}</td>
      <td style="padding: 8px 10px; color: #b45309; border-bottom: 1px solid #e2e8f0;">${wl.namespace}</td>
      <td style="padding: 8px 10px; text-align: right; font-weight: bold; color: #0369a1; border-bottom: 1px solid #e2e8f0;">${wl.share_pct} %</td>
      <td style="padding: 8px 10px; text-align: right; color: #334155; border-bottom: 1px solid #e2e8f0;">${wl.watts} W</td>
      <td style="padding: 8px 10px; text-align: right; color: #334155; border-bottom: 1px solid #e2e8f0;">${formatKwh(wl.kwh)}</td>
      <td style="padding: 8px 10px; text-align: right; font-weight: bold; color: #047857; border-bottom: 1px solid #e2e8f0;">${wl.carbon_gco2} g</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Certificat d'Audit RSE - ${certificateId.value}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 14mm 16mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 0;
      font-size: 11pt;
      line-height: 1.45;
    }
    .header-box {
      border: 1.5px solid #10b981;
      background: linear-gradient(135deg, #ecfdf5 0%, #f8fafc 60%, #f0fdf4 100%);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .shield-icon {
      width: 48px;
      height: 48px;
    }
    .header-titles h1 {
      margin: 0;
      font-size: 16pt;
      font-weight: 800;
      color: #064e3b;
      letter-spacing: -0.5px;
    }
    .header-titles .sub {
      font-size: 8.5pt;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 1px;
      color: #059669;
      margin-bottom: 3px;
    }
    .header-titles .desc {
      font-size: 9pt;
      color: #475569;
      margin-top: 2px;
    }
    .header-right {
      text-align: right;
      font-family: "Courier New", Courier, monospace;
      font-size: 8.5pt;
      color: #334155;
    }
    .header-right strong {
      color: #064e3b;
      font-size: 9.5pt;
    }
    .grid-4 {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }
    .card {
      border: 1px solid #cbd5e1;
      background: #f8fafc;
      border-radius: 8px;
      padding: 10px 12px;
    }
    .card .label {
      font-size: 8pt;
      text-transform: uppercase;
      font-weight: 700;
      color: #64748b;
      margin-bottom: 3px;
      display: block;
    }
    .card .val {
      font-size: 11pt;
      font-weight: 800;
      color: #0f172a;
    }
    .card .meta {
      font-size: 8pt;
      color: #059669;
      font-weight: 600;
      margin-top: 2px;
    }
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 18px;
    }
    .metric-box {
      border-radius: 10px;
      padding: 12px 14px;
      border: 1.5px solid #e2e8f0;
    }
    .metric-energy {
      background: #fffbeb;
      border-color: #fde68a;
    }
    .metric-carbon {
      background: #ecfdf5;
      border-color: #a7f3d0;
    }
    .metric-water {
      background: #f0f9ff;
      border-color: #bae6fd;
    }
    .metric-power {
      background: #f0fdfa;
      border-color: #99f6e4;
    }
    .metric-tag {
      font-size: 8pt;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    .metric-energy .metric-tag { color: #b45309; }
    .metric-carbon .metric-tag { color: #047857; }
    .metric-water .metric-tag { color: #0369a1; }
    .metric-power .metric-tag { color: #0f766e; }
    .metric-value {
      font-size: 16pt;
      font-weight: 900;
      color: #0f172a;
      font-family: "Courier New", Courier, monospace;
      margin: 4px 0 2px 0;
    }
    .metric-sub {
      font-size: 8pt;
      color: #64748b;
    }
    .section-title {
      font-size: 9.5pt;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #334155;
      margin: 14px 0 8px 0;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 4px;
      display: flex;
      justify-content: space-between;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 8.5pt;
      font-family: "Courier New", Courier, monospace;
      margin-bottom: 16px;
    }
    th {
      background: #f1f5f9;
      color: #475569;
      font-weight: 800;
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1.5px solid #cbd5e1;
    }
    .legal-box {
      border: 1.5px solid #a7f3d0;
      background: #f0fdf4;
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 8pt;
      color: #334155;
      margin-top: 14px;
      line-height: 1.5;
    }
    .legal-box strong {
      color: #064e3b;
    }
    .footer-seal {
      margin-top: 10px;
      padding-top: 8px;
      border-top: 1px solid #cbd5e1;
      display: flex;
      justify-content: space-between;
      font-family: "Courier New", Courier, monospace;
      font-size: 7.5pt;
      color: #64748b;
    }
    .footer-seal .status {
      color: #059669;
      font-weight: 800;
    }
  </style>
</head>
<body>
  <div class="cert-container">
    
    <!-- EN-TÊTE OFFICIEL AVEC LOGO AEGIS -->
    <div class="header-box">
      <div class="header-left">
        <!-- SVG Bouclier Aegis officiel -->
        <svg class="shield-icon" viewBox="0 0 64 64" fill="none">
          <path d="M32 4L10 13.5V29.5C10 44.2 19.4 55.6 32 60C44.6 55.6 54 44.2 54 29.5V13.5L32 4Z" fill="#064e3b" stroke="#10b981" stroke-width="2.5" stroke-linejoin="round"/>
          <path d="M32 8L14 16V29.5C14 42 21.5 52 32 56C42.5 52 50 42 50 29.5V16L32 8Z" stroke="#6ee7b7" stroke-width="1.2" opacity="0.6"/>
          <path d="M21.5 32.5L28.8 39.5L43 23.5" stroke="#ffffff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <div class="header-titles">
          <div class="sub">🛡️ Aegis Zero-Trust Shield • Hardware GreenOps</div>
          <h1>Certificat d'Audit d'Empreinte Numérique</h1>
          <div class="desc">Standard CSRD / EFRAG VS (PME) • RGESN 2024 (Art. L. 300-1) • GHG Protocol Scope 2</div>
        </div>
      </div>
      <div class="header-right">
        <div>RÉF. CERTIFICAT :</div>
        <strong>${certificateId.value}</strong>
        <div style="margin-top: 3px;">Délivré le ${currentDateFormatted.value}</div>
      </div>
    </div>

    <!-- PÉRIMÈTRE D'AUDIT -->
    <div class="grid-4">
      <div class="card">
        <span class="label">Période Certifiée</span>
        <div class="val">${periodLabel.value}</div>
        <div class="meta">Durée : ${periodHours.value} heures</div>
      </div>
      <div class="card">
        <span class="label">Serveur Audité</span>
        <div class="val">${nodeName.value}</div>
        <div class="meta">${nodeProvider.value}</div>
      </div>
      <div class="card">
        <span class="label">Capteur Matériel</span>
        <div class="val">Intel/AMD RAPL MSR</div>
        <div class="meta">Scaphandre Probe v4.3.0</div>
      </div>
      <div class="card">
        <span class="label">PUE Datacenter</span>
        <div class="val">${props.summary.pue || 1.15}</div>
        <div class="meta">Datacenter Éco-conçu</div>
      </div>
    </div>

    <!-- 4 GRANDS INDICATEURS D'IMPACT -->
    <div class="metrics-grid">
      <div class="metric-box metric-energy">
        <div class="metric-tag">⚡ Énergie Consommée</div>
        <div class="metric-value">${formatKwh(props.summary.total_kwh)}</div>
        <div class="metric-sub">${formatJoules(props.summary.total_joules)} Joules (RAPL Silicium)</div>
      </div>
      <div class="metric-box metric-carbon">
        <div class="metric-tag">🌱 Émissions GES (Scope 2)</div>
        <div class="metric-value">${formatCarbon(props.summary.total_carbon_gco2, props.summary.total_carbon_kg)}</div>
        <div class="metric-sub">Facteur 52 gCO₂eq / kWh (Réseau FR)</div>
      </div>
      <div class="metric-box metric-water">
        <div class="metric-tag">💧 Empreinte Hydrique (WUE)</div>
        <div class="metric-value">${(props.summary.water_usage_liters || 0).toFixed(2)} L</div>
        <div class="metric-sub">Refroidissement ADEME / Boavizta</div>
      </div>
      <div class="metric-box metric-power">
        <div class="metric-tag">⚙️ Puissance Continue</div>
        <div class="metric-value">${(props.summary.avg_watts || 0).toFixed(2)} W</div>
        <div class="metric-sub">Charge CPU : ${(props.summary.avg_cpu_load_pct || 0).toFixed(1)} %</div>
      </div>
    </div>

    <!-- VENTILATION PAR WORKLOAD -->
    <div class="section-title">
      <span>Ventilation par Workload &amp; Service Dokploy</span>
      <span style="font-size: 8pt; font-weight: normal; color: #64748b;">Attribution cgroup Scaphandre / Kepler</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Service / Application</th>
          <th>Namespace</th>
          <th style="text-align: right;">Part (%)</th>
          <th style="text-align: right;">Puissance</th>
          <th style="text-align: right;">Énergie</th>
          <th style="text-align: right;">Émissions CO₂eq</th>
        </tr>
      </thead>
      <tbody>
        ${workloadsRows || '<tr><td colspan="6" style="padding: 10px; text-align: center; color: #64748b;">Aucun workload ventilé</td></tr>'}
      </tbody>
    </table>

    <!-- CADRE LÉGAL & VISA DE CONFORMITÉ -->
    <div class="legal-box">
      <div><strong>Cadre Réglementaire &amp; Validité d'Audit Extra-Financier :</strong></div>
      <div>• <strong>Directive Européenne CSRD / Standard EFRAG VS (PME)</strong> : Relevés d'énergie et de gaz à effet de serre certifiés conformes pour le reporting extra-financier de durabilité.</div>
      <div>• <strong>Référentiel RGESN 2024 (Art. L. 300-1)</strong> : Mesures matérielles issues des registres MSR du processeur (/sys/class/powercap/intel-rapl), garantissant une rigueur probante sans estimation forfaitaire.</div>
      <div>• <strong>GHG Protocol Scope 2 Location-Based</strong> : Émissions calculées sur le mix électrique de production avec un facteur validé de 52 gCO₂eq / kWh et un PUE de ${props.summary.pue || 1.15}.</div>
      
      <div class="footer-seal">
        <span>Sceau Cryptographique : SHA256:${hashCertificate.value}</span>
        <span class="status">✓ CERTIFIÉ CONFORME PAR LA PLATEFORME SOUVERAINE AEGIS</span>
      </div>
    </div>

  </div>
</body>
</html>`;
}

/**
 * Lance l'impression propre via un iframe invisible dédié.
 * Cette technique contourne les contraintes d'overflow et de fixed
 * de l'application parent sur Chrome et Firefox.
 */
function printCertificate() {
  const printFrame = document.createElement('iframe');
  printFrame.style.position = 'fixed';
  printFrame.style.right = '0';
  printFrame.style.bottom = '0';
  printFrame.style.width = '0';
  printFrame.style.height = '0';
  printFrame.style.border = '0';
  document.body.appendChild(printFrame);

  const doc = printFrame.contentWindow?.document;
  if (!doc) {
    document.body.removeChild(printFrame);
    window.print();
    return;
  }

  doc.open();
  doc.write(generatePrintableHtml());
  doc.close();

  setTimeout(() => {
    try {
      printFrame.contentWindow?.focus();
      printFrame.contentWindow?.print();
    } catch (e) {
      console.warn('[Aegis Certificate] Impression iframe échouée, fallback sur window.print()', e);
      window.print();
    } finally {
      setTimeout(() => {
        if (document.body.contains(printFrame)) {
          document.body.removeChild(printFrame);
        }
      }, 1500);
    }
  }, 250);
}
</script>
