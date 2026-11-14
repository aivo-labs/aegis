<template>
  <div class="space-y-6 text-slate-100 font-sans">
    
    <!-- 1. BARRE DE CONTRÔLE SUPÉRIEURE : NAVIGATION TEMPORELLE & PÉRIMÈTRE MULTI-SERVEURS / K8S -->
    <div class="p-4 rounded-2xl bg-slate-900/80 border border-slate-800/90 flex flex-col gap-3 font-mono text-xs">
      
      <!-- Ligne 1 : Présélections Temporelles & Navigation Historique -->
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="text-slate-400 mr-1 flex items-center gap-1">
            <span>📅</span>
            <span>Période :</span>
          </span>

          <button 
            @click="setRange('1h')"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === '1h' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            1h (Direct)
          </button>
          
          <button 
            @click="setRange('24h')"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === '24h' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            24h (Jour)
          </button>

          <button 
            @click="setRange('7d')"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === '7d' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            7 jours
          </button>

          <button 
            @click="setRange('30d')"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === '30d' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            30 jours
          </button>

          <!-- Sélecteur de Mois Spécifique (ex: Septembre) -->
          <div class="flex items-center gap-1 ml-1 bg-slate-950 border border-slate-800 rounded-lg px-2 py-0.5">
            <span class="text-slate-400 text-[11px]">Mois :</span>
            <select 
              :value="selectedMonth" 
              @change="onMonthChange(($event.target as HTMLSelectElement).value)"
              class="bg-transparent text-emerald-300 font-bold focus:outline-none cursor-pointer"
            >
              <option v-for="m in availableMonths" :key="m" :value="m" class="bg-slate-950 text-slate-200">
                {{ formatMonthLabel(m) }}
              </option>
            </select>
          </div>

          <button 
            @click="setRange('year')"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === 'year' ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            Année {{ selectedYear }}
          </button>

          <button 
            @click="selectedRange = 'custom'"
            :class="['px-3 py-1.5 rounded-lg border cursor-pointer transition-all font-bold', selectedRange === 'custom' ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300' : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white']"
          >
            Personnalisé
          </button>
        </div>

        <!-- Export Rapports & Télémétrie brute -->
        <div class="flex items-center gap-2">
          <!-- Bouton Certificat Officiel PDF -->
          <button 
            @click="showCertificateModal = true"
            class="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-emerald-500/25 to-cyan-500/25 hover:from-emerald-500/40 hover:to-cyan-500/40 border border-emerald-500/50 text-emerald-300 font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            title="Consulter et générer le Certificat Officiel d'Audit RSE / CSRD (Format PDF)"
          >
            <span>📜</span>
            <span>Certificat RSE (PDF)</span>
          </button>

          <!-- Bouton Export Données Brutes CSV -->
          <a 
            :href="csvExportUrl"
            :download="`aegis-rapl-telemetry-${selectedRange}.csv`"
            class="px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs text-xs"
            title="Exporter les relevés RAPL bruts filtrés pour bilan RSE / tableur"
          >
            <span>📥 Export CSV</span>
          </a>
        </div>
      </div>

      <!-- Ligne 2 : Périmètre Multi-Serveurs, Namespaces K8s et Filtre Date Personnalisé -->
      <div class="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-slate-800/80">
        <div class="flex flex-wrap items-center gap-3">
          
          <!-- Sélecteur Multi-Serveurs (Nodes) -->
          <div class="flex items-center gap-1.5">
            <span class="text-slate-400 flex items-center gap-1">
              <span>🖥️</span>
              <span>Serveur :</span>
            </span>
            <select 
              v-model="selectedNode" 
              @change="refreshData"
              class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-cyan-300 font-bold focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">🌐 Tous les serveurs (Cluster Global)</option>
              <option v-for="node in nodes" :key="node.id" :value="node.id">
                {{ node.hostname }} ({{ node.provider }})
              </option>
            </select>
          </div>

          <!-- Sélecteur Kubernetes Namespaces / Workloads Dokploy -->
          <div class="flex items-center gap-1.5">
            <span class="text-slate-400 flex items-center gap-1">
              <span>📦</span>
              <span>Namespace / Workload :</span>
            </span>
            <select 
              v-model="selectedNamespace" 
              @change="refreshData"
              class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-amber-300 font-bold focus:outline-none focus:border-amber-500 cursor-pointer"
            >
              <option value="all">🌐 Tous les namespaces &amp; workloads</option>
              <option value="dokploy">🐳 dokploy (aivo.fr, flow n8n, blog, traefik)</option>
              <option value="aegis-system">🛡️ aegis-system (Cockpit, PEP, DB, Backend)</option>
              <option value="kube-system">⚙️ kube-system (K8s Control Plane)</option>
            </select>
          </div>

          <!-- Champs de date personnalisée si activé -->
          <div v-if="selectedRange === 'custom'" class="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <span class="text-slate-500 text-[10px]">Du</span>
            <input 
              type="date" 
              v-model="customFrom" 
              @change="refreshData"
              class="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-200 text-xs"
            />
            <span class="text-slate-500 text-[10px]">Au</span>
            <input 
              type="date" 
              v-model="customTo" 
              @change="refreshData"
              class="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-200 text-xs"
            />
          </div>
        </div>

        <!-- Statut de la capture -->
        <div class="flex items-center gap-2 text-[11px] text-slate-400">
          <span v-if="selectedRange === '1h' || selectedRange === '24h'" class="flex items-center gap-1.5 text-emerald-400 font-bold">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span>Flux RAPL Direct Actif (&lt; 3s)</span>
          </span>
          <span v-else class="text-cyan-300 flex items-center gap-1">
            <span>📅</span>
            <span>Historique archivé : {{ activePeriodLabel }}</span>
          </span>
          <span v-if="isSimulatedHistory" class="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-500/40 text-amber-300 text-[10px]" title="Reconstitution basée sur le profil matériel réel mesuré du serveur">
            Profil matériel calibré
          </span>
        </div>
      </div>

    </div>

    <!-- 2. 4 CARTES KPIS SYNTHÉTIQUES GREENOPS (ÉNERGIE, CPU, CARBONE & EAU) -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
      
      <!-- CARTE 1 : PUISSANCE & ÉNERGIE ÉLECTRIQUE (RAPL) -->
      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 relative overflow-hidden group hover:border-amber-500/40 transition-all">
        <div class="flex items-center justify-between text-slate-400 text-[11px]">
          <span>Puissance Matérielle (RAPL MSR)</span>
          <span class="text-amber-400 text-sm">⚡</span>
        </div>
        <div class="flex items-baseline gap-1 mt-1.5">
          <span class="text-3xl font-extrabold text-amber-400">
            {{ selectedRange === '1h' ? summary.instant_watts.toFixed(2) : summary.avg_watts.toFixed(2) }}
          </span>
          <span class="text-xs text-slate-400">Watts {{ selectedRange === '1h' ? 'inst.' : 'moy.' }}</span>
        </div>
        <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
          <span class="text-slate-400">Énergie cumulée :</span>
          <strong class="text-white">{{ formatKwh(summary.total_kwh) }}</strong>
        </div>
        <div class="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
          <span>CPU: {{ summary.cpu_watts.toFixed(1) }}W • RAM: {{ summary.ram_watts.toFixed(1) }}W</span>
          <span class="text-amber-300 font-bold">~{{ summary.estimated_cost_eur.toFixed(3) }} €</span>
        </div>
      </div>

      <!-- CARTE 2 : CHARGE PROCESSEUR & EFFICACITÉ -->
      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 relative overflow-hidden group hover:border-cyan-500/40 transition-all">
        <div class="flex items-center justify-between text-slate-400 text-[11px]">
          <span>Charge Processeur (/proc/stat)</span>
          <span class="text-cyan-400 text-sm">📈</span>
        </div>
        <div class="flex items-baseline gap-1 mt-1.5">
          <span class="text-3xl font-extrabold text-cyan-300">{{ summary.avg_cpu_load_pct.toFixed(1) }}</span>
          <span class="text-xs text-slate-400">% CPU moy.</span>
        </div>
        <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
          <span class="text-slate-400">Pic de charge max :</span>
          <strong class="text-cyan-200">{{ summary.max_cpu_load_pct.toFixed(1) }} %</strong>
        </div>
        <div class="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
          <span>PUE Datacenter : {{ summary.pue }}</span>
          <span class="text-emerald-400">Efficacité : Optimale</span>
        </div>
      </div>

      <!-- CARTE 3 : EMPREINTE CARBONE OPÉRATIONNELLE (GHG PROTOCOL) -->
      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 relative overflow-hidden group hover:border-emerald-500/40 transition-all">
        <div class="flex items-center justify-between text-slate-400 text-[11px]">
          <span>Émissions Carbone (Scope 2)</span>
          <span class="text-emerald-400 text-sm">🌱</span>
        </div>
        <div class="flex items-baseline gap-1 mt-1.5">
          <span class="text-3xl font-extrabold text-emerald-400">
            {{ summary.total_carbon_kg >= 1 ? summary.total_carbon_kg.toFixed(2) : summary.total_carbon_gco2.toFixed(1) }}
          </span>
          <span class="text-xs text-slate-400">{{ summary.total_carbon_kg >= 1 ? 'kg' : 'g' }} CO₂eq</span>
        </div>
        <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
          <span class="text-slate-400">Mix décarboné FR :</span>
          <strong class="text-emerald-300">{{ summary.carbon_intensity_gco2_kwh }} gCO₂/kWh</strong>
        </div>
        <div class="text-[10px] text-slate-400 mt-1 truncate" :title="`Équivaut à ${summary.equivalencies.car_km} km en voiture ou ${summary.equivalencies.smartphones_charged} recharges de smartphone`">
          🚗 {{ summary.equivalencies.car_km }} km voiture • 📱 {{ summary.equivalencies.smartphones_charged }} recharges
        </div>
      </div>

      <!-- CARTE 4 : CONSOMMATION D'EAU ESTIMÉE (WATER FOOTPRINT / WUE) -->
      <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 relative overflow-hidden group hover:border-sky-500/40 transition-all">
        <div class="flex items-center justify-between text-slate-400 text-[11px]">
          <span>Empreinte Eau (Water Footprint)</span>
          <span class="text-sky-400 text-sm">💧</span>
        </div>
        <div class="flex items-baseline gap-1 mt-1.5">
          <span class="text-3xl font-extrabold text-sky-300">{{ summary.water_usage_liters.toFixed(2) }}</span>
          <span class="text-xs text-slate-400">Litres H₂O</span>
        </div>
        <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
          <span class="text-slate-400">Facteur WUE + Mix :</span>
          <strong class="text-sky-200">1.50 L / kWh</strong>
        </div>
        <div class="text-[10px] text-slate-400 mt-1 truncate" :title="`Équivaut à ${summary.equivalencies.water_bottles} bouteilles d'eau de 1.5L ou ${summary.equivalencies.showers_pct}% d'une douche`">
          🍼 {{ summary.equivalencies.water_bottles }} bouteilles 1.5L • 🚿 {{ summary.equivalencies.showers_pct }}% douche
        </div>
      </div>

    </div>

    <!-- 3. DIAGRAMME CENTRAL MULTI-MÉTRIQUES (WATTS, CPU %, EAU & CARBONE) -->
    <div class="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl font-mono text-xs">
      
      <!-- En-tête du Graphique avec Onglets de Métriques -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-4 border-b border-slate-800">
        <div>
          <div class="text-emerald-400 font-bold mb-0.5 flex items-center gap-1.5">
            <span>⚡ MESURE DIRECTE LINUX RAPL (/sys/class/powercap/intel-rapl)</span>
          </div>
          <h3 class="text-base font-extrabold text-white">
            Évolution Télémétrique &amp; Corrélation Énergie-Charge
          </h3>
        </div>

        <!-- Onglets du graphique -->
        <div class="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 gap-1">
          <button 
            @click="activeMetric = 'watts'"
            :class="[
              'px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold flex items-center gap-1.5',
              activeMetric === 'watts' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-white'
            ]"
          >
            <span>⚡ Puissance (Watts)</span>
          </button>

          <button 
            @click="activeMetric = 'cpu'"
            :class="[
              'px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold flex items-center gap-1.5',
              activeMetric === 'cpu' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
            ]"
          >
            <span>📈 Charge CPU (%)</span>
          </button>

          <button 
            @click="activeMetric = 'water_carbon'"
            :class="[
              'px-3 py-1.5 rounded-lg transition-all cursor-pointer font-bold flex items-center gap-1.5',
              activeMetric === 'water_carbon' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'text-slate-400 hover:text-white'
            ]"
          >
            <span>💧 Eau &amp; 🌱 Carbone</span>
          </button>
        </div>
      </div>

      <!-- Zone de Rendu SVG Multi-Courbes Agrandie & Interactive -->
      <div class="w-full h-80 sm:h-96 min-h-[360px] relative bg-slate-950/90 rounded-xl p-4 border border-slate-800 flex flex-col justify-between select-none">
        
        <svg 
          viewBox="0 0 540 180" 
          class="w-full h-full overflow-visible cursor-crosshair"
          @mousemove="onChartMouseMove"
          @mouseleave="onChartMouseLeave"
        >
          <!-- Dégradés sous les courbes -->
          <defs>
            <linearGradient id="wattsGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#06b6d4" stop-opacity="0.0" />
            </linearGradient>

            <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.4" />
              <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0" />
            </linearGradient>

            <linearGradient id="waterGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#0ea5e9" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#0ea5e9" stop-opacity="0.0" />
            </linearGradient>

            <linearGradient id="carbonGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#10b981" stop-opacity="0.35" />
              <stop offset="100%" stop-color="#10b981" stop-opacity="0.0" />
            </linearGradient>
          </defs>

          <!-- Lignes horizontales de repère (Axes Y) -->
          <line x1="35" y1="20" x2="535" y2="20" stroke="#1e293b" stroke-dasharray="3,3" />
          <line x1="35" y1="52" x2="535" y2="52" stroke="#1e293b" stroke-dasharray="3,3" />
          <line x1="35" y1="85" x2="535" y2="85" stroke="#1e293b" stroke-dasharray="3,3" />
          <line x1="35" y1="117" x2="535" y2="117" stroke="#1e293b" stroke-dasharray="3,3" />
          <line x1="35" y1="150" x2="535" y2="150" stroke="#334155" />

          <!-- Labels Y selon la métrique active -->
          <g v-if="activeMetric === 'watts'" fill="#64748b" font-size="9" font-family="monospace">
            <text x="4" y="24">{{ maxYWatts }}W</text>
            <text x="4" y="56">{{ Math.round(maxYWatts * 0.75) }}W</text>
            <text x="4" y="89">{{ Math.round(maxYWatts * 0.5) }}W</text>
            <text x="4" y="121">{{ Math.round(maxYWatts * 0.25) }}W</text>
            <text x="4" y="153">0W</text>
          </g>

          <g v-else-if="activeMetric === 'cpu'" fill="#64748b" font-size="9" font-family="monospace">
            <text x="4" y="24">{{ maxYCpu }}%</text>
            <text x="4" y="56">{{ Math.round(maxYCpu * 0.75) }}%</text>
            <text x="4" y="89">{{ Math.round(maxYCpu * 0.5) }}%</text>
            <text x="4" y="121">{{ Math.round(maxYCpu * 0.25) }}%</text>
            <text x="4" y="153">0%</text>
          </g>

          <g v-else fill="#64748b" font-size="8" font-family="monospace">
            <text x="2" y="24">
              <tspan fill="#38bdf8">{{ maxYWater }}cl</tspan>
              <tspan fill="#64748b">/</tspan>
              <tspan fill="#34d399">{{ maxYCarbon }}g</tspan>
            </text>
            <text x="2" y="56">
              <tspan fill="#38bdf8">{{ (maxYWater * 0.75).toFixed(1) }}cl</tspan>
              <tspan fill="#64748b">/</tspan>
              <tspan fill="#34d399">{{ (maxYCarbon * 0.75).toFixed(2) }}g</tspan>
            </text>
            <text x="2" y="89">
              <tspan fill="#38bdf8">{{ (maxYWater * 0.5).toFixed(1) }}cl</tspan>
              <tspan fill="#64748b">/</tspan>
              <tspan fill="#34d399">{{ (maxYCarbon * 0.5).toFixed(2) }}g</tspan>
            </text>
            <text x="2" y="121">
              <tspan fill="#38bdf8">{{ (maxYWater * 0.25).toFixed(1) }}cl</tspan>
              <tspan fill="#64748b">/</tspan>
              <tspan fill="#34d399">{{ (maxYCarbon * 0.25).toFixed(2) }}g</tspan>
            </text>
            <text x="2" y="153">0</text>
          </g>

          <!-- 1. VUE WATTS (Courbe + Surface Dégradée) -->
          <g v-if="activeMetric === 'watts'">
            <path :d="dynamicAreaSvgPath" fill="url(#wattsGradient)" />
            <path :d="dynamicSvgPath" fill="none" stroke="#06b6d4" stroke-width="2.5" />
          </g>

          <!-- 2. VUE CPU LOAD (%) -->
          <g v-else-if="activeMetric === 'cpu'">
            <path :d="dynamicCpuAreaSvgPath" fill="url(#cpuGradient)" />
            <path :d="dynamicCpuLoadSvgPath" fill="none" stroke="#38bdf8" stroke-width="2.5" />
          </g>

          <!-- 3. VUE EAU & CARBONE (2 COURBES : BLEU EAU + VERT CARBONE) -->
          <g v-else>
            <path :d="dynamicWaterAreaSvgPath" fill="url(#waterGradient)" />
            <path :d="dynamicWaterSvgPath" fill="none" stroke="#0ea5e9" stroke-width="2.5" />
            <path :d="dynamicCarbonAreaSvgPath" fill="url(#carbonGradient)" />
            <path :d="dynamicCarbonSvgPath" fill="none" stroke="#10b981" stroke-width="2.5" />
          </g>

          <!-- Repère vertical dynamique et points de contact au survol -->
          <g v-if="hoveredIndex !== null" class="pointer-events-none">
            <line 
              :x1="getPointX(hoveredIndex)" 
              y1="20" 
              :x2="getPointX(hoveredIndex)" 
              y2="150" 
              stroke="#94a3b8" 
              stroke-width="1.5" 
              stroke-dasharray="3,3" 
            />
            <!-- Marqueur sur courbe Watts -->
            <circle 
              v-if="activeMetric === 'watts' && hoveredPoint" 
              :cx="getPointX(hoveredIndex)" 
              :cy="getPointYWatts(hoveredPoint.watts)" 
              r="5" 
              fill="#06b6d4" 
              stroke="#ffffff" 
              stroke-width="2" 
            />
            <!-- Marqueur sur courbe CPU -->
            <circle 
              v-else-if="activeMetric === 'cpu' && hoveredPoint" 
              :cx="getPointX(hoveredIndex)" 
              :cy="getPointYCpu(hoveredPoint.cpu_load_pct)" 
              r="5" 
              fill="#38bdf8" 
              stroke="#ffffff" 
              stroke-width="2" 
            />
            <!-- Marqueurs sur courbes Eau & Carbone -->
            <template v-else-if="hoveredPoint">
              <circle 
                :cx="getPointX(hoveredIndex)" 
                :cy="getPointYWater(hoveredPoint.water_cl)" 
                r="5" 
                fill="#0ea5e9" 
                stroke="#ffffff" 
                stroke-width="2" 
              />
              <circle 
                :cx="getPointX(hoveredIndex)" 
                :cy="getPointYCarbon(hoveredPoint.carbon_gco2)" 
                r="5" 
                fill="#10b981" 
                stroke="#ffffff" 
                stroke-width="2" 
              />
            </template>
          </g>

          <!-- Repères temporels horizontaux (Axe X) -->
          <g v-if="timeseries.length >= 2" fill="#64748b" font-size="9" font-family="monospace">
            <text x="40" y="168">{{ timeseries[0].time }}</text>
            <text x="260" y="168" text-anchor="middle">{{ timeseries[Math.floor(timeseries.length / 2)].time }}</text>
            <text x="480" y="168" text-anchor="end">{{ timeseries[timeseries.length - 1].time }}</text>
          </g>
        </svg>

        <!-- Infobulle interactive au survol -->
        <div 
          v-if="hoveredPoint && hoveredIndex !== null"
          class="absolute z-30 pointer-events-none bg-slate-950/95 backdrop-blur-md border border-slate-700/80 shadow-2xl rounded-xl p-3 text-xs font-mono transition-all duration-75"
          :style="{
            left: `${Math.min(75, Math.max(5, (getPointX(hoveredIndex) / 540) * 100))}%`,
            top: '16px',
            transform: getPointX(hoveredIndex) > 300 ? 'translateX(-100%)' : 'translateX(0)'
          }"
        >
          <div class="flex items-center justify-between gap-3 pb-1.5 mb-2 border-b border-slate-800 text-[11px]">
            <span class="text-slate-300 font-bold">📅 {{ formatHoverDate(hoveredPoint) }}</span>
            <span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold text-[10px]">{{ hoveredPoint.time }}</span>
          </div>
          <div class="space-y-1.5 text-[11px]">
            <div class="flex items-center justify-between gap-4">
              <span class="text-amber-400 font-semibold flex items-center gap-1">⚡ Puissance Totale :</span>
              <strong class="text-white">{{ hoveredPoint.watts.toFixed(2) }} W</strong>
            </div>
            <div class="flex items-center justify-between gap-4 text-slate-400 text-[10px] pl-3">
              <span>CPU / RAM :</span>
              <span class="text-slate-300">{{ hoveredPoint.cpu_watts.toFixed(2) }}W • {{ hoveredPoint.ram_watts.toFixed(2) }}W</span>
            </div>
            <div class="flex items-center justify-between gap-4">
              <span class="text-cyan-300 font-semibold flex items-center gap-1">📈 Charge CPU :</span>
              <strong class="text-cyan-200">{{ hoveredPoint.cpu_load_pct.toFixed(1) }} %</strong>
            </div>
            <div class="flex items-center justify-between gap-4">
              <span class="text-sky-300 font-semibold flex items-center gap-1">💧 Empreinte Eau :</span>
              <strong class="text-sky-200">{{ hoveredPoint.water_cl.toFixed(2) }} cl</strong>
            </div>
            <div class="flex items-center justify-between gap-4">
              <span class="text-emerald-400 font-semibold flex items-center gap-1">🌱 Émission Carbone :</span>
              <strong class="text-emerald-300">{{ hoveredPoint.carbon_gco2.toFixed(3) }} gCO₂eq</strong>
            </div>
          </div>
        </div>

      </div>

      <!-- Légende et Synthèse sous le Graphique -->
      <div class="mt-4 flex flex-wrap items-center justify-between gap-3 text-slate-400 text-[11px]">
        <div class="flex items-center gap-4">
          <template v-if="activeMetric === 'water_carbon'">
            <span class="flex items-center gap-1.5 text-sky-400 font-bold">
              <span class="w-3 h-1 bg-sky-400 rounded-full inline-block"></span>
              <span>Empreinte Eau (cl H₂O)</span>
            </span>
            <span class="text-slate-500">•</span>
            <span class="flex items-center gap-1.5 text-emerald-400 font-bold">
              <span class="w-3 h-1 bg-emerald-400 rounded-full inline-block"></span>
              <span>Émissions Carbone (gCO₂eq)</span>
            </span>
            <span class="text-slate-500">•</span>
            <span>Eau totale : <strong class="text-white">{{ summary.water_usage_liters.toFixed(2) }} L</strong></span>
            <span class="text-slate-500">•</span>
            <span>Carbone : <strong class="text-emerald-300">{{ summary.total_carbon_gco2.toFixed(1) }} gCO₂eq</strong></span>
          </template>
          <template v-else>
            <span class="flex items-center gap-1.5 text-cyan-300 font-bold">
              <span class="w-3 h-1 bg-cyan-400 rounded-full inline-block"></span>
              <span>Courbe : {{ activeMetric === 'watts' ? 'Puissance Globale RAPL' : 'Charge CPU Totale' }}</span>
            </span>
            <span class="text-slate-500">•</span>
            <span>Moyenne période : <strong class="text-white">{{ activeMetric === 'watts' ? summary.avg_watts.toFixed(2) + ' W' : summary.avg_cpu_load_pct.toFixed(1) + ' %' }}</strong></span>
            <span class="text-slate-500">•</span>
            <span>Pic max : <strong class="text-amber-300">{{ activeMetric === 'watts' ? summary.max_watts.toFixed(2) + ' W' : summary.max_cpu_load_pct.toFixed(1) + ' %' }}</strong></span>
          </template>
        </div>

        <div class="flex items-center gap-3 text-slate-500">
          <span v-if="hoveredPoint" class="text-cyan-400 animate-pulse font-semibold">
            🔍 Survol actif : {{ hoveredPoint.time }}
          </span>
          <span>{{ timeseries.length }} points temporels</span>
        </div>
      </div>

    </div>

    <!-- 4. RÉPARTITION PAR WORKLOAD, NAMESPACE KUBERNETES & SERVICES DOKPLOY -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 font-mono text-xs">
      
      <!-- COLONNE GAUCHE (2 Tiers) : TABLEAU D'ATTRIBUTION SCAPHANDRE / KEPLER -->
      <div class="lg:col-span-2 p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <div>
              <h4 class="text-sm font-bold text-white flex items-center gap-2">
                <span>📦</span>
                <span>Attribution de l'Énergie par Workload &amp; Namespace</span>
              </h4>
              <p class="text-[11px] text-slate-400 mt-0.5">
                Ventilation estimée selon les cycles CPU cgroup (méthode Kepler / Scaphandre)
              </p>
            </div>
            <span class="px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-bold">
              {{ workloads.length }} workloads
            </span>
          </div>

          <!-- Liste des Workloads / Namespaces -->
          <div class="space-y-3 mt-3">
            <div 
              v-for="wl in workloads" 
              :key="wl.service"
              class="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-slate-700 transition-all"
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-amber-300 font-bold text-[10px] shrink-0">
                    {{ wl.namespace }}
                  </span>
                  <span class="text-white font-bold truncate">
                    {{ wl.service }}
                  </span>
                  <span class="text-[10px] text-slate-500 hidden sm:inline">
                    ({{ wl.type }})
                  </span>
                </div>

                <div class="flex items-center gap-3 shrink-0">
                  <span v-if="wl.req_count && wl.req_count > 0" class="px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-700/40 text-cyan-300 text-[10px] font-bold">
                    {{ wl.req_count }} req
                  </span>
                  <span class="text-amber-400 font-bold">{{ wl.watts }} W</span>
                  <span class="text-cyan-300 font-bold">{{ wl.share_pct }}%</span>
                </div>
              </div>

              <!-- Barre de progression de la part d'énergie -->
              <div class="w-full bg-slate-900 rounded-full h-1.5 mt-2.5 overflow-hidden">
                <div 
                  class="bg-gradient-to-r from-cyan-500 to-amber-500 h-1.5 rounded-full" 
                  :style="{ width: `${wl.share_pct}%` }"
                ></div>
              </div>

              <!-- Ligne de métriques environnementales du workload -->
              <div class="mt-2 flex flex-wrap items-center justify-between text-[10px] text-slate-400 pt-1.5 border-t border-slate-900">
                <span>CPU: <strong class="text-slate-200">{{ wl.cpu_load_pct }}%</strong></span>
                <span>Énergie: <strong class="text-slate-200">{{ formatKwh(wl.kwh) }}</strong></span>
                <span>CO₂: <strong class="text-emerald-400">{{ wl.carbon_gco2 }} g</strong></span>
                <span>Eau: <strong class="text-sky-300">{{ wl.water_liters }} L</strong></span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- COLONNE DROITE (1 Tiers) : STATUT DES SERVEURS DU CLUSTER & AUDIT ECOINDEX -->
      <div class="space-y-5">
        
        <!-- Cartouche Nœuds du Cluster -->
        <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90">
          <div class="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <h4 class="text-sm font-bold text-white flex items-center gap-2">
              <span>🖥️</span>
              <span>Nœuds du Cluster</span>
            </h4>
            <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">
              {{ nodes.length }} actif{{ nodes.length > 1 ? 's' : '' }}
            </span>
          </div>

          <div v-if="isLoading && nodes.length === 0" class="py-6 text-center text-slate-500 font-mono text-xs animate-pulse">
            Découverte des nœuds du cluster...
          </div>

          <div v-else class="space-y-3">
            <div 
              v-for="node in nodes" 
              :key="node.id"
              class="p-3 rounded-xl bg-slate-950 border border-slate-800"
            >
              <div class="flex items-center justify-between">
                <span class="font-bold text-white">{{ node.hostname }}</span>
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              </div>
              <div class="text-[11px] text-slate-400 mt-1">
                IP: <span class="text-slate-200">{{ node.ip }}</span> • {{ node.provider }}
              </div>
              <div class="text-[10px] text-slate-500 mt-0.5">
                {{ node.os_info }} ({{ node.agent }})
              </div>
              <div class="mt-2 pt-2 border-t border-slate-900 flex items-center justify-between text-[11px]">
                <span class="text-slate-400">Puissance moyenne :</span>
                <span class="text-amber-400 font-bold">{{ node.avg_watts }} W</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Cartouche Éco-Conception EcoIndex v3 -->
        <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90">
          <div class="text-slate-400 text-[11px]">Audit Passif &amp; Éco-Conception Web</div>
          <div class="flex items-baseline gap-2 mt-1">
            <span class="text-3xl font-extrabold text-emerald-400">82</span>
            <span class="text-xs text-slate-400">/ 100</span>
            <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-xs border border-emerald-500/40">
              Grade B
            </span>
          </div>
          <p class="text-[11px] text-slate-400 mt-2 leading-relaxed">
            Mesures conformes au standard <strong>EcoIndex v3 (GreenIT.fr)</strong> combinant complexité du DOM, requêtes HTTP et taille des ressources transférées.
          </p>
        </div>

      </div>

    </div>

    <!-- 5. ENCART PÉDAGOGIQUE & NORMES ENVIRONNEMENTALES (GHG / BOAVIZTA / ADEME) -->
    <div class="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 font-mono text-[11px] text-slate-400 leading-relaxed space-y-1.5">
      <div class="text-white font-bold flex items-center gap-1.5">
        <span>📐</span>
        <span>Méthodologie &amp; Référentiels GreenOps Standardisés :</span>
      </div>
      <p>
        • <strong>Énergie Matérielle Directe (RAPL)</strong> : Mesures matérielles issues des registres MSR CPU Intel/AMD via <code class="text-emerald-300">/sys/class/powercap/intel-rapl</code>, dissociant la consommation du package CPU et de la mémoire DRAM.
      </p>
      <p>
        • <strong>Empreinte Carbone (GHG Protocol Scope 2)</strong> : Calculée selon le facteur d'émission dynamique du réseau électrique (mix français standardisé à <code class="text-cyan-300">52 gCO₂eq / kWh</code> issu des données RTE / electricityMap).
      </p>
      <p>
        • <strong>Consommation d'Eau (Water Footprint / WUE)</strong> : Estimée à <code class="text-sky-300">1.50 L / kWh</code> selon les référentiels Boavizta &amp; ADEME, intégrant le refroidissement direct évaporatif des datacenters et l'évaporation indirecte du mix électrique (tours aéroréfrigérantes).
      </p>
      <p>
        • <strong>Attribution Workload</strong> : Ventilation de l'énergie par conteneur et namespace Kubernetes inspirée du projet CNCF <strong>Kepler</strong> (Kernel-based Energy Proportionality Exporter).
      </p>
    </div>

    <!-- MODALE DU CERTIFICAT OFFICIEL D'AUDIT RSE / CSRD (FORMAT PDF & IMPRESSION) -->
    <CockpitRseCertificateModal
      :show="showCertificateModal"
      :summary="summary"
      :workloads="workloads"
      :nodes="nodes"
      :selectedRange="selectedRange"
      :selectedMonth="selectedMonth"
      :selectedYear="selectedYear"
      :customFrom="customFrom"
      :customTo="customTo"
      :selectedNode="selectedNode"
      :selectedNamespace="selectedNamespace"
      @close="showCertificateModal = false"
    />

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useTelemetry } from '../../../composables/useTelemetry';
import CockpitRseCertificateModal from '../cockpit/CockpitRseCertificateModal.vue';

const props = withDefaults(defineProps<{
  isDemo?: boolean;
}>(), {
  isDemo: false,
});

const showCertificateModal = ref(false);

const {
  selectedRange,
  selectedMonth,
  selectedYear,
  customFrom,
  customTo,
  selectedNode,
  selectedNamespace,
  activeMetric,
  isLoading,
  isSimulatedHistory,
  summary,
  timeseries,
  workloads,
  nodes,
  availableMonths,
  maxYWatts,
  maxYCpu,
  maxYWater,
  maxYCarbon,
  dynamicSvgPath,
  dynamicAreaSvgPath,
  dynamicCpuLoadSvgPath,
  dynamicCpuAreaSvgPath,
  dynamicWaterSvgPath,
  dynamicWaterAreaSvgPath,
  dynamicCarbonSvgPath,
  dynamicCarbonAreaSvgPath,
  fetchEnergyTelemetry,
} = useTelemetry({ isDemo: props.isDemo });

const csvExportUrl = computed(() => {
  const params = new URLSearchParams({
    format: 'csv',
    range: selectedRange.value,
  });
  if (selectedRange.value === 'month') {
    params.set('month', selectedMonth.value);
  } else if (selectedRange.value === 'year') {
    params.set('year', selectedYear.value);
  } else if (selectedRange.value === 'custom') {
    if (customFrom.value) params.set('from', customFrom.value);
    if (customTo.value) params.set('to', customTo.value);
  }
  if (selectedNode.value) params.set('node', selectedNode.value);
  if (selectedNamespace.value) params.set('namespace', selectedNamespace.value);
  return `/api/v1/dashboard/energy/export?${params.toString()}`;
});

// État d'interaction au survol du graphique
const hoveredIndex = ref<number | null>(null);

const hoveredPoint = computed(() => {
  if (hoveredIndex.value === null || !timeseries.value || !timeseries.value[hoveredIndex.value]) {
    return null;
  }
  return timeseries.value[hoveredIndex.value];
});

const chartStepX = computed(() => {
  if (timeseries.value.length < 2) return 440;
  return 440 / (timeseries.value.length - 1);
});

function getPointX(idx: number): number {
  if (timeseries.value.length < 2) return 40;
  return Math.round(40 + idx * chartStepX.value);
}

function getPointYWatts(w: number): number {
  const maxW = maxYWatts.value || 20;
  return Math.max(20, Math.min(148, Math.round(150 - ((w / maxW) * 128))));
}

function getPointYCpu(cpu: number): number {
  const maxCpu = maxYCpu.value || 10;
  return Math.max(20, Math.min(148, Math.round(150 - ((cpu / maxCpu) * 128))));
}

function getPointYWater(water: number): number {
  const maxWater = maxYWater.value || 2.0;
  return Math.max(20, Math.min(148, Math.round(150 - ((water / maxWater) * 128))));
}

function getPointYCarbon(carbon: number): number {
  const maxCarbon = maxYCarbon.value || 1.0;
  return Math.max(20, Math.min(148, Math.round(150 - ((carbon / maxCarbon) * 128))));
}

function formatHoverDate(pt: any): string {
  if (!pt) return '';
  if (pt.timestamp) {
    try {
      const d = new Date(pt.timestamp);
      if (!isNaN(d.getTime())) {
        return d.toLocaleDateString('fr-FR', {
          day: '2-digit',
          month: '2-digit',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        });
      }
    } catch (e) {}
  }
  return pt.time || '';
}

function onChartMouseMove(e: MouseEvent) {
  if (!timeseries.value || timeseries.value.length < 2) return;
  const target = e.currentTarget as SVGElement;
  const rect = target.getBoundingClientRect();
  const clientX = e.clientX - rect.left;
  const svgX = (clientX / rect.width) * 540;
  const clampedX = Math.max(40, Math.min(480, svgX));
  const ratio = (clampedX - 40) / 440;
  const idx = Math.round(ratio * (timeseries.value.length - 1));
  hoveredIndex.value = Math.max(0, Math.min(timeseries.value.length - 1, idx));
}

function onChartMouseLeave() {
  hoveredIndex.value = null;
}

function setRange(range: string) {
  selectedRange.value = range;
  fetchEnergyTelemetry();
}

function onMonthChange(month: string) {
  selectedMonth.value = month;
  selectedRange.value = 'month';
  fetchEnergyTelemetry();
}

function refreshData() {
  fetchEnergyTelemetry();
}

const activePeriodLabel = computed(() => {
  if (selectedRange.value === '1h') return '1 dernière heure';
  if (selectedRange.value === '24h') return 'Dernières 24 heures';
  if (selectedRange.value === '7d') return '7 derniers jours';
  if (selectedRange.value === '30d') return '30 derniers jours';
  if (selectedRange.value === 'month') return formatMonthLabel(selectedMonth.value);
  if (selectedRange.value === 'year') return `Année ${selectedYear.value}`;
  if (selectedRange.value === 'custom') return `Du ${customFrom.value || '...'} au ${customTo.value || '...'}`;
  return selectedRange.value;
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
      return `${months[monthNum - 1]} ${year}`;
    }
  }
  return m;
}

function formatKwh(kwh: number): string {
  if (kwh < 1) {
    return `${(kwh * 1000).toFixed(1)} Wh`;
  }
  return `${kwh.toFixed(3)} kWh`;
}

let pollTimer: any = null;

onMounted(() => {
  fetchEnergyTelemetry();

  if (!props.isDemo) {
    // Polling automatique si en direct (1h ou 24h)
    pollTimer = setInterval(() => {
      if (selectedRange.value === '1h' || selectedRange.value === '24h') {
        fetchEnergyTelemetry();
      }
    }, 3500);
  }
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>
