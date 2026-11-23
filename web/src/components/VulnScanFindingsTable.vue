<!--
SPDX-FileCopyrightText: The OpenArtifact Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<template>
  <p v-if="!findings.length" class="text-sm text-muted">{{ t('security.vuln.noFindings') }}</p>
  <TableScroller v-else>
    <table class="w-full text-sm">
      <thead class="border-b border-border">
        <tr>
          <th scope="col" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.id') }}</th>
          <th scope="col" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.severity') }}</th>
          <th scope="col" data-drop-order="3" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.exploit') }}</th>
          <th scope="col" data-drop-order="2" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.cvss') }}</th>
          <th v-if="showPackage" scope="col" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.common.package') }}</th>
          <th scope="col" data-drop-order="4" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.fixedIn') }}</th>
          <th scope="col" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vuln.finding.summary') }}</th>
          <th scope="col" class="text-left py-2 pr-3 text-muted font-medium">{{ t('security.vex.eyebrow') }}</th>
          <th v-if="canDecide" scope="col" class="py-2 pl-3" :class="ACTIONS_HEAD"><span class="sr-only">{{ t('common.actions') }}</span></th>
        </tr>
      </thead>
      <tbody>
        <template v-for="f in findings" :key="JSON.stringify([f.id, f.package])">
          <tr class="group/row border-b border-border last:border-0 align-top" data-testid="finding-row">
            <td class="py-2 pr-3 font-mono text-xs whitespace-nowrap">
              <button type="button" class="text-left text-primary hover:underline" :aria-expanded="advisoryIsOpen(f.id, f.package)" @click="toggleAdvisory(f.id, f.package)">{{ f.id }}</button>
              <div v-if="f.cve && f.cve !== f.id" class="text-muted" data-testid="finding-cve">{{ f.cve }}</div>
            </td>
            <td class="py-2 pr-3 text-xs">{{ f.severity }}</td>
            <td class="py-2 pr-3" data-testid="finding-exploit">
              <div class="flex flex-wrap items-center gap-1">
                <KevBadge v-if="f.kev" :date-added="f.kev_date_added" :due-date="f.kev_due_date" :ransomware="f.kev_ransomware" />
                <EpssBadge v-if="f.epss !== null" :score="f.epss" :percentile="f.epss_percentile" :date="f.epss_date" :elevated="f.priority === 'epss'" />
                <span v-if="!f.kev && f.epss === null" class="text-xs text-muted">—</span>
              </div>
            </td>
            <td class="py-2 pr-3 text-xs font-mono">{{ f.cvss > 0 ? f.cvss : '—' }}</td>
            <td v-if="showPackage" class="py-2 pr-3 text-xs font-mono break-words">{{ f.package || '—' }}</td>
            <td class="py-2 pr-3 text-xs font-mono">{{ f.fixed_in || '—' }}</td>
            <td class="truncate py-2 pr-3 text-xs text-muted" :class="GROW_CELL" :title="f.summary">{{ f.summary }}</td>
            <td class="py-2 pr-3">
              <div v-if="vexByVuln.get(f.id)" class="flex flex-col items-start gap-1">
                <VexStatusBadge :status="vexByVuln.get(f.id)!.status" data-testid="finding-vex-status" />
                <VexSourceBadge :record="vexByVuln.get(f.id)!" />
              </div>
            </td>
            <td v-if="canDecide" class="py-2 pl-3" :class="ACTIONS_CELL">
              <RowActions :actions="decisionActions(f.id)" @action="emit('decide', f.id)" />
            </td>
          </tr>
          <tr v-if="advisory && advisoryIsOpen(f.id, f.package)" data-testid="finding-advisory" class="border-b border-border bg-surface-hover">
            <td :colspan="7 + Number(showPackage) + Number(canDecide)" class="p-4">
              <div class="max-w-3xl space-y-4 break-words text-sm text-foreground">
                <p v-if="advisory.description || advisory.summary" class="whitespace-pre-wrap">{{ advisory.description || advisory.summary }}</p>
                <dl class="grid grid-cols-2 gap-3 text-sm">
                  <div v-if="advisory.package"><dt class="text-muted">{{ t('security.common.package') }}</dt><dd class="font-mono">{{ advisory.package }}</dd></div>
                  <div><dt class="text-muted">{{ t('security.vuln.finding.severity') }}</dt><dd>{{ advisory.severity }}</dd></div>
                  <div><dt class="text-muted">{{ t('security.vuln.finding.fixedIn') }}</dt><dd class="font-mono">{{ advisory.fixed_in || '—' }}</dd></div>
                  <div><dt class="text-muted">{{ t('security.vuln.finding.cvss') }}</dt><dd>{{ advisory.cvss > 0 ? advisory.cvss : '—' }}</dd></div>
                  <div v-if="aliases.length" class="col-span-2"><dt class="text-muted">{{ t('security.vuln.finding.aliases') }}</dt><dd class="font-mono">{{ aliases.join(', ') }}</dd></div>
                </dl>
                <a v-if="advisoryURL" :href="advisoryURL" target="_blank" rel="noopener noreferrer" class="text-primary underline">
                  {{ t('security.vuln.finding.advisory') }}
                </a>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </TableScroller>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { CheckBadgeIcon } from '@heroicons/vue/20/solid'
import RowActions, { type RowAction } from './ui/RowActions.vue'
import TableScroller from './ui/TableScroller.vue'
import { ACTIONS_CELL, ACTIONS_HEAD, GROW_CELL } from './ui/tableStyles'
import VexSourceBadge from './VexSourceBadge.vue'
import VexStatusBadge from './VexStatusBadge.vue'
import EpssBadge from './security/EpssBadge.vue'
import KevBadge from './security/KevBadge.vue'
import { vulnFindings, type VulnScan } from '../api/security'
import type { VexRecord } from '../api/vex'
import { safeHttpUrl } from '../lib/artifactLinks'
import { sortVulns } from '../lib/exploitPriority'
import { t, tp } from '../i18n'

const props = withDefaults(defineProps<{
  scan: VulnScan
  /** The caller may record VEX decisions (administrators); otherwise the recorded status is shown only. */
  canDecide?: boolean
  /** Decisions of the open scan's artifact, by vulnerability id. */
  vexByVuln: Map<string, VexRecord>
}>(), { canDecide: true })

const emit = defineEmits<{ decide: [vulnId: string] }>()

function decisionActions(vulnId: string): RowAction[] {
  return [{ key: 'decide', label: tp('security.vuln.rowAction', { action: t('security.vex.decision'), name: vulnId }), icon: CheckBadgeIcon }]
}

/** Most urgent first: KEV, high EPSS, then severity and CVSS. */
const findings = computed(() => sortVulns(vulnFindings(props.scan)))
const advisory = ref<NonNullable<VulnScan['vulnerabilities']>[number] | null>(null)
const advisoryURL = computed(() => safeHttpUrl(advisory.value?.primary_url) ?? advisory.value?.references?.map(safeHttpUrl).find(Boolean))
const aliases = computed(() => {
  const finding = advisory.value
  if (!finding) return []
  return [...new Set([...(finding.aliases ?? []), finding.cve].filter((id) => id && id !== finding.id))]
})

function advisoryIsOpen(id: string, pkg?: string): boolean {
  return advisory.value?.id === id && (advisory.value.package ?? '') === (pkg ?? '')
}

function toggleAdvisory(id: string, pkg?: string): void {
  if (advisoryIsOpen(id, pkg)) {
    advisory.value = null
    return
  }
  advisory.value = props.scan.vulnerabilities?.find((finding) => finding.id === id && (finding.package ?? '') === (pkg ?? '')) ?? null
}

const showPackage = computed(() => findings.value.some((f) => f.package))
</script>
