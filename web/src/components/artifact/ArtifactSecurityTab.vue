<!--
SPDX-FileCopyrightText: The OpenArtifact Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<!--
  Everyone with read access sees what the scans counted. Maintainers and admins also
  see the findings and can record VEX decisions: the findings name vulnerabilities,
  which the server withholds from plain readers.
-->
<template>
  <div class="space-y-8">
    <section aria-labelledby="artifact-sec-summary">
      <h2 id="artifact-sec-summary" class="mb-3 text-base font-semibold text-foreground">{{ t('artifact.security.summary') }}</h2>
      <template v-if="summary">
        <p v-if="level === 'unscanned'" class="max-w-2xl text-sm text-muted" data-testid="sec-unscanned">
          <span class="font-medium text-foreground">{{ t('artifact.security.unscanned') }}</span>
          {{ t('artifact.security.unscannedHint') }}
        </p>
        <template v-else>
          <p class="mb-3 text-sm text-muted" data-testid="sec-scanned">
            <template v-if="level === 'clean'">{{ t('artifact.security.clean') }} </template>
            {{ tp('artifact.security.lastScanned', { when: summary.scanned_at ? formatDateTime(summary.scanned_at) : '–' }) }}
          </p>
          <dl class="grid max-w-3xl grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
            <div v-for="s in SEVERITIES" :key="s">
              <dt class="text-xs text-muted">{{ t(`ui.severity.${s}`) }}</dt>
              <dd class="mt-0.5"><SeverityBadge :severity="s" :count="summary.vuln[s]" /></dd>
            </div>
          </dl>
          <dl class="mt-4 flex flex-wrap gap-x-8 gap-y-3 text-sm">
            <div>
              <dt class="text-xs text-muted">{{ t('artifact.security.license') }}</dt>
              <dd class="mt-0.5 tabular-nums" data-testid="sec-license">
                <router-link v-if="summary.license.violations > 0 && ctx.caps.value.maintain" :to="scanLink('license')" class="text-primary hover:underline">{{ tpn('artifact.security.violations', summary.license.violations) }}</router-link>
                <template v-else>{{ tpn('artifact.security.violations', summary.license.violations) }}</template>
              </dd>
            </div>
            <div>
              <dt class="text-xs text-muted">{{ t('artifact.security.secrets') }}</dt>
              <dd class="mt-0.5 tabular-nums" data-testid="sec-secret">
                <router-link v-if="summary.secret.count > 0 && ctx.caps.value.maintain" :to="scanLink('secret')" class="text-primary hover:underline">{{ tp('artifact.security.secretCount', { count: summary.secret.count }) }}</router-link>
                <template v-else>{{ tp('artifact.security.secretCount', { count: summary.secret.count }) }}</template>
              </dd>
            </div>
            <div v-if="summary.ai.quarantine_recommended + summary.ai.review_required > 0">
              <dt class="text-xs text-muted">{{ t('artifact.security.ai') }}</dt>
              <dd class="mt-0.5 tabular-nums">{{ tp('artifact.security.aiCount', { quarantine: summary.ai.quarantine_recommended, review: summary.ai.review_required }) }}</dd>
            </div>
            <div>
              <dt class="text-xs text-muted">{{ t('artifact.security.quarantine') }}</dt>
              <dd class="mt-0.5" data-testid="sec-quarantine">{{ summary.quarantined ? t('artifact.security.quarantined') : t('artifact.security.notQuarantined') }}</dd>
            </div>
          </dl>
        </template>
      </template>
      <p v-else class="text-sm text-muted">{{ t('common.loading') }}</p>
    </section>

    <section aria-labelledby="artifact-sec-findings">
      <h2 id="artifact-sec-findings" class="mb-3 text-base font-semibold text-foreground">{{ t('artifact.security.findings') }}</h2>
      <p v-if="!ctx.caps.value.admin" class="max-w-2xl text-sm text-muted" data-testid="sec-restricted">
        {{ t('artifact.security.restricted') }}
        <router-link v-if="ctx.caps.value.maintain" :to="inboxLink" class="text-primary hover:underline" data-testid="sec-inbox-link">{{ t('artifact.security.openInbox') }}</router-link>
      </p>
      <StateBlock v-else-if="error" variant="error" :title="t('artifact.security.loadFailed')" :hint="error">
        <template #action><AppButton variant="secondary" @click="load()">{{ t('ui.state.retry') }}</AppButton></template>
      </StateBlock>
      <p v-else-if="loading" class="text-sm text-muted">{{ t('common.loading') }}</p>
      <p v-else-if="rows.length === 0" class="max-w-2xl text-sm text-muted" data-testid="sec-no-scans">{{ t('artifact.security.noScans') }}</p>
      <div v-else class="space-y-6">
        <div v-for="row in rows" :key="row.key">
          <h3 v-if="row.state || rows.length > 1 || row.scan?.platform" class="mb-2 break-all font-mono text-xs text-muted">
            {{ row.state?.platform || row.scan?.platform || row.state?.digest || row.scan?.package_name }} · {{ row.scan?.scanner ?? 'trivy' }}
          </h3>
          <ArtifactOCIScanState
            v-if="row.state"
            :state="row.state"
            :scanned-at="row.scan?.scanned_at"
            :retrying="retrying === row.state.digest"
            @retry="retry(row.state.digest)"
          />
          <template v-if="row.scan">
            <p v-if="!row.state && (row.scan.scan_status === 'failed' || row.scan.scan_status === 'partial')" role="status" class="mb-2 text-sm text-warning">
              {{ row.scan.scan_error || t('artifact.security.scanFailed') }}
            </p>
            <VulnScanFindingsTable :scan="row.scan" :vex-by-vuln="vexByScan[row.scan.artifact_id] ?? new Map()" @decide="decide(row.scan, $event)" />
          </template>
        </div>
      </div>
    </section>

    <VexDecisionDialog
      v-if="deciding"
      :open="true"
      :repo="ctx.repoName.value"
      :artifact-id="deciding.scan.artifact_id"
      :artifact-label="`${ctx.pkgName.value}@${ctx.entry.value?.version ?? ''}`"
      :vuln-id="deciding.vulnId"
      :existing="vexByScan[deciding.scan.artifact_id]?.get(deciding.vulnId) ?? null"
      @close="deciding = null"
      @saved="afterDecision"
      @deleted="afterDecision"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useIntervalFn } from '@vueuse/core'
import AppButton from '../AppButton.vue'
import StateBlock from '../ui/StateBlock.vue'
import ArtifactOCIScanState from './ArtifactOCIScanState.vue'
import SeverityBadge from '../ui/SeverityBadge.vue'
import VexDecisionDialog from '../VexDecisionDialog.vue'
import VulnScanFindingsTable from '../VulnScanFindingsTable.vue'
import { getVulnScan, listOCIScans, listVulnScans, retryOCIScan, type OciScanState, type VulnScan } from '../../api/security'
import { listVexStatements, type VexRecord } from '../../api/vex'
import { useArtifactContext } from '../../composables/useArtifact'
import { securityLevel } from '../../lib/artifactSecurity'
import { formatDateTime } from '../../lib/datetime'
import { vexByVulnId } from '../../lib/vex'
import { t, tp, tpn } from '../../i18n'
import { useToastStore } from '../../stores/toast'

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const

const ctx = useArtifactContext()
const summary = computed(() => ctx.summary.value)
const level = computed(() => securityLevel(summary.value))

function scanLink(type: 'license' | 'secret') {
  return { path: '/security', query: { type, repo: ctx.repoName.value } }
}

const inboxLink = computed(() => ({ path: '/security', query: { repo: ctx.repoName.value, q: ctx.pkgName.value } }))

const scans = ref<VulnScan[]>([])
const ociScans = ref<OciScanState[]>([])
const retrying = ref('')
const toasts = useToastStore()
const tag = computed(() => {
  const entry = ctx.entry.value
  if (!entry || ctx.format.value !== 'docker' || ctx.repository.value?.repo_type !== 'hosted') return undefined
  return { package_name: ctx.pkgName.value, version: entry.version }
})
const rows = computed(() => {
  const autoIds = new Set(ociScans.value.map((state) => state.report_id))
  const byID = new Map(scans.value.map((scan) => [scan.id, scan]))
  return [
    ...ociScans.value.map((state) => ({ key: state.digest, state, scan: state.report_id ? byID.get(state.report_id) : undefined })),
    ...scans.value.filter((scan) => !autoIds.has(scan.id)).map((scan) => ({ key: scan.id, scan, state: undefined })),
  ]
})
const vexByScan = ref<Record<string, Map<string, VexRecord>>>({})
const loading = ref(false)
const error = ref('')
const deciding = ref<{ scan: VulnScan; vulnId: string } | null>(null)

let generation = 0
async function load(quiet = false): Promise<void> {
  const mine = ++generation
  if (!quiet) {
    scans.value = []
    ociScans.value = []
    vexByScan.value = {}
  }
  error.value = ''
  const entry = ctx.entry.value
  if (!ctx.caps.value.admin || !entry) return
  loading.value = !quiet
  const repo = ctx.repoName.value
  const selectedTag = tag.value
  try {
    const [listed, states] = await Promise.all([
      listVulnScans(repo, selectedTag),
      selectedTag ? listOCIScans(repo, selectedTag) : [],
    ])
    const fileIDs = new Set(entry.files.map((f) => f.id))
    const ids = new Set(listed.filter((s) => selectedTag || fileIDs.has(s.artifact_id)).map((s) => s.id))
    for (const state of states) {
      if (state.report_id) ids.add(state.report_id)
    }
    const full = await Promise.all(Array.from(ids, (id) => getVulnScan(repo, id)))
    const artifacts = [...new Set(full.map((scan) => scan.artifact_id))]
    const vex = await Promise.all(artifacts.map((id) => listVexStatements(repo, id)))
    if (mine !== generation) return
    scans.value = full
    ociScans.value = states
    vexByScan.value = Object.fromEntries(artifacts.map((id, i) => [id, vexByVulnId(vex[i] ?? [])]))
  } catch (err) {
    if (mine === generation) error.value = err instanceof Error ? err.message : String(err)
  } finally {
    if (mine === generation) loading.value = false
  }
}

let refreshing = false
async function refreshOCI(): Promise<void> {
  const selectedTag = tag.value
  if (!selectedTag || refreshing) return
  refreshing = true
  const mine = generation
  try {
    const states = await listOCIScans(ctx.repoName.value, selectedTag)
    if (mine !== generation) return
    const current = new Map(ociScans.value.map((state) => [state.digest, state]))
    if (states.some((state) => {
      const previous = current.get(state.digest)
      return state.report_id && (state.report_id !== previous?.report_id ||
        state.database_updated_at !== previous.database_updated_at ||
        (state.status === 'completed' && previous.status !== 'completed'))
    })) {
      await load(true)
    } else {
      ociScans.value = states
    }
  } catch (err) {
    if (mine === generation) error.value = err instanceof Error ? err.message : String(err)
  } finally {
    refreshing = false
  }
}

const running = computed(() => ociScans.value.some(({ status }) => status !== 'completed' && status !== 'failed'))
const { pause, resume } = useIntervalFn(() => void refreshOCI(), 5000, { immediate: false })
watch(running, (active) => active ? resume() : pause())

async function retry(digest: string): Promise<void> {
  retrying.value = digest
  try {
    await retryOCIScan(ctx.repoName.value, digest)
    await refreshOCI()
  } catch (err) {
    toasts.error(t('artifact.security.scanFailed'), err instanceof Error ? err.message : String(err))
  } finally {
    retrying.value = ''
  }
}

function decide(scan: VulnScan, vulnId: string): void {
  deciding.value = { scan, vulnId }
}

async function afterDecision(): Promise<void> {
  deciding.value = null
  await load()
}

watch(() => [ctx.repoName.value, ctx.pkgName.value, ctx.entry.value?.version, ctx.repository.value, ctx.caps.value.admin,
  ctx.summary.value?.scanned_at], () => void load(), { immediate: true })
</script>
