<!--
SPDX-FileCopyrightText: The OpenArtifact Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

<template>
  <div class="mb-3 space-y-2 text-sm">
    <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted" role="status" data-testid="oci-scan-state">
      <span>{{ t(statusLabels[state.status]) }}</span>
      <span v-if="scannedAt">{{ tp('artifact.security.lastScanned', { when: formatDateTime(scannedAt) }) }}</span>
      <span v-if="state.database_updated_at">{{ tp('artifact.security.ociDatabase', { when: formatDateTime(state.database_updated_at) }) }}</span>
      <AppButton v-if="state.status === 'failed'" size="sm" variant="secondary" :loading="retrying" @click="emit('retry')">
        {{ t('ui.state.retry') }}
      </AppButton>
    </div>
    <p v-if="state.status === 'failed'" class="text-warning">{{ state.error || t('artifact.security.scanFailed') }}</p>
    <template v-if="state.changes">
      <details v-for="kind in changeKinds" :key="kind" class="group text-muted">
        <summary class="w-fit cursor-pointer font-medium text-foreground">
          {{ tp(changeLabels[kind], { count: formatNumber(state.changes[kind].length) }) }}
        </summary>
        <ul v-if="state.changes[kind].length" class="mt-1 max-h-56 space-y-1 overflow-y-auto pl-4 text-xs">
          <li v-for="finding in state.changes[kind]" :key="JSON.stringify([finding.id, finding.package])" class="break-words font-mono">
            {{ finding.id }} · {{ finding.package }} · {{ finding.severity }}
          </li>
        </ul>
      </details>
    </template>
  </div>
</template>

<script setup lang="ts">
import AppButton from '../AppButton.vue'
import type { OciScanState } from '../../api/security'
import { t, tp } from '../../i18n'
import { formatDateTime } from '../../lib/datetime'
import { formatNumber } from '../../lib/intl'

defineProps<{ state: OciScanState; scannedAt?: string | null; retrying: boolean }>()
const emit = defineEmits<{ retry: [] }>()

const statusLabels = {
  waiting_for_sbom: 'artifact.security.ociWaiting',
  queued: 'artifact.security.ociQueued',
  scanning: 'security.vuln.status.scanning',
  completed: 'security.vuln.status.completed',
  failed: 'security.vuln.status.failed',
} as const

const changeKinds = ['added', 'removed'] as const
const changeLabels = { added: 'artifact.security.ociAdded', removed: 'artifact.security.ociRemoved' } as const
</script>
