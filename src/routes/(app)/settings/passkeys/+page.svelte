<script lang="ts">
	import { enhance, deserialize } from '$app/forms';
	import { invalidateAll } from '$app/navigation';
	import { startRegistration } from '@simplewebauthn/browser';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/forms/TextField.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';
	import Stamp from '$lib/components/marks/Stamp.svelte';
	import { Copy, Download } from 'lucide-svelte';
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();

	type AddStage = 'idle' | 'registering' | 'added';
	let addStage = $state<AddStage>('idle');
	let addError = $state('');

	async function runAddPasskey(options: unknown) {
		try {
			const attestation = await startRegistration({
				optionsJSON: options as Parameters<typeof startRegistration>[0]['optionsJSON']
			});
			const formData = new FormData();
			formData.append('attestation', JSON.stringify(attestation));
			const res = await fetch('/settings/passkeys?/completeAdd', {
				method: 'POST',
				headers: { 'x-sveltekit-action': 'true' },
				body: formData
			});
			const result = deserialize(await res.text());
			if (result.type === 'success') {
				addStage = 'added';
				await invalidateAll();
			} else if (result.type === 'failure' && result.data) {
				const d = result.data as { error?: string };
				addError = d.error ?? 'failed to add passkey';
				addStage = 'idle';
			} else {
				addError = 'failed to add passkey';
				addStage = 'idle';
			}
		} catch (e) {
			addError = e instanceof Error ? e.message : 'passkey registration failed';
			addStage = 'idle';
		}
	}

	let editingId = $state<string | null>(null);
	let editingName = $state('');

	function startRename(id: string, currentName: string) {
		editingId = id;
		editingName = currentName;
	}

	function cancelRename() {
		editingId = null;
		editingName = '';
	}

	type CodesStage = 'idle' | 'confirm' | 'showing';
	let codesStage = $state<CodesStage>('idle');
	let recoveryCodes = $state<string[]>([]);
	let codesSaved = $state(false);

	$effect(() => {
		const f = form as { recoveryCodes?: string[] } | null;
		if (f?.recoveryCodes && f.recoveryCodes.length > 0) {
			recoveryCodes = f.recoveryCodes;
			codesStage = 'showing';
		}
	});

	function copyRecoveryCodes() {
		navigator.clipboard.writeText(recoveryCodes.join('\n'));
	}

	function downloadRecoveryCodes() {
		const blob = new Blob([recoveryCodes.join('\n')], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'finance-sim-recovery-codes.txt';
		a.click();
		URL.revokeObjectURL(url);
	}

	function relativeTime(unixSec: number): string {
		if (!unixSec) return 'never';
		const now = Math.floor(Date.now() / 1000);
		const diff = now - unixSec;
		if (diff < 60) return 'just now';
		if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
		if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
		if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
		return new Date(unixSec * 1000).toISOString().slice(0, 10);
	}

	let revokeError = $derived((form as { error?: string } | null)?.error ?? '');
</script>

<SectionHead
	eyebrow="VI · Settings"
	title="Passkeys."
	meta={`${data.passkeys.length} on file`}
/>

{#if data.forceSetup}
	<div class="warn" role="alert">
		<em>You signed in with a recovery code.</em> Add a new passkey now to keep your account accessible.
	</div>
{/if}

<section class="sec">
	<h2 class="sub">Devices on file</h2>

	{#if revokeError && revokeError !== 'display name must be 1-40 chars' && revokeError !== 'device name must be 1-40 chars'}
		<FormError message={revokeError} />
	{/if}

	<table class="pk">
		<thead>
			<tr>
				<th>Device</th>
				<th>Last used</th>
				<th>Sync</th>
				<th></th>
			</tr>
		</thead>
		<tbody>
			{#if data.passkeys.length === 0}
				<tr>
					<td colspan="4" class="empty"><em>No devices on file.</em></td>
				</tr>
			{:else}
				{#each data.passkeys as pk (pk.id)}
					<tr>
						<td>
							{#if editingId === pk.id}
								<form
									method="POST"
									action="?/rename"
									use:enhance={() => async ({ result }) => {
										if (result.type === 'success') {
											editingId = null;
											await invalidateAll();
										}
									}}
									class="rename"
								>
									<input type="hidden" name="passkeyId" value={pk.id} />
									<TextField name="deviceName" label="" bind:value={editingName} />
									<Button type="submit" variant="primary">Save</Button>
									<Button type="button" variant="quiet" onclick={cancelRename}>Cancel</Button>
								</form>
							{:else}
								<span class="dev">{pk.deviceName}</span>
								{#if pk.suggestion && pk.suggestion !== pk.deviceName}
									<span class="hint">({pk.suggestion})</span>
								{/if}
							{/if}
						</td>
						<td class="muted">{relativeTime(pk.lastUsedAt)}</td>
						<td>
							{#if pk.backupState === 1}
								<span class="tag tag--sync" title="synced across devices">Synced</span>
							{:else}
								<span class="tag tag--local" title="this device only">Local</span>
							{/if}
						</td>
						<td>
							<div class="actions">
								{#if editingId !== pk.id}
									<Button
										type="button"
										variant="quiet"
										onclick={() => startRename(pk.id, pk.deviceName)}
									>
										Rename
									</Button>
								{/if}
								<form
									method="POST"
									action="?/revoke"
									use:enhance={({ cancel }) => {
										if (
											!confirm(
												`Revoke "${pk.deviceName}"? You'll need another passkey or recovery code to sign in.`
											)
										) {
											cancel();
											return;
										}
										return async ({ result }) => {
											if (result.type === 'success') await invalidateAll();
										};
									}}
								>
									<input type="hidden" name="passkeyId" value={pk.id} />
									<Button type="submit" variant="danger">Revoke</Button>
								</form>
							</div>
						</td>
					</tr>
				{/each}
			{/if}
		</tbody>
	</table>
</section>

<section class="sec">
	<h2 class="sub">Register another device</h2>

	{#if addStage === 'registering'}
		<p class="prose"><em>Confirm with your device…</em></p>
	{:else if addStage === 'added'}
		<p class="prose ok"><em>Device registered.</em></p>
		<Button type="button" variant="quiet" onclick={() => (addStage = 'idle')}>
			Register another
		</Button>
	{:else}
		<FormError message={addError} />
		<form
			method="POST"
			action="?/beginAdd"
			use:enhance={() => {
				addError = '';
				return async ({ result }) => {
					if (result.type === 'failure') {
						const d = result.data as { error?: string } | undefined;
						addError = d?.error ?? 'failed to begin passkey registration';
					} else if (result.type === 'success' && result.data) {
						const d = result.data as { stage: string; options: unknown };
						if (d.stage === 'options') {
							addStage = 'registering';
							await runAddPasskey(d.options);
						}
					}
				};
			}}
		>
			<Button type="submit" variant="primary">Register this device</Button>
		</form>
	{/if}
</section>

<section class="sec">
	<h2 class="sub">Recovery codes</h2>

	{#if codesStage === 'showing'}
		<p class="prose">
			A fresh set. Each works once.
		</p>
		<pre class="codes">{recoveryCodes.join('\n')}</pre>
		<div class="row">
			<Button variant="quiet" onclick={copyRecoveryCodes}>
				<Copy class="ico" /> Copy
			</Button>
			<Button variant="quiet" onclick={downloadRecoveryCodes}>
				<Download class="ico" /> Download
			</Button>
		</div>
		<label class="check">
			<input type="checkbox" bind:checked={codesSaved} />
			<span>I've saved my recovery codes</span>
		</label>
		<Button
			variant="primary"
			disabled={!codesSaved}
			onclick={() => {
				codesStage = 'idle';
				codesSaved = false;
			}}
		>
			Done
		</Button>
	{:else if codesStage === 'confirm'}
		<p class="prose">
			The current eight codes will lapse. A fresh set is issued.
		</p>
		<div class="row">
			<form
				method="POST"
				action="?/regenerateCodes"
				use:enhance={() => async ({ result, update }) => {
					if (result.type === 'failure') codesStage = 'idle';
					// Propagate the action's return ({ recoveryCodes }) into the page's
					// form prop so the $effect can flip codesStage to 'showing'.
					await update();
				}}
			>
				<Button type="submit" variant="danger">Yes, replace</Button>
			</form>
			<Button type="button" variant="quiet" onclick={() => (codesStage = 'idle')}>Cancel</Button>
		</div>
	{:else}
		<p class="prose">
			Replace all eight codes. The current set lapses at once.
		</p>
		<Button type="button" variant="quiet" onclick={() => (codesStage = 'confirm')}>
			Replace recovery codes
		</Button>
	{/if}
</section>

<style>
	.warn {
		background: var(--color-paper-receipt);
		border-left: 3px solid var(--color-stamp);
		padding: 12px 14px;
		margin: 16px 0;
		font-family: var(--font-body);
		font-size: 14px;
		color: var(--color-ink);
	}
	.sec { margin-top: 36px; }
	.sub {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 60, 'wght' 500;
		font-size: 22px;
		margin: 0 0 12px;
		letter-spacing: -0.01em;
	}
	.prose {
		font-family: var(--font-body);
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0 0 12px;
		max-width: 60ch;
	}
	.prose.ok { color: var(--color-gain); }

	.pk { width: 100%; border-collapse: collapse; font-family: var(--font-body); }
	.pk thead th {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 500;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		text-align: left;
		padding: 0 12px 10px 0;
		border-bottom: 1.5px solid var(--color-ink);
	}
	.pk tbody td {
		padding: 14px 12px 14px 0;
		border-bottom: 1px solid var(--color-rule-soft);
		font-size: 14px;
		vertical-align: middle;
	}
	.pk tbody tr:last-child td { border-bottom: 1px solid var(--color-ink); }
	.pk .empty {
		text-align: center;
		padding: 24px 0;
		color: var(--color-ink-3);
		font-style: italic;
	}
	.dev {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		font-size: 15px;
	}
	.hint {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 12px;
		color: var(--color-ink-3);
		margin-left: 4px;
	}
	.muted { color: var(--color-ink-3); font-family: var(--font-mono); font-size: 12px; }
	.tag {
		display: inline-block;
		font-family: var(--font-mono);
		font-size: 9.5px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		padding: 3px 8px;
		border: 1px solid var(--color-rule);
	}
	.tag--sync { color: var(--color-ink); border-color: var(--color-ink); }
	.tag--local { color: var(--color-ink-3); border-color: var(--color-rule); }


	.actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
	.rename {
		display: flex;
		gap: 8px;
		align-items: flex-end;
	}

	.codes {
		font-family: var(--font-mono);
		font-size: 13px;
		background: var(--color-paper-receipt);
		padding: 14px 18px;
		margin: 0 0 12px;
		line-height: 1.7;
		letter-spacing: 0.04em;
		max-width: 360px;
		box-shadow: 0 14px 28px -22px rgba(22, 17, 10, 0.18);
	}
	.row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
	:global(.row .ico) { width: 14px; height: 14px; margin-right: 4px; }
	.check {
		display: flex;
		gap: 8px;
		align-items: center;
		font-family: var(--font-body);
		font-size: 14px;
		color: var(--color-ink);
		margin: 12px 0;
	}
</style>
