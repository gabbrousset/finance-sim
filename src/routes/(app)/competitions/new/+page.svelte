<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import SectionHead from '$lib/components/marks/SectionHead.svelte';

	let { form } = $props();

	let type: 'live' | 'historical' = $state('live');
	let name = $state('');
	let startDate = $state('');
	let endDate = $state('');
	let startingCash = $state('10000');

	$effect(() => {
		if (form?.type === 'historical' || form?.type === 'live') type = form.type;
		if (form && 'name' in form && typeof form.name === 'string') name = form.name;
		if (form && 'startDate' in form && typeof form.startDate === 'string') startDate = form.startDate;
		if (form && 'endDate' in form && typeof form.endDate === 'string') endDate = form.endDate;
		if (form && 'startingCash' in form && typeof form.startingCash === 'string')
			startingCash = form.startingCash;
	});
</script>

<SectionHead eyebrow="V · Competitions" title="New competition." meta="Open to invitees" />

<form method="POST" use:enhance class="cn">
	<div class="seg">
		<div class="seg__lbl">Type</div>
		<div class="seg__row">
			<label class:on={type === 'live'}>
				<input type="radio" name="type" value="live" bind:group={type} />
				Live
			</label>
			<label class:on={type === 'historical'}>
				<input type="radio" name="type" value="historical" bind:group={type} />
				Historical
			</label>
		</div>
		<p class="seg__hint">
			{type === 'live'
				? 'Trade live prices over a future window.'
				: 'Pick a past window; everyone builds a portfolio at the start price; resolve when ready.'}
		</p>
	</div>

	<TextField name="name" label="Name" bind:value={name} required />
	<TextField name="startDate" label="Start date" type="date" bind:value={startDate} required />
	<TextField name="endDate" label="End date" type="date" bind:value={endDate} required />
	<TextField
		name="startingCash"
		label="Starting cash ($)"
		type="number"
		bind:value={startingCash}
		required
	/>
	<FormError message={form?.error ?? ''} />
	<Button type="submit" variant="primary">Create</Button>
</form>

<style>
	.cn {
		display: flex;
		flex-direction: column;
		gap: 18px;
		max-width: 460px;
	}
	.seg__lbl {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
		margin-bottom: 6px;
	}
	.seg__row {
		display: inline-flex;
		border: 1.5px solid var(--color-ink);
	}
	.seg__row label {
		padding: 6px 18px;
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		cursor: pointer;
		color: var(--color-ink);
	}
	.seg__row label.on {
		background: var(--color-ink);
		color: var(--color-paper-receipt);
	}
	.seg__row input { display: none; }
	.seg__hint {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 13px;
		color: var(--color-ink-2);
		margin: 8px 0 0;
	}
</style>
