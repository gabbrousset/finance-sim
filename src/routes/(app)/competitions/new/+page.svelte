<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';

	let { form } = $props();

	let type: 'live' | 'historical' = $state('live');
	let name = $state('');
	let startDate = $state('');
	let endDate = $state('');
	let startingCash = $state('10000');

	// Repopulate from the form prop on validation failures so users don't
	// lose their typed input. Form prop changes after each submit.
	$effect(() => {
		if (form?.type === 'historical' || form?.type === 'live') {
			type = form.type;
		}
		if (form && 'name' in form && typeof form.name === 'string') {
			name = form.name;
		}
		if (form && 'startDate' in form && typeof form.startDate === 'string') {
			startDate = form.startDate;
		}
		if (form && 'endDate' in form && typeof form.endDate === 'string') {
			endDate = form.endDate;
		}
		if (form && 'startingCash' in form && typeof form.startingCash === 'string') {
			startingCash = form.startingCash;
		}
	});
</script>

<h1 class="text-2xl font-semibold">create competition</h1>

<form method="POST" use:enhance class="mt-6 flex max-w-md flex-col gap-4">
	<div>
		<div class="text-sm font-medium">type</div>
		<div class="mt-2 inline-flex rounded-md border border-zinc-200 dark:border-zinc-800">
			<label
				class="flex cursor-pointer items-center gap-2 px-4 py-2 text-sm {type === 'live'
					? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
					: ''}"
			>
				<input type="radio" name="type" value="live" bind:group={type} class="hidden" />
				live
			</label>
			<label
				class="flex cursor-pointer items-center gap-2 px-4 py-2 text-sm {type === 'historical'
					? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
					: ''}"
			>
				<input type="radio" name="type" value="historical" bind:group={type} class="hidden" />
				historical
			</label>
		</div>
		<p class="mt-1 text-xs text-zinc-500">
			{type === 'live'
				? 'trade live prices over a future window'
				: 'pick a past window; everyone builds a portfolio at the start price; resolve when ready'}
		</p>
	</div>

	<TextField name="name" label="name" bind:value={name} required />
	<TextField name="startDate" label="start date" type="date" bind:value={startDate} required />
	<TextField name="endDate" label="end date" type="date" bind:value={endDate} required />
	<TextField
		name="startingCash"
		label="starting cash ($)"
		type="number"
		bind:value={startingCash}
		required
	/>
	<FormError message={form?.error ?? ''} />
	<Button type="submit" variant="primary">create</Button>
</form>
