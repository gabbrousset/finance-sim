<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	type Props = Omit<HTMLInputAttributes, 'value'> & {
		name: string;
		label: string;
		value?: string;
		error?: string;
		hint?: string;
	};

	let {
		name,
		label,
		value = $bindable(''),
		type = 'text',
		placeholder,
		error,
		hint,
		disabled,
		...rest
	}: Props = $props();
</script>

<div class="tf">
	<label for={name} class="tf__label">{label}</label>
	<div class="tf__row">
		<input
			id={name}
			{name}
			{type}
			{placeholder}
			{disabled}
			bind:value
			class="tf__input"
			class:tf__input--error={!!error}
			{...rest}
		/>
		{#if hint}<span class="tf__hint">{hint}</span>{/if}
	</div>
	{#if error}<p class="tf__error">{error}</p>{/if}
</div>

<style>
	.tf { display: flex; flex-direction: column; gap: 4px; }
	.tf__label {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.tf__row {
		display: flex;
		align-items: baseline;
		gap: 8px;
		border-bottom: 1.5px solid var(--color-ink);
		padding: 2px 0 4px;
	}
	.tf__row:focus-within { border-bottom-width: 2px; }
	.tf__input {
		flex: 1;
		background: transparent;
		border: 0;
		outline: 0;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 500;
		font-size: 20px;
		letter-spacing: -0.015em;
		color: var(--color-ink);
		padding: 0;
	}
	.tf__input--error { color: var(--color-loss); }
	.tf__input:disabled { opacity: 0.55; }
	.tf__hint {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 11px;
		color: var(--color-ink-3);
	}
	.tf__error {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-loss);
		margin: 2px 0 0;
	}
</style>
