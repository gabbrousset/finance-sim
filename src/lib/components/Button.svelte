<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';

	type Variant = 'primary' | 'quiet' | 'danger';
	type Props = HTMLButtonAttributes & {
		variant?: Variant;
		children: Snippet;
	};

	let {
		variant = 'primary',
		type = 'button',
		disabled = false,
		children,
		class: cls,
		...rest
	}: Props = $props();
</script>

<button {type} {disabled} class="btn btn--{variant} {cls ?? ''}" {...rest}>
	{@render children()}
</button>

<style>
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 24, 'wght' 600;
		text-transform: uppercase;
		letter-spacing: 0.18em;
		font-size: 12px;
		padding: 10px 18px;
		cursor: pointer;
		transition: opacity 0.15s, background-color 0.15s;
		border: 0;
		border-radius: 2px;
	}
	.btn:disabled { opacity: 0.5; cursor: not-allowed; }

	.btn--primary {
		background: var(--color-ink);
		color: var(--color-paper-receipt);
	}
	.btn--primary:hover:not(:disabled) { opacity: 0.88; }

	.btn--quiet {
		background: transparent;
		color: var(--color-ink);
		text-decoration: underline;
		text-underline-offset: 4px;
		text-decoration-thickness: 1px;
		letter-spacing: 0;
		text-transform: none;
		font-family: var(--font-body);
		font-style: italic;
		font-variation-settings: initial;
		padding: 4px 2px;
		font-size: 14px;
	}
	.btn--quiet:hover:not(:disabled) { color: var(--color-stamp); }

	.btn--danger {
		background: var(--color-ink);
		color: var(--color-paper-receipt);
		box-shadow: inset 0 0 0 1.5px var(--color-loss);
	}
</style>
