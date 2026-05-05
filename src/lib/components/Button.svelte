<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';

	type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
	type Size = 'sm' | 'md' | 'lg';

	type Props = HTMLButtonAttributes & {
		variant?: Variant;
		size?: Size;
		children: Snippet;
	};

	let {
		variant = 'primary',
		size = 'md',
		type = 'button',
		disabled = false,
		children,
		class: cls,
		...rest
	}: Props = $props();

	const base =
		'inline-flex items-center justify-center font-medium rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed';

	const variants: Record<Variant, string> = {
		primary:
			'bg-zinc-900 text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-100',
		secondary:
			'border border-zinc-300 hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-800',
		ghost: 'hover:bg-zinc-100 dark:hover:bg-zinc-800',
		danger: 'bg-red-600 text-white hover:bg-red-700'
	};

	const sizes: Record<Size, string> = {
		sm: 'h-8 px-3 text-sm',
		md: 'h-10 px-4 text-sm',
		lg: 'h-11 px-5'
	};

	const classes = $derived([base, variants[variant], sizes[size], cls].filter(Boolean).join(' '));
</script>

<button {type} {disabled} class={classes} {...rest}>
	{@render children()}
</button>
