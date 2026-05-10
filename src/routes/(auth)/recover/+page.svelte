<script lang="ts">
	import { enhance } from '$app/forms';
	import TextField from '$lib/components/forms/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import FormError from '$lib/components/forms/FormError.svelte';
	import type { PageProps } from './$types';

	let { form }: PageProps = $props();
</script>

<h1 class="auth-h">Recovery.</h1>
<p class="auth-deck"><em>Enter your username and a recovery code to regain access.</em></p>

<form method="POST" use:enhance class="auth-form">
	<TextField name="username" label="Username" required autocomplete="username" />
	<TextField name="code" label="Recovery code" required autocomplete="off" />
	<FormError message={form?.error ?? ''} />
	<Button type="submit" variant="primary">Recover account</Button>
</form>

<p class="auth-foot">
	<a href="/signin">Back to sign in</a>
</p>

<style>
	.auth-h {
		font-family: var(--font-display);
		font-variation-settings: 'opsz' 96, 'wght' 500;
		font-size: 32px;
		letter-spacing: -0.02em;
		line-height: 1;
		margin: 0 0 4px;
		color: var(--color-ink);
	}
	.auth-deck {
		font-family: var(--font-body);
		font-style: italic;
		font-size: 14px;
		color: var(--color-ink-2);
		margin: 0 0 24px;
	}
	.auth-form { display: flex; flex-direction: column; gap: 14px; }
	.auth-foot {
		margin-top: 18px;
		font-family: var(--font-body);
		font-size: 14px;
	}
	.auth-foot a {
		color: var(--color-ink-2);
		border-bottom: 1px dotted var(--color-rule);
		text-decoration: none;
	}
	.auth-foot a:hover { color: var(--color-ink); }
</style>
