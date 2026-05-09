import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import Stamp from './Stamp.svelte';

describe('Stamp', () => {
	it('renders the label', () => {
		render(Stamp, { props: { label: 'Filled' } });
		expect(screen.getByText('Filled')).toBeInTheDocument();
	});

	it('renders an optional sub-label', () => {
		render(Stamp, { props: { label: 'Final', sub: 'Champion: marie' } });
		expect(screen.getByText('Champion: marie')).toBeInTheDocument();
	});

	it('applies the variant class', () => {
		const { container } = render(Stamp, { props: { label: 'Closed', variant: 'ink' } });
		const el = container.querySelector('.stamp');
		expect(el?.className).toContain('stamp--ink');
	});
});
