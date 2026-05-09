import { render } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import FormBar from './FormBar.svelte';

describe('FormBar', () => {
	it('renders one swatch per delta when at default length', () => {
		const { container } = render(FormBar, { props: { deltas: [1, -1, 0, 1, 1, -1] } });
		expect(container.querySelectorAll('.fb__seg').length).toBe(6);
	});

	it('colors swatches by sign of delta', () => {
		const { container } = render(FormBar, { props: { deltas: [1, -1, 0, 0, 0, 0] } });
		const segs = container.querySelectorAll('.fb__seg');
		expect(segs[0]?.className).toContain('fb__seg--up');
		expect(segs[1]?.className).toContain('fb__seg--dn');
		expect(segs[2]?.className).toContain('fb__seg--flat');
	});

	it('pads short input with flat swatches up to default length 6', () => {
		const { container } = render(FormBar, { props: { deltas: [1, 1] } });
		expect(container.querySelectorAll('.fb__seg').length).toBe(6);
	});
});
