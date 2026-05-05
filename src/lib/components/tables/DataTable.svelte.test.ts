import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import DataTable from './DataTable.svelte';

describe('DataTable', () => {
	it('renders rows and tabular numerics', () => {
		render(DataTable, {
			columns: [
				{ key: 'symbol', label: 'Symbol' },
				{ key: 'price', label: 'Price', tabular: true }
			],
			rows: [{ symbol: 'AAPL', price: '$190.50' }]
		});
		expect(screen.getByText('AAPL')).toBeInTheDocument();
		expect(screen.getByText('$190.50')).toHaveClass('tabular');
	});

	it('renders empty state when rows is empty', () => {
		render(DataTable, {
			columns: [{ key: 'symbol', label: 'Symbol' }],
			rows: []
		});
		expect(screen.getByText('no data')).toBeInTheDocument();
	});

	it('renders custom empty message', () => {
		render(DataTable, {
			columns: [{ key: 'symbol', label: 'Symbol' }],
			rows: [],
			empty: 'nothing here'
		});
		expect(screen.getByText('nothing here')).toBeInTheDocument();
	});

	it('renders column headers', () => {
		render(DataTable, {
			columns: [
				{ key: 'symbol', label: 'Symbol' },
				{ key: 'price', label: 'Price', tabular: true }
			],
			rows: []
		});
		expect(screen.getByText('Symbol')).toBeInTheDocument();
		expect(screen.getByText('Price')).toBeInTheDocument();
	});
});
