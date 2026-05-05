export function dollarsToCents(dollars: number): number {
  const cents = Math.round(dollars * 100);
  if (Math.abs(cents - dollars * 100) > 1e-6) {
    throw new Error(`fractional cents not representable: ${dollars}`);
  }
  return cents;
}

export function centsToDollars(cents: number): number {
  return cents / 100;
}

const fmt = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD'
});

export function formatUsd(cents: number): string {
  return fmt.format(cents / 100);
}
