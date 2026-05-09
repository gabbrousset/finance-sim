<script lang="ts">
	import uPlot from 'uplot';
	import 'uplot/dist/uPlot.min.css';
	import { formatUsd } from '$lib/shared/money';

	let {
		series,
		height = 240
	}: { series: { date: string; valueCents: number }[]; height?: number } = $props();

	let el: HTMLDivElement | undefined = $state();
	let chart: uPlot | undefined;

	$effect(() => {
		if (!el || series.length === 0) return;

		const xs = series.map((p) => new Date(p.date).getTime() / 1000);
		const ys = series.map((p) => p.valueCents / 100);
		const baseline = ys[0] ?? 10000;
		const width = el.clientWidth || 600;
		const host = el;

		const opts: uPlot.Options = {
			width,
			height,
			legend: { show: false },
			scales: { x: { time: true }, y: {} },
			axes: [
				{
					stroke: () => getComputedStyle(host).getPropertyValue('--color-ink-3').trim() || '#8a7e66',
					font: '10px "JetBrains Mono", monospace',
					ticks: {
						stroke: () => getComputedStyle(host).getPropertyValue('--color-rule').trim() || '#b9ad8e',
						width: 1
					},
					grid: { show: false },
					size: 30
				},
				{
					stroke: () => getComputedStyle(host).getPropertyValue('--color-ink-3').trim() || '#8a7e66',
					font: '10px "JetBrains Mono", monospace',
					ticks: { show: false },
					grid: {
						stroke: () => getComputedStyle(host).getPropertyValue('--color-rule-soft').trim() || '#d4c8a8',
						width: 1,
						dash: [1, 3]
					},
					size: 64,
					values: (_self: uPlot, ticks: number[]) =>
						ticks.map((t) => formatUsd(Math.round(t * 100)))
				}
			],
			series: [
				{},
				{
					stroke: () => getComputedStyle(host).getPropertyValue('--color-ink').trim() || '#16110a',
					width: 1.4,
					points: { show: false }
				}
			],
			hooks: {
				draw: [
					(u: uPlot) => {
						const yMin = u.scales.y!.min;
						const yMax = u.scales.y!.max;
						if (yMin == null || yMax == null) return;
						if (baseline < yMin || baseline > yMax) return;
						const yPx = u.valToPos(baseline, 'y', true);
						const ctx = u.ctx;
						ctx.save();
						const brass = getComputedStyle(host).getPropertyValue('--color-brass').trim() || '#9b7a32';
						ctx.strokeStyle = brass;
						ctx.lineWidth = 1;
						ctx.setLineDash([4, 3]);
						ctx.globalAlpha = 0.6;
						ctx.beginPath();
						const left = u.bbox.left;
						const right = u.bbox.left + u.bbox.width;
						ctx.moveTo(left, yPx);
						ctx.lineTo(right, yPx);
						ctx.stroke();
						ctx.restore();
					}
				]
			}
		};

		chart?.destroy();
		chart = new uPlot(opts, [xs, ys], el);

		const ro = new ResizeObserver(() => {
			if (el && chart) chart.setSize({ width: el.clientWidth, height });
		});
		ro.observe(el);

		return () => {
			ro.disconnect();
			chart?.destroy();
		};
	});
</script>

<figure class="ec">
	<figcaption class="ec__cap">
		<em>Account equity, last thirty days, drawn at close.</em>
		<span class="ec__fig">Fig. I</span>
	</figcaption>
	<div bind:this={el} class="ec__host" style:height="{height}px"></div>
</figure>

<style>
	.ec { margin: 0 0 56px; }
	.ec__cap {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		font-family: var(--font-body);
		font-style: italic;
		font-size: 13px;
		color: var(--color-ink-2);
		margin-bottom: 8px;
	}
	.ec__fig {
		font-family: var(--font-mono);
		font-style: normal;
		font-size: 9.5px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		color: var(--color-ink-3);
	}
	.ec__host { width: 100%; }
	:global(.u-axis) { color: var(--color-ink-3); }
</style>
