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
		const width = el.clientWidth || 600;

		const opts: uPlot.Options = {
			width,
			height,
			legend: { show: false },
			scales: { x: { time: true }, y: {} },
			axes: [
				{ stroke: 'currentColor' },
				{
					stroke: 'currentColor',
					values: (_self: uPlot, ticks: number[]) =>
						ticks.map((t) => formatUsd(Math.round(t * 100)))
				}
			],
			series: [
				{},
				{
					stroke: 'oklch(0.65 0.18 250)',
					width: 2,
					points: { show: false }
				}
			]
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

<div bind:this={el} class="w-full" style:height="{height}px"></div>
