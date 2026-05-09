<script lang="ts">
	import uPlot from 'uplot';
	import 'uplot/dist/uPlot.min.css';

	let {
		data,
		dates,
		width = 110,
		height = 28
	}: { data: number[]; dates?: string[]; width?: number; height?: number } = $props();

	let el: HTMLDivElement | undefined = $state();
	let chart: uPlot | undefined;

	$effect(() => {
		if (!el || data.length === 0) return;
		const xs: number[] = dates
			? dates.map((d) => new Date(d).getTime() / 1000)
			: data.map((_, i) => i);

		const first = data[0];
		const last = data[data.length - 1];
		let strokeVar = '--color-ink';
		if (first != null && last != null) {
			if (last > first) strokeVar = '--color-gain';
			else if (last < first) strokeVar = '--color-loss';
		}
		const stroke =
			getComputedStyle(el).getPropertyValue(strokeVar).trim() || '#16110a';

		const opts: uPlot.Options = {
			width,
			height,
			legend: { show: false },
			cursor: { show: false },
			scales: { x: { time: !!dates }, y: {} },
			axes: [{ show: false }, { show: false }],
			series: [{}, { stroke, width: 1.2, points: { show: false } }]
		};

		chart?.destroy();
		chart = new uPlot(opts, [xs, data], el);
		return () => chart?.destroy();
	});
</script>

<div bind:this={el} class="sp" style:width="{width}px" style:height="{height}px"></div>

<style>
	.sp { display: inline-block; }
</style>
