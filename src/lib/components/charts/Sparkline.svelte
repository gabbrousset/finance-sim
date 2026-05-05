<script lang="ts">
	import uPlot from 'uplot';
	import 'uplot/dist/uPlot.min.css';

	let { data, dates }: { data: number[]; dates?: string[] } = $props();
	let el: HTMLDivElement | undefined = $state();
	let chart: uPlot | undefined;

	$effect(() => {
		if (!el || data.length === 0) return;

		const xs: number[] = dates
			? dates.map((d) => new Date(d).getTime() / 1000)
			: data.map((_, i) => i);

		const isGain =
			data[0] != null &&
			data[data.length - 1] != null &&
			data[data.length - 1]! >= data[0]!;

		const opts: uPlot.Options = {
			width: 80,
			height: 20,
			legend: { show: false },
			cursor: { show: false },
			scales: { x: { time: !!dates }, y: {} },
			axes: [{ show: false }, { show: false }],
			series: [
				{},
				{
					stroke: isGain ? 'oklch(0.72 0.18 145)' : 'oklch(0.65 0.22 25)',
					width: 1.5,
					points: { show: false }
				}
			]
		};

		chart?.destroy();
		chart = new uPlot(opts, [xs, data], el);

		return () => chart?.destroy();
	});
</script>

<div bind:this={el} class="inline-block"></div>
