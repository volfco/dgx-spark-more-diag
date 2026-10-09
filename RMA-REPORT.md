# ASUS Ascent GX10 (NVIDIA GB10) serial TAMSAG014886WK8: instant power-offs under GPU load caused by a degraded GPU thermal interface

**Summary.** This unit lost power instantly (no OS log, no Xid, no panic) whenever the GPU ran substantial load at
clocks of about 2320 MHz and above, and during NVIDIA's field diagnostic. It also ran its GPU hotspot about three
times hotter per watt than an identical reference unit, under silent firmware throttling. After repeated
power-offs, its GPU boot firmware stalled (`MODS-000000900167 "GFW boot reported a failure"`; `NV_PMC_SCRATCH_RESET_PLUS_2`
= 0x08 instead of 0xFF) until AC power was removed. **Re-pasting the GPU removed every symptom**: the hotspot now
heats like the reference unit, and the load steps that powered the unit off 4 times out of 4 (2400 MHz) and in 5 of 5
field-diagnostic runs (maximum P-state) now run for 10 s at 107–122 W without a fault. The power-offs are most
consistent with the GB10's hardware thermal shutdown firing on a local GPU-die hotspot faster than any OS-visible
sensor can show it.

Evidence tags: **[O]** observed, **[C]** calculated from observations, **[H]** hypothesis, **[U]** unknown.

## 1. Units and configuration [O]

| | affected unit | reference unit |
|---|---|---|
| Model | ASUS Ascent GX10 (DGX Spark platform, GB10) | ASUS Ascent GX10 |
| Serial | TAMSAG014886WK8 | TAMSAG0057052W2 |
| BIOS | GX10DGX.0106.2026.0707.0731 | same |
| EC | 0x02000007 | same |
| SoC/BSP capsule, USB-C PD firmware | 0x03000008, 0x00000516 | same |
| VBIOS | 9A.0B.2D.00.00 | same |
| Driver / GSP firmware | 580.159.03 (open kernel modules) | same |
| Kernel | 6.17.0-1018-nvidia (Ubuntu 24.04) | same |
| GPU PCI ID | 10de:2e12 (MODS chip GB20B) | same |
| NVMe unsafe shutdowns | 80 | 45 |
| GPU silicon data (field-diagnostic log) | AteSpeedo 2197/1739/1996/2165, GPCVddSpeedo 2218/1750/2007/2186, ATE NVVDD Iddq 10836 mA, Bin Speedo ~2472 MHz, Comp Speedo ~2981 MHz | not collected |

## 2. Field symptoms (before the repaste) [O]
- Instant power-off while serving an LLM (vLLM, GPU clock cap 2200 MHz) during prompt-prefill bursts (2026-10-08 21:46
  and 23:29 UTC). No kernel message; the journal ends seconds early; the peer node's direct-attach links drop within 1 s.
- During model load: Xid 119 (GSP RPC timeout), then `NV_ERR_GPU_IN_FULLCHIP_RESET`, then a reboot (23:06 UTC).
- NVIDIA field diagnostic r9.257.3 (`partnerdiag --field`): the node powered off in GpuStress on five runs (6–25 s in),
  including one with the fans forced to maximum and a 42 °C start. The field-diagnostic log of two of those runs ends at
  `Enter CuvidNVDEC (test 360) [virtual test id Video:CuvidNVDEC_max_0]`, entered right after MODS set the maximum
  P-state; power was lost ~17 s and ~5 s later.
- Field diagnostic r9.257.8 (2026-10-09 01:07 UTC): `MODS-000000900167 GFW boot reported a failure` after a 16 s poll of
  `PMC_SCRATCH_RESET_PLUS_2` (last value 0x00000008), before any load. The NVIDIA driver then failed the same wait
  (`ksec2PrepareBootCommands_HAL ... Call timed out` → `RmInitAdapter failed! (0x62:0x65:2028)`). AC removal restored the GPU.

## 3. Method [O]
- Load: a persistent CUDA kernel running bf16 tensor-core MMA with random operands on all 48 SMs, started from idle,
  phases timed on the GPU's global timer (continuous, or square waves down to 100 µs/20 µs). Requirements: CUDA 13 with
  CuPy and pynvml. The GPU clock was locked with `nvidia-smi -lgc 0,<MHz>`.
- Telemetry, every line written with O_DSYNC so it survives a power cut: NVML at 20 ms, all ACPI thermal zones, and on the
  affected unit (kernel lockdown off) the SoC power-budget registers (SPBM, physical 0x1C238000, read-only) at 50 Hz:
  DC input, system, SoC package and GPU power, PROCHOT and power-limit state, and the package Tj.
- Both units ran the same tests, concurrently where the comparison is thermal. Fan control: the reference unit used the
  factory curve; the affected unit used the factory curve for the thermal comparisons and a maximum fan floor
  (via a third-party fan-floor driver) for the power-off tests.

## 4. Thermal comparison [O]
ACPI zone `TSOC` (= SPBM `PKG_TJ_MAX`) equalled `TGPU` in every sample before the repaste: the package hotspot was the GPU.

| test | reference | affected, before repaste | affected, after repaste |
|---|---|---|---|
| 1200 MHz, ~30 W, 60 s: hotspot rise at 5 s / peak | +2.7–3.2 °C / ~52 °C | +15.7 °C / 63.8 °C | +2.2 °C / 54.7 °C |
| 1800 MHz, ~53 W, 3 s pulses: rise per pulse / peak | +7.5…+11 °C / ~56 °C | +30…+36 °C / 76.3 °C | +9.3…+11.7 °C / 52.6 °C |
| 1800 MHz, ~53 W, 30 s sustained: peak | 60.6 °C | 85.0 °C, still rising | — |
| 2100 MHz, ~77 W, 3 s pulses | +12…+17 °C / ~63 °C | 42.6 → 90.7 °C in the first pulse | +15…+17.8 °C / 59.6 °C |
| 2100 MHz, ~77 W, 20 s | 42.7 → 65.9 °C, no throttling | held at 96–97 °C by firmware throttling (SW thermal slowdown 14.4 s, HW 0.6 s; no OS message) | — |

Before the repaste the other six zones stayed at or below the reference: the excess heating was local to the GPU.
After the repaste the package hotspot is a CPU cluster and `TGPU` reads lower.

## 5. Power-off reproduction and the effect of the repaste [O]

| clock lock / load from idle | affected, before repaste | affected, after repaste | reference |
|---|---|---|---|
| 2100 MHz continuous, 10 s | survives (GPU 90.8 W) | — | survives |
| 2200 MHz continuous, 10 s | survives (peak GPU 96.0 W), throttling at ~95 °C | — | — |
| 2400 MHz continuous, own adapter | **power lost at +0.12 s** (GPU 95.1 W) | **survives 10 s at 106.8–107.0 W (2 of 2)** | survives 10 s at 105–106 W |
| 2400 MHz continuous, reference unit's adapter | **power lost at ~+0.4 s** | — | survives on the affected unit's adapter (101 W) |
| 2400 MHz, SMs ramped in over ~0.5 s | **power lost at +0.49 s** (GPU 98.5 W) | — | — |
| 2400 MHz, SMs ramped in over 4 s | **power lost at +2.88 s** (GPU 62–69 W in a throttle dip, Tj reading 85.7 °C) | — | — |
| no cap (ran to 2509 MHz, power-limited) | field diagnostic at max P-state: power lost 5 of 5 | **survives 10 s at 107.5 W mean, 122 W peak** | — |

The reference unit also passed a full sweep of clock locks 1200–2400 MHz × {continuous, 10 ms/10 ms, 1 ms/1 ms,
100 µs/100 µs, 100 µs/20 µs} load patterns, 10 s each.

SPBM record of the first 2400 MHz power-off (20 ms samples; values are filtered by the firmware):

| t from load start | DC input | SoC package | GPU | package Tj register |
|---|---|---|---|---|
| −0.02 s | 40.3 W | 27.3 W | 16.1 W | 36.6 °C |
| +0.00 s | 47.2 W | 33.4 W | 22.4 W | 36.6 °C |
| +0.04 s | 84.1 W | 67.8 W | 56.7 W | 36.7 °C |
| +0.08 s | 112.8 W | 94.8 W | 83.5 W | 36.7 °C |
| +0.10 s | 125.1 W | 106.3 W | 95.1 W | 38.5 °C |
| +0.12 s | — power lost | | | |

## 6. Interpretation
1. **[O] One cause, at the GPU's thermal interface.** Every failing test passes after re-pasting the GPU, with no other change
   (same firmware, driver, adapter, scripts).
2. **[O] Not the power adapter.** Swapping adapters between the units moved nothing.
3. **[O] The firmware power manager did not act.** PL level, PID winner, PROCHOT status and the EC limits (PL1 140 W,
   SYSPL1 231 W) were unchanged in every SPBM sample up to each power-off.
4. **[O] The OS-visible temperatures cannot show the trigger.** The SPBM package-Tj register (which all ACPI thermal zones
   read) changes on median every ~60 ms (90th percentile 140–200 ms) and reports fixed sensor sites; it updated once or twice
   between the 2400 MHz load step and the power-off. The ACPI critical trip (104.85 °C) produces a logged orderly shutdown and
   never fired.
5. **[H] Mechanism.** With a degraded thermal interface, a region of GPU die heats far faster than the package sensors report
   (at ~95 W, tens of °C within ~100 ms where the die has no conductive path); the GB10's hardware thermal shutdown cuts power
   below the OS with no log. Higher clocks raise power density and leakage, which is why the trigger appeared above
   ~2200 MHz and at the maximum P-state. Silent firmware throttling at ~97 °C (§4) is the same fault seen at lower power.
6. **[H] Boot-firmware stall.** Repeated hard power-offs are a plausible cause of the FWSEC stall at
   `PMC_SCRATCH_RESET_PLUS_2` = 0x08, which only AC removal cleared. [U] Not re-tested after the repaste.

## 7. Status and recommendations
- The affected unit currently runs at a 1200 MHz GPU clock cap; after the repaste it passed every test that failed before
  (one session). [U] Long-term stability: re-run NVIDIA's field diagnostic and production load before removing the cap.
- For other GB10 units with the same instant power-off signature: compare the GPU hotspot rise per watt against a known-good
  unit at a fixed clock lock (§4). A rise several times faster at equal power indicates the thermal interface, and clock caps
  only mask it.

## Appendix: reproducing with sparkdiag
The measurements in this report were taken with the scripts that became `sparkdiag.py` in this repository:
- §4 thermal comparison: `sudo ./sparkdiag.py stress --experiments thermal --caps 1200,1800,2100 --i-understand-this-can-power-off-the-node`
  on each unit, then `./sparkdiag.py compare --label affected=DIR1 --label reference=DIR2 --reference reference`.
- §5 power-off reproduction: `--experiments killstep --cap 2400`, `--experiments ramp --cap 2400` and
  `--experiments sweep --caps 1200,1500,1800,2100,2400` (each can power the unit off; `sparkdiag resume` reads the
  synced records afterwards). Before/after an intervention such as a repaste:
  `./sparkdiag.py compare --before DIR_BEFORE --after DIR_AFTER --reference DIR_REFERENCE`.
- §2/§6 forensics: `sudo ./sparkdiag.py all` (boot history with abrupt-power-loss detection, NVRM/RmInitAdapter decode,
  `VSEC_DEBUG_SEC` decode, field-diagnostic run analysis and log decoding with keys derived from the installed MODS binary).
- The raw 20 ms records from both units, the sweep logs, the 50 Hz SPBM logs up to each power-off and the
  field-diagnostic run directories are available on request.
