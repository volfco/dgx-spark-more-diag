# sparkdiag

Hardware root-cause investigation toolkit for NVIDIA GB10 systems (DGX Spark / ASUS Ascent GX10) that power off
or fail to boot the GPU under load. One self-contained Python 3 program (`sparkdiag.py`, stdlib only) that packages
a GB10 instability investigation (instant power-offs under GPU load, traced to a degraded GPU thermal interface) so the same evidence can be collected and the same conclusions
rediscovered on any unit, and produces a far more detailed report than NVIDIA's field diagnostic (`partnerdiag`).

```
sudo ./sparkdiag.py all --out /var/log/sparkdiag                 # inventory + forensics + report (read-only)
sudo ./sparkdiag.py telemetry --out /var/log/sparkdiag --udp collector.example:9999   # crash-survivable sampler
sudo ./sparkdiag.py stress --experiments thermal,sweep --caps 1200,1500,1800,2100 --out /var/log/sparkdiag \
     --i-understand-this-can-power-off-the-node                 # DESTRUCTIVE characterisation
sudo ./sparkdiag.py resume --out /var/log/sparkdiag             # after a power loss: what was running
./sparkdiag.py compare --label spark1=/path/spark1 --label spark0=/path/spark0 --reference spark0 --out ./report
./sparkdiag.py compare --before /path/spark1-before --after /path/spark1-after --reference spark0 --out ./report   # same unit, two points in time
```

## MODS log decoding

`sparkdiag.py` contains no NVIDIA key material. MODS field-diagnostic logs (`fieldiag.log`/`.mle`) are decoded with
AES keys derived at run time from the MODS binary installed on the node
(`/opt/nvidia/dgx-spark-fieldiag/dgx/tests/mods.580/fieldiag`, or `--mods-bin PATH`). Logs written by a different
MODS build than the binary given are reported, not decoded.

## Subcommands

| command | mode | what it does |
|---|---|---|
| `inventory` | read-only | DMI (BIOS/board/serials), ESRT capsule versions, fwupd devices, kernel/cmdline/lockdown/Secure Boot/taint, NVIDIA driver/GSP/VBIOS/PCI link/clock-event counters, PCI device + AER + link state, ACPI table list + sha256 (root), thermal zones with ACPI names (`device/path`) mapped to SPBM fields, cooling devices, fan driver state, NVMe `unsafe_shutdowns`/`power_cycles` (nvme-cli, root), boot list with unclean-shutdown detection (journal of a boot not ending in a shutdown sequence) and gap to the next boot, installed fieldiag version/MODS binary/`modsblacklist.conf` leftover/MODS module, CDI spec vs live `nvidia-uvm` major (`/proc/devices`, `/dev/nvidia-uvm`), docker + image presence, mlx5 "insufficient power" lines. |
| `forensics` | read-only | previous boots: journal grep (NVRM/Xid/GSP/SEC2/GB20B/SEC_FAULT/thermal/BERT/mlx5/watchdog) with decode of `RmInitAdapter failed! (init:rm:line)` (RM_INIT enum + NV_STATUS), Xid codes, SEC2 secure-boot timeout strings, `Check failed` lines; last journal lines and clean/abrupt classification; BERT/HEST/ERST presence + APEI kernel lines (+ BERT payload head, root); pstore; PCI cfg `0x2B4` VSEC_DEBUG_SEC with bit names (VMON, DCLS, L5_WDT, lockdown) and IFF position; `--bar0`: the read-only BAR0 plan (below); MODS run discovery (`/opt/nvidia/dgx-spark-fieldiag/{dgx,logs}/**/logs-*`, `--mods-logs DIR`) with wrapper status (`test_status.log`, `unified_summary.json`, `summary.json`, `run.log`), decoded `fieldiag.log`/`.mle`: error codes (`test*1000+rc`, RC names), `Boot status` with GFW-stage decode, last test reached, log tail, completeness; flight-recorder logs. Decoded plaintext is written to `OUT/mods-decoded/`. |
| `telemetry` | read-only | unified sampler at `--rate-ms` (default 20): NVML instant/average power, SM clock, GPU temperature, clocks-event bitmask (ctypes `libnvidia-ml.so.1`; `nvidia-smi --query-gpu -lms` fallback), all thermal zones (millidegrees) with ACPI names, fan RPM (hwmon `dgx_ec_fan` or any hwmon fan), SPBM power/limit/temperature words via read-only `/dev/mem` when lockdown is `none` (else `\_TZ.RREG` through `/proc/acpi/call` if present, else skipped — the record header says which), clocks-event counters every `--counters-s`, new `/dev/kmsg` lines. Output `telemetry-*.log` is `KIND {json}` lines on an O_DSYNC file followed by `os.sync()`; `--udp HOST:PORT` mirrors every line. |
| `stress` | **DESTRUCTIVE** | requires `--i-understand-this-can-power-off-the-node`. Experiments (`--experiments`): `thermal` (per cap: 30 s sustain + 3 s/7 s pulses → zone0 rise at 1/5/30 s, C/W), `sweep` (caps × {continuous, 10ms/10ms, 1ms/1ms, 100us/100us, 100us/20us} with the %globaltimer MMA kernel), `killstep` (idle → continuous full-GPU step at `--cap` or `--kill-caps`), `ramp` (same final load reached with 0/50/200/1000 ms block-join ramps), `partial` (25/50/75/100 % of SMs). Every step: cool-down below `--cool-below`, `nvidia-smi -lgc 0,CAP`, a synced marker (`steps.log`, `logger -t sparkdiag`, `MARK` record), state.json persisted durably *before* the step starts, GPU job directly (if `cupy`+`pynvml` import) or `docker run` of `--image` (default `$SPARKDIAG_IMAGE`) with the embedded kernel script bind-mounted, host sampler running throughout, thermal abort guard (`--abort-c`, default 95 C) and a hard stop. Afterwards the clock lock is restored (`--restore-cap`, default 1200 as in the investigation scripts; `none` = `-rgc`) and the fan mode (`--fan keep|max|auto`, via the `dgx_ec_fan_control` driver only). `--dry-run` prints the plan. |
| `resume` | read-only (+ `--continue`) | reads `stress/state.json`: which step was running when the records stop, the last telemetry/SPBM sample, the last markers. `--continue` (with the consent flag) marks that step `died` and runs the remaining plan. |
| `report` / `compare` | offline | `--before DIR --after DIR`: before/after-intervention mode for the SAME unit (e.g. a GPU repaste): runs are paired by cap and pattern, the power-offs and the hotspot rise per watt are compared (and against `--reference`), and the verdict is stated (removed → thermal; unchanged → points away from the thermal interface). Otherwise ingests one or more result directories (sparkdiag output, or the investigation's raw recorder logs, SPBM logs, sweep/killstep logs, flight-recorder logs): inventory table + diffs, forensics, per-experiment tables, cross-node comparison at equal cap/pattern/power, power-loss events, the last-N-ms window before every power loss (NVML + SPBM, from the synced logs), findings, reproduction recipe → `report.md` + `report.json`. |
| `all` | read-only | `inventory` + `forensics` + `report`. |
| `mods` | offline | decode/summarise MODS files directly (`./sparkdiag.py mods fieldiag.log --mods-bin …`). |

Exit codes: 0 ok, 2 preflight/usage problem, 3 destructive command without consent.

## Safety: what is read, what is never touched

Read (all read-only): sysfs/procfs (`/sys/class/{dmi,thermal,hwmon,pci}`, `/sys/firmware/{efi,acpi}`, `/proc/{cmdline,version,devices,driver/nvidia}`), the journal (`journalctl`), `nvidia-smi` queries, NVML through ctypes (query calls only), `fwupdmgr get-devices`, `nvme smart-log`, `lspci`/`setpci -s … .l` (reads), PCI config space via sysfs (`0x2B4` needs root), `/dev/kmsg`, MODS log/spec files and the MODS binary (never executed), CDI spec files.

Optional read-only hardware mappings (root, lockdown `none`, explicitly documented):
* **SPBM page** `0x1C238000` (4 KiB, MediaTek System Power Budget Manager shared memory, the same page the kernel's thermal zones read through `\_TZ.RREG`): `/dev/mem` opened `O_RDONLY`, `mmap(PROT_READ)`; words read: PID winner `0x08`, PL level `0x48`, PROCHOT `0x4C`, OS/EC/UEFI/effective PL and SYSPL limits `0x100–0x174`, telemetry rails `0x300–0x338` (sys total, SoC pkg, CPU, VCORE, VDDQ, DC input/CHR, GPC/GPU in/out, total sys in, pre-regulator), limit floors/ceilings `0x708–0x73C`, EWMA `0x800/0x80C`, temperatures `0x818–0x838` (deci-Kelvin; `0x818` PKG_TJ_MAX = thermal_zone TSOC). Never written: the `UPDATE_SPBM` doorbell at 0, `*_VAL_OS` limits, `*_CLEAR_OVERFLOW`. Alternative on lockdown kernels: `\_TZ.RREG <phys>` via `/proc/acpi/call` (the DSDT's own 32-bit read method).
* **BAR0** (`forensics --bar0`): the ordered plan from `gpu-boot/REPORT.md` §5.1 — `NV_PMC_BOOT_0` (0x0), `NV_PMC_BOOT_42` (0xA00), `SCRATCH_RESET_PLUS_2` PLM (0x5E4) and value (0x5E0; 0xFF = GFW boot complete), `PBUS_SW_SCRATCH(30)` (0x1478), `XAL_EP_INTR_0`, WPR2 hi/lo, GSP falcon HWCFG2/MAILBOX0-1/MAILBOX(0..3)/IRQSTAT/fault-containment/RISC-V CPUCTL,RPC,PRIV_ERR*,HUB_ERR, SEC2 HWCFG2/MAILBOX0-1/queue heads+tails/CPUCTL/RPC. One aligned 32-bit read each, in that order; stop on `0xFFFFFFFF` (off the bus) or `0xBADF0200` (SEC_FAULT dummy); `0xBADFxxxx` PRI errors decoded. **Excluded and asserted at import time:** `*EMEMD/DMEMD/IMEMD` auto-increment ports, ICD debug interfaces, interrupt-clear registers, the PRAMIN window `0x700000–0x7FFFFF`, `NV_XAL_EP_BAR0_WINDOW`. The mapping is refused if PCI `COMMAND` Memory Space Enable is clear (enabling it is not read-only) or lockdown is on.

Never touched, by design (no code path exists): the EC in any form — **no FF-A calls, no eSPI, no fan packets of our own** (fan floor changes go only through the existing `dgx_ec_fan_control` driver's cooling device / `dgx-fan-control` CLI when the user asks for `--fan max`); `\_SB.ESPI` MMIO `0x16050000`; SPMI/PMIC ranges (`0x1C6Axxxx–0x1C6Dxxxx`, `0x1C548xxx`, `0x1C57/5C/61/66xxxx`); SPM `0x1C800000`/`0x1C87B00x`; the SSPM/HFRP/ROT windows; any SPBM write; any GPU register write; efivars writes. `NEVER_TOUCH_PHYS` is checked against the SPBM mapping at start.

Side effects that *are* performed, only by `stress` and only with the consent flag: `nvidia-smi -lgc/-rgc`, fan cooling-state writes through the driver, `systemctl stop/start dgx-fan-control` (for `--fan max`), `logger` journal markers, GPU load inside the container/process. `stress` without the flag exits 3 before doing anything.

The GPU load generator (`GPU_LOAD_SRC`, written to `stress/sparkdiag_gpuload.py`) is the investigation's `khzload.py` with one fix: the thermal-abort flag lives in **host-mapped pinned memory** (`cudaHostAlloc(cudaHostAllocMapped)` + `cudaHostGetDevicePointer`, read as `volatile` by the persistent kernel) so a host store reaches the running kernel within microseconds; it self-checks visibility at start (`FLAGCHECK`) and refuses to run if the mapping does not work. Second layer: if the sensors stay above the limit for `--hard-stop-s` (1 s) after an abort, the script hard-exits (`HARDSTOP`, destroying the CUDA context) and the orchestrator kills the container/process.

## Result directory layout

```
OUT/
  inventory.json  forensics.json  mods-decoded/      # read-only collectors
  telemetry-<stamp>-<tag>.log                        # KIND {json} lines: HDR TEL CTR KMSG MARK ABORT END
  stress/state.json       # plan + per-step status/summary, durable (written before every step)
  stress/steps.log        # ISO markers: SESSION-START / BEGIN / RESULT / … (fsync'd), also sent to the journal
  stress/telemetry-<stamp>.log   # the host sampler for the whole session (SPBM, zones, NVML, kmsg)
  stress/rec/<stamp>-<step-id>.log   # the GPU script's own record (START/FLAGCHECK/LAUNCHED/TEL/ABORT/DONE/END)
  stress/sparkdiag_gpuload.py
  report/report.md  report/report.json
```

`TEL` records carry flat keys compatible with the investigation recorders (`p_inst_mw`, `p_avg_mw`, `sm_mhz`, `gpu_c`, `evr`, `thermal_zoneN` in millidegrees, `fan1/fan2` RPM, `spbm_<name>` raw words, `hot_c`). `report` also ingests the raw investigation data (`repro/runs/*`: `KIND {json}` recorder logs, `spbm-*.log` "ts v1 v2 …" with the `keys=` header, `sweep-*.log`/`killstep-*.log`, `flightrec-*.log`).

## How to read the report

* **Findings** come first, sorted critical → warning → info. Every evidence line is tagged **[O]** observed (a number from the data), **[C]** calculated (ratio, window, band derived from [O] lines) or **[H]** hypothesis. The finding ids map to the investigation's (revised) conclusions:
  * `heat-path` — **the primary diagnostic**: zone0 (ACPI TSOC = SPBM PKG_TJ_MAX, the GPU hotspot) rises ≥ 2× faster per watt than the reference node at the same cap/pattern/power at a fixed clock lock, while the other zones do not → localized heat-path fault (thermal interface). Single-node fallback `heat-path-single` grades against the healthy envelope (0.45 C/W at 30 s) and is tagged [H].
  * `load-step-poweroff`: a run whose records stop within seconds of a load step, with the SPBM window (DC input / GPU rail / SoC package / Tj register at 50 Hz up to the last flushed sample), the statement that the SPBM power-management state (PL level, PID winner, PROCHOT, EC limits) did not change before the cut, and the **Tj-register update cadence** measured from the SPBM log (median/p10/p90 of the intervals between value changes; ~60 ms median on GB10). A cut within ~2 update intervals of the step is flagged **"thermal not excluded"**: the register is a filtered maximum of fixed sensor sites and cannot show an unsensed die region heating within ~100 ms. The report never concludes "not thermal" from a temperature read inside the sensor update interval. Mechanisms are listed as [H] (hardware thermal shutdown on a local die hotspot — favoured when the unit also shows `heat-path` — or rail/PMIC protection) with the discriminator: a cooling intervention and the same steps again.
  * `clock-band`: survived vs died caps under full load → the band containing the trigger, framed as V/F-dependent power density (a higher V/F point raises power density and leakage on the die; fits a local thermal trigger as well as an electrical limit; not proof of an electrical fault); "ramping does not prevent the trip" when deaths span several ramp lengths.
  * `intervention-effect` (`--before/--after`): the power-offs removed and the hotspot heating normalised after a cooling change → the fault was thermal; power-off still present → points away from the thermal interface.
  * `thermal-plateau`: a firmware loop holding zone0 at ~96 C below the 104.85 C `_CRT` with SM dithering, node alive — the same fault at lower power density.
  * `gfw-boot-stall` / `gfw-boot-stall-bar0` / `rminit` / `sec-fault`: MODS `Boot status = 0x…` ≠ 0xFF, BAR0 0x5e0 ≠ 0xFF, `RmInitAdapter failed (0x62:0x65:…)` decoded, PCI 0x2B4 fault bits.
  * `fieldiag-truncated`, `mods-not-decoded`, `stale-cdi`, `fieldiag-blacklist`, `mods-module`, `unclean-boots`, `bert`, `xid`, `nvme-unsafe`, `access`, `inventory-diff`, `zone-identity`, `flightrec`.
* **Inventory** table across nodes, then unavailable items with the reason (needs root, tool missing, not present).
* **Forensics**: boot table (clean/ABRUPT, gap to next boot), decoded journal lines, PCI 0x2B4, BAR0 table, MODS run table (tests, result, error, boot status, last MODS test, logs decoded or why not).
* **Experiments**: per node per run: cap, pattern, P mean/max, zone0 base/peak, rise at 1/5/30 s, C/W, SM max, plateau, status (`ok`/`aborted`/`DIED`); per-pulse tables; cross-node comparison; power-loss events; which step a sweep/killstep log was in when it stopped.
* **Last N ms before power loss**: NVML/ACPI samples and the SPBM step table (dt from the onset) for every death.
* **Reproduction recipe**: generated from the data (killing cap and expected time-to-cut, the before/after re-test after a cooling intervention, clock-band discriminators, the thermal comparison), as sparkdiag commands and by-hand equivalents.
* **Data sources and limitations**: what was ingested, what could not be read.

Units: zone temperatures in C (sysfs millidegrees / 1000), SPBM temperatures deci-Kelvin → C, SPBM power words mW → W, NVML mW → W, counters in µs.

## Tests (offline)

```
python3 -m py_compile sparkdiag.py
SPARKDIAG_FIXTURES=/path/to/investigation-data python3 -m unittest discover -s tests -v   # fixture tests skip when unset
```

The tests use the real recorded data (`../repro/runs`, the MODS evidence run, the fieldiag binary, the decoded
references, the baseline captures) and skip with a message when a fixture is absent. They check both builds (key
hygiene, embedded-key fallback), the AES implementation (FIPS-197 vector, counter wrap vs `cryptography`), MODS
decoding (log/MLE/spec byte-exact against the references; other-build and no-binary failure modes), the record,
SPBM, step-log and flight-recorder parsers, that the analysis reproduces FINDINGS.md numerically (zone0 +15.6 vs
+2.9 C at 5 s at 1200 MHz, 0.83 vs 0.32 C/W at 1800, the 96 C plateau, the 2400 MHz death 80–120 ms after the step
at 125.1 W / 38.5 C, SPBM max 142.4 W at 2100, the sweep log stopping in `cap=2400 cont`, `Boot status 0x00000008`),
the Tj-register cadence (median ~60 ms, p90 140-200 ms; two updates between the 2400 MHz step and the cut), the findings engine
incl. the before/after intervention verdict on a fabricated post-repaste fixture, the CLI degradation on a machine without a GPU/SPBM/fieldiag (exit 0, every missing item
named), the consent gate and dry run, the plan generator, resume on a fabricated state, and that the GPU script's
abort flag is host-mapped. Test scratch files go under `tests/.tmp` (or `$SPARKDIAG_TEST_TMP`), never `/tmp`.

## Known limitations

* GPU clock-lock state is not queryable through nvidia-smi; `stress` records what it sets and restores `--restore-cap` (default 1200) at the end.
* Under kernel lockdown (Secure Boot on) SPBM needs the `acpi_call` module (`\_TZ.RREG`) and BAR0 cannot be read; the report says so.
* MODS logs from a build other than the installed binary are reported, not decoded.
* NVML field IDs 185/186 (average/instant power) are validated against `nvmlDeviceGetPowerUsage` at start and dropped if inconsistent; GPU voltage is not exposed by NVML on GB10.
* The GPU load runs in a container image given by `--image` or `$SPARKDIAG_IMAGE` (any CUDA 13 image with `cupy`, `pynvml` and `nvcc`) or directly when those import on the host; the orchestrator itself needs nothing beyond the standard library.
* The step-vs-ramp / partial-load experiments produce new data; the findings engine derives the clock band, ramp and spread statements from whatever runs are ingested.
* The tool never reads the EC, PMIC or TF-A: a cut that leaves no OS-visible trace is characterised by its timing, the last SPBM/NVML samples and the latches (0x2B4, 0x5e0) on the next boot, not by a vendor fault code.
* No OS-visible temperature can show a local die hotspot inside the sensor update interval (SPBM Tj register ~60 ms median, ACPI zones 250-500 ms); the decisive evidence for a thermal cause is the heat-path comparison and a before/after cooling intervention, which is why the report ranks those first.
