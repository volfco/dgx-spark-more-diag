#!/usr/bin/env python3
"""sparkdiag -- hardware root-cause investigation toolkit for NVIDIA GB10 (DGX Spark / ASUS Ascent GX10) instability.

One self-contained, stdlib-only program (Python 3.8+) that packages a GB10 power-off investigation into a tool:

  inventory   read-only: firmware/kernel/driver/PCI/NVMe/boot/fieldiag/CDI/fan state
  forensics   read-only: previous-boot analysis, NVRM/Xid decode, BERT/pstore, PCI cfg 0x2B4, optional BAR0 plan,
              MODS field-diag log discovery + decode (keys derived at run time from the installed MODS binary)
  telemetry   read-only: unified crash-survivable sampler (NVML + ACPI zones + fans + SPBM power telemetry)
  stress      DESTRUCTIVE: characterisation experiments (needs --i-understand-this-can-power-off-the-node)
  resume      after a power loss: which stress step was running, last telemetry, optionally continue the plan
  report      ingest one or more result directories -> Markdown + JSON with [O]/[C]/[H]-tagged findings
  compare     same as report for several nodes (inventory diffs emphasised)
  all         the safe subcommands (inventory, forensics, report)
  mods        decode / summarise MODS logs or spec files directly

See README.md for what is read, what is never touched, and how to read the report.
"""
import argparse
import ctypes
import datetime
import glob
import hashlib
import json
import mmap
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib

VERSION = "1.0.0"
BUILD = "shareable"   # build.py rewrites this to "internal" and fills MODS_KNOWN_KEYS
MODS_KNOWN_KEYS = {}  # shareable build: empty.  Internal build: {version: {"log": hex, "data": hex}}

PROG = "sparkdiag"
DEFAULT_MODS_BIN = "/opt/nvidia/dgx-spark-fieldiag/dgx/tests/mods.580/fieldiag"
# Container image for the GPU load generator in docker mode: any CUDA 13 image with cupy and pynvml.
DEFAULT_IMAGE = os.environ.get("SPARKDIAG_IMAGE", "")
FIELDIAG_ROOT = "/opt/nvidia/dgx-spark-fieldiag"
MODS_BLACKLIST = "/etc/modprobe.d/modsblacklist.conf"

# ----------------------------------------------------------------------------------------------------------------
# Reference tables (all from the local investigation reports; provenance noted per table)
# ----------------------------------------------------------------------------------------------------------------

# MediaTek SPBM (System Power Budget Manager) shared page, phys 0x1C238000, 4 KiB.  Offsets and names come from the
# \_SB.MTEL _DSM register map in the DSDT (rca/acpi/REPORT.md section 2.1).  Units: temperatures are deci-Kelvin
# (verified: raw 3239 == thermal_zone0 50.75 C); power words behave as mW (third-party drivers + consistency with NVML).
SPBM_BASE = 0x1C238000
SPBM_SIZE = 0x1000
SPBM_FIELDS = [  # (name, offset, unit, ACPI/_DSM name)
    ("pid_win", 0x08, "idx", "PID_MIN_WINNER"),
    ("pl_lvl", 0x48, "idx", "PL_CUR_LEVEL_STATUS"),
    ("prochot", 0x4C, "flag", "PROCHOT_STATUS"),
    ("pl1_os", 0x100, "mW", "PL1_VAL_OS"), ("spl1_os", 0x110, "mW", "SYSPL1_VAL_OS"),
    ("pl1_ec", 0x120, "mW", "PL1_VAL_EC"), ("pl2_ec", 0x124, "mW", "PL2_VAL_EC"),
    ("spl1_ec", 0x130, "mW", "SYSPL1_VAL_EC"), ("spl2_ec", 0x134, "mW", "SYSPL2_VAL_EC"),
    ("pl1_uefi", 0x140, "mW", "PL1_VAL_UEFI"), ("spl1_uefi", 0x150, "mW", "SYSPL1_VAL_UEFI"),
    ("pl1_eff", 0x160, "mW", "PL1_VAL"), ("pl2_eff", 0x164, "mW", "PL2_VAL"),
    ("spl1_eff", 0x170, "mW", "SYSPL1_VAL"), ("spl2_eff", 0x174, "mW", "SYSPL2_VAL"),
    ("sys_tot", 0x300, "mW", "TE_SYS_TOTAL"), ("soc_pkg", 0x304, "mW", "TE_SOC_PKG"),
    ("c_and_g", 0x308, "mW", "TE_C_AND_G"), ("cpu_p", 0x30C, "mW", "TE_CPU_P"), ("cpu_e", 0x310, "mW", "TE_CPU_E"),
    ("vcore", 0x314, "mW", "TE_VCORE"), ("vddq", 0x318, "mW", "TE_VDDQ"),
    ("dc_in", 0x31C, "mW", "TE_CHR (DC input)"),
    ("gpc_out", 0x320, "mW", "TE_GPC_OUT"), ("gpu", 0x324, "mW", "TE_TOTAL_GPU_OUT"),
    ("gpc_in", 0x328, "mW", "TE_GPC_IN"), ("gpu_in", 0x32C, "mW", "TE_TOTAL_GPU_IN"),
    ("sys_in", 0x330, "mW", "TE_TOTAL_SYS_IN"), ("prereg", 0x338, "mW", "TE_PREREG_IN"),
    ("pl1_lo", 0x708, "mW", "PL1_LIMIT_LOW"), ("pl1_hi", 0x70C, "mW", "PL1_LIMIT_HIGH"),
    ("spl1_lo", 0x738, "mW", "SYSPL1_LIMIT_LOW"), ("spl1_hi", 0x73C, "mW", "SYSPL1_LIMIT_HIGH"),
    ("ewma_pl1", 0x800, "mW", "PWR_AVG_EWMA_S_PL1"), ("ewma_spl1", 0x80C, "mW", "PWR_AVG_EWMA_S_SYSPL1"),
    ("tj", 0x818, "dK", "PKG_TJ_MAX (thermal_zone TSOC)"), ("tj_c", 0x81C, "dK", "PKG_TJ_MAX_C"),
    ("t_cpu_e0", 0x820, "dK", "TEMP_CPU_E_CLU_0 (TS0E)"), ("t_cpu_p0", 0x824, "dK", "TEMP_CPU_P_CLU_0 (TS0P)"),
    ("t_cpu_e1", 0x828, "dK", "TEMP_CPU_E_CLU_1 (TS1E)"), ("t_cpu_p1", 0x82C, "dK", "TEMP_CPU_P_CLU_1 (TS1P)"),
    ("t_gpu", 0x830, "dK", "TEMP_GPU (TGPU)"), ("t_soc", 0x834, "dK", "TEMP_SOC (TUNC)"), ("t_dla", 0x838, "dK", "TEMP_DLA"),
]
SPBM_BY_NAME = {f[0]: f for f in SPBM_FIELDS}
# Legacy names used by repro/spbmlog.py (its "gpu_in" was 0x320 = GPC_OUT and "gpu_out" was 0x324 = TOTAL_GPU_OUT)
SPBM_LEGACY_NAMES = {"gpu_out": "gpu", "gpu_in": "gpc_out"}
# SPBM offsets that must never be written (and that this tool never maps writable): the UPDATE_SPBM doorbell at 0,
# *_VAL_OS limits 0x100-0x11C, *_CLEAR_OVERFLOW accumulators.  /dev/mem is only ever opened O_RDONLY here.

# ACPI thermal zone name (from /sys/class/thermal/thermal_zoneN/device/path) -> SPBM field (DSDT \_TZ.RREG reads)
ACPI_TZ_TO_SPBM = {"TSOC": "tj", "TS0E": "t_cpu_e0", "TS0P": "t_cpu_p0", "TS1E": "t_cpu_e1", "TS1P": "t_cpu_p1",
                   "TGPU": "t_gpu", "TUNC": "t_soc"}
ACPI_TZ_INDEX_ORDER = ["TSOC", "TS0E", "TS0P", "TS1E", "TS1P", "TGPU", "TUNC"]  # DSDT declaration order [H] if no path
ACPI_CRT_DECI_K = 3780  # _CRT = 0x0EC4 on every zone = 104.85 C

# Physical ranges this tool never touches (rca/acpi/REPORT.md section 6 / P3).  Documented for the README and
# asserted at run time before any /dev/mem mapping.
NEVER_TOUCH_PHYS = [
    (0x16050000, 0x16051000, "ESPI controller (EC eSPI; a normal-world read caused a watchdog reboot)"),
    (0x1C6A0000, 0x1C6E0000, "SPMI masters -> PMICs"), (0x1C548000, 0x1C549000, "SPMI"),
    (0x1C570000, 0x1C570100, "SPMI"), (0x1C5C0000, 0x1C5C0100, "SPMI"), (0x1C610000, 0x1C610100, "SPMI"),
    (0x1C660000, 0x1C660100, "SPMI"),
    (0x1C800000, 0x1C800100, "MediaTek SPM"), (0x1C87B000, 0x1C87B008, "SPM"),
    (0x1C870200, 0x1C870600, "SSPM window (unidentified)"), (0x311C0000, 0x311C0100, "HFRP window (unidentified)"),
    (0x1C8B0000, 0x1C900000, "SSPM MCU"), (0x18010000, 0x18021000, "ROT0/ROT1 root-of-trust mailboxes"),
]

# PCI config 0x2B4 NV_EP_PCFG_GPU_VSEC_DEBUG_SEC (gpu-boot/REPORT.md section 4.1; gb20b/dev_boot.h).
VSEC_DEBUG_SEC_BITS_GB20B = {2: "SEC2_DCLS", 3: "SEC2_L5_WDT", 4: "GSP_DCLS", 5: "GSP_L5_WDT", 6: "PMU_DCLS",
                             7: "PMU_L5_WDT", 8: "GPMVDD_VMON", 9: "GPCVDD_VMON",
                             10: "SOC2GPU_SEC_FAULT_FUNCTION_LOCKDOWN_REQ", 11: "FUNCTION_LOCKDOWN",
                             12: "DEVICE_LOCKDOWN"}
VSEC_DEBUG_SEC_BITS_GB10B = {0: "FUSE_POD", 1: "SEC2_SCPM", 2: "SEC2_DCLS", 3: "SEC2_L5_WDT", 4: "GSP_DCLS",
                             5: "GSP_L5_WDT", 6: "PMU_DCLS", 7: "PMU_L5_WDT"}
VSEC_OFFSET = 0x2B4

# BAR0 read-only plan (gpu-boot/REPORT.md section 5.1), in the documented order.  [b] = borrowed from a sibling
# chip header (unverified for this die); every read is one aligned 32-bit load, never a write.
BAR0_PLAN = [
    (0x000000, "NV_PMC_BOOT_0", "0xFFFFFFFF = off bus (stop); 0xBADF0200 = SEC_FAULT lockdown (stop); else chip id"),
    (0x000A00, "NV_PMC_BOOT_42", "bits 29:24 arch (0x1A GB1xx / 0x1B GB2xx), 23:20 impl (0xB GB10B|GB20B, 0xC GB20C)"),
    (0x0005E4, "NV_PMC_SCRATCH_RESET_PLUS_2_PRIV_LEVEL_MASK", "bit0 = level-0 readable"),
    (0x0005E0, "NV_PMC_SCRATCH_RESET_PLUS_2", "0xFF = GFW/FWSEC boot complete; 0 = never written; other = stalled stage"),
    (0x001478, "NV_PBUS_SW_SCRATCH(30)", "bit0 = RM 'GPU reset required' latch (index inferred)"),
    (0x10F100, "NV_XAL_EP_INTR_0 [b]", "bit1 PRI_FECSERR, bit2 PRI_REQ_TIMEOUT, bit3 PRI_RSP_TIMEOUT, bit5 FB_ACK_TIMEOUT, bit24 TRS_TIMEOUT"),
    (0x1FA828, "NV_PFB_PRI_MMU_WPR2_ADDR_HI [b]", "non-zero = WPR2 up (ACR/GSP-FMC ran since reset)"),
    (0x1FA824, "NV_PFB_PRI_MMU_WPR2_ADDR_LO [b]", ""),
    (0x1100F4, "NV_PGSP_FALCON_HWCFG2", "bit12 MEM_SCRUBBING, bit13 RISCV_BR_PRIV_LOCKDOWN, 0xBADF41xx = target locked"),
    (0x110040, "NV_PGSP_FALCON_MAILBOX0", "GSP-FMC/ACR error code (8-bit) or boot-args address low"),
    (0x110044, "NV_PGSP_FALCON_MAILBOX1", "boot-args address high"),
    (0x110804, "NV_PGSP_MAILBOX(0)", "GSP-RM scratch (dumped on Xid 119)"),
    (0x110808, "NV_PGSP_MAILBOX(1)", ""), (0x11080C, "NV_PGSP_MAILBOX(2)", ""), (0x110810, "NV_PGSP_MAILBOX(3)", ""),
    (0x110008, "NV_PGSP_FALCON_IRQSTAT [b]", "bit24 FATAL_ERROR"),
    (0x111700, "NV_PGSP_RISCV_FAULT_CONTAINMENT_SRCSTAT [b]", "bit0 GLOBAL_MEM faulted (poison, Xid 140)"),
    (0x111388, "GSP NV_PRISCV_RISCV_CPUCTL", "bit4 HALTED, bit5 STOPPED, bit7 ACTIVE_STAT"),
    (0x1113EC, "GSP NV_PRISCV_RISCV_RPC", "last RISC-V PC"),
    (0x111420, "GSP PRIV_ERR_STAT (GB202 layout)", ""), (0x111424, "GSP PRIV_ERR_INFO", ""),
    (0x111428, "GSP PRIV_ERR_ADDR", ""), (0x11142C, "GSP PRIV_ERR_ADDR_HI", ""), (0x111430, "GSP HUB_ERR_STAT", ""),
    (0x8400F4, "NV_PSEC_FALCON_HWCFG2", "SEC2 lockdown/scrub state"),
    (0x840040, "NV_PSEC_FALCON_MAILBOX0", "SEC2 partition status (GB10B: 0xc001cafe = busy)"),
    (0x840044, "NV_PSEC_FALCON_MAILBOX1", ""),
    (0x840C00, "NV_PSEC_QUEUE_HEAD(0)", "RM->SEC2 command queue"), (0x840C04, "NV_PSEC_QUEUE_TAIL(0)", ""),
    (0x840C80, "NV_PSEC_MSGQ_HEAD(0)", "SEC2->RM message queue"), (0x840C84, "NV_PSEC_MSGQ_TAIL(0)", ""),
    (0x841388, "SEC2 NV_PRISCV_RISCV_CPUCTL", "is the SEC2 core running"),
    (0x8413EC, "SEC2 NV_PRISCV_RISCV_RPC", "last PC"),
]
# Registers with read side effects: never read (asserted against BAR0_PLAN at import time).
BAR0_EXCLUDED = [
    (0x700000, 0x800000, "PRAMIN window"), (0x10FD40, 0x10FD44, "NV_XAL_EP_BAR0_WINDOW"),
    (0x840AC0, 0x840AC8, "NV_PSEC_EMEMC/EMEMD auto-increment ports"),
    (0x110184, 0x110188, "GSP IMEMD"), (0x1101C4, 0x1101C8, "GSP DMEMD"),
    (0x840184, 0x840188, "SEC2 IMEMD"), (0x8401C4, 0x8401C8, "SEC2 DMEMD"),
    (0x111000, 0x111010, "GSP RISC-V ICD (debug) interface head"), (0x841000, 0x841010, "SEC2 RISC-V ICD head"),
]
for _off, _n, _d in BAR0_PLAN:
    for _lo, _hi, _why in BAR0_EXCLUDED:
        assert not (_lo <= _off < _hi), "BAR0 plan contains excluded register %#x (%s)" % (_off, _why)
BAR0_PRI_ERRORS = {0xBAD001: "HOST_PRI_TIMEOUT", 0xBAD0B0: "HOST_FB_ACK_TIMEOUT", 0xBADF10: "FECS_PRI_TIMEOUT",
                   0xBADF11: "PRI_DECODE", 0xBADF12: "PRI_RESET (target in reset)", 0xBADF13: "PRI_FLOORSWEEP",
                   0xBADF14: "STUCK_ACK", 0xBADF15: "0_EXPECTED_ACK", 0xBADF16: "FENCE_ERROR", 0xBADF17: "SUBID",
                   0xBADF20: "ORPHAN", 0xBADF30: "DEAD_RING", 0xBADF40: "TRAP", 0xBADF41: "TARGET_LOCKED (FMC/FSP holds target mask)",
                   0xBADF50: "CLIENT_ERR"}
BAR0_SCPM_DUMMY = 0xBADF0200

# RmInitAdapter failed! (initStatus:rmStatus:line) -- initStatus is the RM_INIT_* enum (osinit.c:48-96), rmStatus is
# NV_STATUS (nvstatuscodes.h).  Both tables from open-gpu-kernel-modules 580.159.03 (gpu-boot/src).
RM_INIT_STATUS = {0x00: "RM_INIT_OK", 0x10: "RM_INIT_REG_SETUP_FAILED", 0x11: "RM_INIT_SYS_ENVIRONMENT_FAILED",
                  0x20: "RM_INIT_GPU_GPUMGR_ALLOC_GPU_FAILED", 0x21: "RM_INIT_GPU_GPUMGR_CREATE_DEV_FAILED",
                  0x22: "RM_INIT_GPU_GPUMGR_ATTACH_GPU_FAILED", 0x23: "RM_INIT_GPU_PRE_INIT_FAILED",
                  0x24: "RM_INIT_GPU_STATE_INIT_FAILED", 0x25: "RM_INIT_GPU_LOAD_FAILED",
                  0x26: "RM_INIT_GPU_DMA_CONFIGURATION_FAILED", 0x27: "RM_INIT_GPU_GPUMGR_EXPANDED_VISIBILITY_FAILED",
                  0x30: "RM_INIT_VBIOS_FAILED", 0x31: "RM_INIT_VBIOS_POST_FAILED", 0x32: "RM_INIT_VBIOS_X86EMU_FAILED",
                  0x40: "RM_INIT_SCALABILITY_FAILED", 0x41: "RM_INIT_WATCHDOG_FAILED", 0x42: "RM_INIT_ALLOC_RMAPI_FAILED",
                  0x43: "RM_INIT_GPUINFO_WITH_RMAPI_FAILED",
                  0x60: "RM_INIT_FIRMWARE_POLICY_FAILED", 0x61: "RM_INIT_FIRMWARE_FETCH_FAILED",
                  0x62: "RM_INIT_FIRMWARE_INIT_FAILED"}
NV_STATUS = {0x0: "NV_OK", 0xFFFF: "NV_ERR_GENERIC", 0x1: "NV_ERR_BROKEN_FB", 0x5: "NV_ERR_CARD_NOT_PRESENT",
             0xB: "NV_ERR_ECC_ERROR", 0xF: "NV_ERR_GPU_IS_LOST", 0x10: "NV_ERR_GPU_IN_FULLCHIP_RESET",
             0x11: "NV_ERR_GPU_NOT_FULL_POWER", 0x1A: "NV_ERR_INSUFFICIENT_RESOURCES", 0x1C: "NV_ERR_INSUFFICIENT_POWER",
             0x1F: "NV_ERR_INVALID_ARGUMENT", 0x25: "NV_ERR_INVALID_DATA", 0x40: "NV_ERR_INVALID_STATE",
             0x47: "NV_ERR_MEMORY_TRAINING_FAILED", 0x51: "NV_ERR_NO_MEMORY", 0x55: "NV_ERR_NOT_READY",
             0x56: "NV_ERR_NOT_SUPPORTED", 0x57: "NV_ERR_OBJECT_NOT_FOUND", 0x59: "NV_ERR_OPERATING_SYSTEM",
             0x60: "NV_ERR_RC_ERROR", 0x61: "NV_ERR_REJECTED_VBIOS", 0x62: "NV_ERR_RESET_REQUIRED",
             0x65: "NV_ERR_TIMEOUT", 0x66: "NV_ERR_TIMEOUT_RETRY", 0x6B: "NV_ERR_PRIV_SEC_VIOLATION",
             0x6F: "NV_ERR_PMU_NOT_READY", 0x70: "NV_ERR_FLCN_ERROR", 0x71: "NV_ERR_FATAL_ERROR",
             0x72: "NV_ERR_MEMORY_ERROR", 0x79: "NV_ERR_RISCV_ERROR", 0x7F: "NV_ERR_SECURE_BOOT_FAILED"}
RM_INIT_LINE_HINTS = {2028: "RM_SET_ERROR after kgspInitRm() failed in RmInitAdapter (osinit.c:2028, 580.159.03)"}

# MODS error codes: code = test*1000 + rc; test 900 = Gpu.Initialize pseudo-test.  RC names observed in the binary.
MODS_RC_NAMES = {167: "GFW_BOOT_FAILURE (GFW boot reported a failure)",
                 168: "GFW_FUSE_CHECK_FAILURE (anomalous fuse configuration)"}
# [H] GFW boot progress encoding of PGC6_AON_SECURE_SCRATCH_GROUP_05 (RM decoder in the MODS binary); whether FWSEC
# uses the same encoding for PMC_SCRATCH_RESET_PLUS_2 on GB10/GB20B is an inference.
GFW_BOOT_PROGRESS = {0: "NOT_STARTED", 1: "STARTED", 2: "BOOT_VALIDATION_COMPLETED",
                     3: "FBFALCON_BOOT_TRAINING_COMPLETED", 4: "FB_SCRUB_STARTED",
                     5: "FB_SCRUB_SYNC_RM_KMD_HEAP_REGION_COMPLETED", 6: "FB_SCRUB_SYNC_DISPLAY_REGION_COMPLETED",
                     7: "FB_SCRUB_ASYNC_REST_OF_FB_STARTED", 8: "VPR_RANGE_SETUP_COMPLETED", 0xFF: "COMPLETED"}

# NVML clocks-event-reason bitmask (nvml.h nvmlClocksEventReason*)
CLOCK_EVENT_BITS = {0x1: "GpuIdle", 0x2: "ApplicationsClocksSetting", 0x4: "SwPowerCap", 0x8: "HwSlowdown",
                    0x10: "SyncBoost", 0x20: "SwThermalSlowdown", 0x40: "HwThermalSlowdown",
                    0x80: "HwPowerBrakeSlowdown", 0x100: "DisplayClockSetting"}

# Healthy-unit reference envelope (a healthy ASUS GX10 measured with the factory fan curve and the bf16 MMA load).
# Used only to grade a single node when no reference node is given; always tagged [H] in findings.
REFERENCE_HEALTHY = {"zone0_rise_5s_per_w_max": 0.15,   # healthy unit: +2.7 C at 5 s @28 W (0.10 C/W); +8..11 C @52 W pulses
                     "zone0_c_per_w_30s_max": 0.45,     # healthy unit: 0.30 C/W at 30 s @52 W (degraded paste: 0.83)
                     "throttle_plateau_c": 96.0}

# ----------------------------------------------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------------------------------------------

def utc_stamp(t=None):
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime(t if t is not None else time.time()))


def iso(t=None):
    dt = datetime.datetime.fromtimestamp(t if t is not None else time.time(), datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def run_cmd(cmd, timeout=30, text=True, check=False, env=None, input_data=None):
    """Run a command; returns (rc, stdout, stderr).  rc=127 when the program is missing, 124 on timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, text=text, env=env, input=input_data)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "" if text else b"", "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "" if text else b"", "%s: timeout after %ss" % (cmd[0], timeout)
    except OSError as e:
        return 126, "" if text else b"", str(e)


def read_text(path, default=None, strip=True):
    try:
        with open(path, "r", errors="replace") as f:
            s = f.read()
        return s.strip() if strip else s
    except OSError:
        return default


def read_int(path, default=None):
    s = read_text(path)
    if s is None:
        return default
    try:
        return int(s, 0)
    except ValueError:
        return default


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return "unreadable: %s" % e


def is_root():
    return os.geteuid() == 0


def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def write_json_durable(path, obj):
    """Write JSON atomically and durably (temp file + fsync + rename + directory fsync + os.sync)."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(d)
    try:
        os.sync()
    except OSError:
        pass


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class SyncWriter:
    """Append-only record file opened O_DSYNC: every write is on stable storage when it returns (crash-survivable).
    Lines are 'KIND {json}' (the format of the repro recorders) so one parser reads everything."""

    def __init__(self, path, udp=None):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_DSYNC, 0o644)
        fsync_dir(d)
        self.lock = threading.Lock()
        self.udp = None
        if udp:
            host, port = udp
            try:
                self.udp = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (host, int(port)))
            except OSError:
                self.udp = None

    def rec(self, kind, **kw):
        kw.setdefault("t", round(time.time(), 4))
        kw.setdefault("m", round(time.monotonic(), 4))
        line = ("%s %s\n" % (kind, json.dumps(kw, separators=(",", ":"), default=str))).encode()
        with self.lock:
            try:
                os.write(self.fd, line)
            except OSError:
                pass
            if self.udp:
                try:
                    self.udp[0].sendto(line[:65000], self.udp[1])
                except OSError:
                    pass

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


class Log:
    verbose = False

    @staticmethod
    def info(msg):
        sys.stderr.write("%s: %s\n" % (PROG, msg))
        sys.stderr.flush()

    @staticmethod
    def debug(msg):
        if Log.verbose:
            sys.stderr.write("%s: %s\n" % (PROG, msg))


def item(ok, data=None, note=None, **extra):
    """Uniform collector result: every inventory/forensics item says whether it was available and why not."""
    d = {"ok": bool(ok)}
    if data is not None:
        d["data"] = data
    if note:
        d["note"] = note
    d.update(extra)
    return d


def needs_root(what):
    return item(False, note="skipped: needs root (%s)" % what)


# ----------------------------------------------------------------------------------------------------------------
# AES-128 (encrypt-only; CTR mode) in pure Python, with optional acceleration.  Needed only for MODS log decoding.
# ----------------------------------------------------------------------------------------------------------------

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_XT = [((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1 for a in range(256)]
_SHIFT = [(i + 4 * (i % 4)) % 16 for i in range(16)]


class AES128:
    """FIPS-197 AES-128, encryption only (CTR mode and the MODS key unwrap need nothing else)."""

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("AES-128 key must be 16 bytes")
        w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
        rcon = 1
        for i in range(4, 44):
            t = list(w[i - 1])
            if i % 4 == 0:
                t = [_SBOX[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _XT[rcon]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        self.rk = [sum(w[4 * r:4 * r + 4], []) for r in range(11)]

    def encrypt_block(self, block):
        rk = self.rk
        s = [b ^ k for b, k in zip(block, rk[0])]
        for r in range(1, 11):
            s = [_SBOX[s[j]] for j in _SHIFT]
            if r != 10:
                o = []
                for c in (0, 4, 8, 12):
                    a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                    o += [_XT[a0] ^ _XT[a1] ^ a1 ^ a2 ^ a3,
                          a0 ^ _XT[a1] ^ _XT[a2] ^ a2 ^ a3,
                          a0 ^ a1 ^ _XT[a2] ^ _XT[a3] ^ a3,
                          _XT[a0] ^ a0 ^ a1 ^ a2 ^ _XT[a3]]
                s = o
            k = rk[r]
            s = [s[j] ^ k[j] for j in range(16)]
        return bytes(s)

    def ctr(self, iv, data):
        """AES-CTR with a big-endian 128-bit counter starting at iv (Crypto++ CTR_Mode<AES> semantics)."""
        ctr = int.from_bytes(iv, "big")
        out = bytearray(len(data))
        enc = self.encrypt_block
        mask = (1 << 128) - 1
        for off in range(0, len(data), 16):
            ks = enc(((ctr + off // 16) & mask).to_bytes(16, "big"))
            chunk = data[off:off + 16]
            out[off:off + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
        return bytes(out)


def aes_ctr(key, iv, data):
    """AES-128-CTR decrypt/encrypt; uses `cryptography` or pycryptodome when importable, pure Python otherwise."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # optional accelerator
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return dec.update(data) + dec.finalize()
    except Exception:
        pass
    try:
        from Crypto.Cipher import AES as _AES  # pycryptodome, optional
        return _AES.new(key, _AES.MODE_CTR, nonce=b"", initial_value=iv).decrypt(data)
    except Exception:
        pass
    return AES128(key).ctr(iv, data)


def mods_unwrap_key(blob48):
    """MODS key blob {C[16] | K2[16] | IV2[16]} -> AES key = C XOR AES_K2(IV2)  (function 0x1a1365e0 in 629.580.34)."""
    c, k2, iv2 = blob48[:16], blob48[16:32], blob48[32:48]
    ks = AES128(k2).encrypt_block(iv2)
    return bytes(a ^ b for a, b in zip(c, ks))


# ----------------------------------------------------------------------------------------------------------------
# MODS (NVIDIA field diagnostic) encrypted file support.  Keys are derived from the installed MODS binary at run
# time; the shareable build embeds none.  Formats from mods-re/REPORT.md section 1.
# ----------------------------------------------------------------------------------------------------------------

MODS_MAGIC = {b"\xf1\x1a\x80": 5, b"\xf1\x1a\x81": 6, b"\xf1\x1a\x82": 7, b"\x2b\xd4\xff": 8}
MODS_KEY_LANDMARK = b" unzip 1.01 Copyright 1998-2004 Gilles Vollant"  # minizip string right after the key blobs
MODS_KEY_VADDRS_629_580_34 = {"A": 0xf7a5a20, "B": 0x419bbe0, "C": 0x419bc10, "D": 0x419bc40}  # fixed-address fallback


def mods_classify(data):
    return MODS_MAGIC.get(bytes(data[:3]), 0)


def mods_parse_header(data):
    """Header fields without decrypting.  Type 6: version/arch/iv; type 5/7: declared size/iv."""
    t = mods_classify(data)
    if t == 6 and len(data) >= 0x4B:
        return {"type": 6, "version": data[3:0x33].split(b"\0")[0].decode("latin1"),
                "arch": data[0x33:0x3b].split(b"\0")[0].decode("latin1"), "iv": bytes(data[0x3b:0x4b]),
                "ciphertext_len": len(data) - 0x4B}
    if t in (5, 7) and len(data) >= 27:
        return {"type": t, "size": struct.unpack_from("<Q", data, 3)[0], "iv": bytes(data[11:27]),
                "ciphertext_len": len(data) - 27}
    return {"type": t}


class ElfMap:
    """Minimal ELF64 program-header reader: virtual address -> file offset (stdlib only)."""

    def __init__(self, path):
        self.path = path
        self.loads = []
        with open(path, "rb") as f:
            hdr = f.read(64)
            if hdr[:4] != b"\x7fELF" or hdr[4] != 2:
                raise ValueError("not an ELF64 file")
            phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
            phentsize, phnum = struct.unpack_from("<HH", hdr, 0x36)
            f.seek(phoff)
            for _ in range(phnum):
                p = f.read(phentsize)
                ptype, flags, off, va, _pa, fsz, _msz, _al = struct.unpack_from("<IIQQQQQQ", p)
                if ptype == 1:
                    self.loads.append((va, off, fsz))

    def file_offset(self, va):
        for base, off, fsz in self.loads:
            if base <= va < base + fsz:
                return off + (va - base)
        return None


class ModsKeyring:
    """Candidate AES keys for a MODS build, derived from its binary (never embedded in the shareable build)."""

    def __init__(self):
        self.candidates = []   # (key_bytes, source)
        self.binary = None
        self.binary_versions = []
        self.notes = []

    @classmethod
    def from_binary(cls, path):
        kr = cls()
        kr.binary = path
        if not path or not os.path.isfile(path):
            kr.notes.append("MODS binary not found: %s" % path)
            return kr
        try:
            with open(path, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    # build identification: NUL-terminated "NNN.NNN.NN" strings
                    for m in re.finditer(rb"(?<![0-9.])(6[0-9]{2}\.[0-9]{3}\.[0-9]{2,3})\x00", mm):
                        v = m.group(1).decode()
                        if v not in kr.binary_versions:
                            kr.binary_versions.append(v)
                        if len(kr.binary_versions) > 8:
                            break
                    seen = set()

                    def add(off, src):
                        if off < 0 or off + 48 > len(mm):
                            return
                        blob = bytes(mm[off:off + 48])
                        if blob in seen or len(set(blob)) < 20 or b"\0\0\0\0" in blob:
                            return
                        seen.add(blob)
                        try:
                            kr.candidates.append((mods_unwrap_key(blob), src))
                        except Exception:
                            pass

                    # 1. landmark: the three wrapped blobs (data, log, legacy) precede the minizip copyright string
                    p = mm.find(MODS_KEY_LANDMARK)
                    if p >= 0:
                        kr.notes.append("landmark found at file offset %#x" % p)
                        base = p - (p % 16)
                        for off in range(base - 48, base - 48 - 1024, -16):
                            add(off, "landmark-%d" % (base - off))
                    else:
                        kr.notes.append("landmark string not found in binary")
                    # 2. the fixed virtual addresses of the analysed build, via the ELF program headers
                    try:
                        em = ElfMap(path)
                        for name, va in MODS_KEY_VADDRS_629_580_34.items():
                            fo = em.file_offset(va)
                            if fo is not None:
                                add(fo, "vaddr-%s-%#x" % (name, va))
                    except Exception as e:
                        kr.notes.append("ELF mapping failed: %s" % e)
                finally:
                    mm.close()
        except OSError as e:
            kr.notes.append("cannot read MODS binary: %s" % e)
        kr.notes.append("%d candidate keys derived" % len(kr.candidates))
        return kr

    def known_keys(self, version):
        """Internal build only: embedded keys for a version string."""
        ent = MODS_KNOWN_KEYS.get(version) or {}
        return [(bytes.fromhex(v), "embedded-%s-%s" % (version, k)) for k, v in ent.items() if v and len(v) == 32]

    def binary_has_version(self, version):
        return version in self.binary_versions


def mods_decode(data, keyring, want_version=None):
    """Decode one MODS file.  Returns dict: ok, type, plaintext (bytes), key_source, version, arch, reason."""
    hdr = mods_parse_header(data)
    t = hdr.get("type", 0)
    res = {"ok": False, "type": t, "header": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in hdr.items()}}
    if t == 0:
        res["reason"] = "unrecognised magic %s (empty or plaintext file)" % bytes(data[:3]).hex()
        return res
    ver = hdr.get("version") or want_version
    cands = list(keyring.candidates) if keyring else []
    if ver:
        cands += keyring.known_keys(ver) if keyring else []
    if not cands:
        res["reason"] = "no candidate keys (binary absent/unreadable and no embedded keys)"
        return res
    if t == 6:
        iv, ct = hdr["iv"], bytes(data[0x4B:])
        probe = ct[:16]
        for key, src in cands:
            if AES128(key).ctr(iv, probe)[:9] != b"encrypted":
                continue
            pt = aes_ctr(key, iv, ct)
            res.update(ok=True, plaintext=pt[9:], key_source=src, version=hdr["version"], arch=hdr["arch"])
            return res
        res["reason"] = "no candidate key yields the 'encrypted' marker (log build %s)" % ver
    else:
        payload = bytes(data[11:])
        if t == 7:
            payload = _unpack7(payload)
        iv, ct = payload[:16], payload[16:]
        probe = ct[:16]
        for key, src in cands:
            head = AES128(key).ctr(iv, probe)
            if len(head) < 2 or head[0] != 0x78 or ((head[0] << 8) | head[1]) % 31 != 0:
                continue
            pt = aes_ctr(key, iv, ct)
            try:
                dobj = zlib.decompressobj()
                out = dobj.decompress(pt) + dobj.flush()
            except zlib.error as e:
                res["reason"] = "zlib: %s" % e
                continue
            res.update(ok=True, plaintext=out, key_source=src, declared_size=hdr.get("size"),
                       size_match=(len(out) == hdr.get("size")), complete=bool(dobj.eof))
            return res
        res.setdefault("reason", "no candidate key inflates this data file")
    if keyring and keyring.binary and ver and keyring.binary_versions and not keyring.binary_has_version(ver):
        res["reason"] += "; installed MODS binary is build %s, file is build %s (keys are per build)" % (
            "/".join(keyring.binary_versions[:2]), ver)
    return res


def _unpack7(data):
    out = bytearray()
    acc = nbits = 0
    for c in data:
        if not (c & 0x80):
            break
        acc = (acc << 7) | (c & 0x7F)
        nbits += 7
        if nbits >= 8:
            out.append((acc >> (nbits - 8)) & 0xFF)
            nbits -= 8
            acc &= (1 << nbits) - 1 if nbits else 0
    return bytes(out)


def protobuf_walk(buf, depth=0, max_depth=6):
    """Generic protobuf wire-format walker -> list of (field, wiretype, value).  LEN values are bytes; nested
    messages are decoded lazily by the caller.  Tolerant of truncation (returns what parsed)."""
    out = []
    i, n = 0, len(buf)
    try:
        while i < n:
            tag, i = _varint(buf, i)
            field, wt = tag >> 3, tag & 7
            if wt == 0:
                v, i = _varint(buf, i)
            elif wt == 1:
                v = struct.unpack_from("<Q", buf, i)[0]
                i += 8
            elif wt == 2:
                ln, i = _varint(buf, i)
                v = bytes(buf[i:i + ln])
                if len(v) < ln:
                    break
                i += ln
            elif wt == 5:
                v = struct.unpack_from("<I", buf, i)[0]
                i += 4
            else:
                break
            out.append((field, wt, v))
    except (IndexError, struct.error, ValueError):
        pass
    return out


def _varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7
        if shift > 70:
            raise ValueError("bad varint")


def mle_entries(pt):
    """Decoded .mle -> list of entries {t (unix s or None), text, rc, fields}.  Field ids per mods-re/REPORT.md 1.6
    (f7 text, f2 timestamp delta in 0.5 ns, f6 priority, f17 device record, f24 RC record)."""
    entries = []
    tcum = 0
    for field, wt, v in protobuf_walk(pt):
        if field != 1 or wt != 2:
            continue
        e = {"text": None, "rc": None, "strings": []}
        for f2, w2, v2 in protobuf_walk(v):
            if f2 == 2 and w2 == 0:
                tcum += v2
                e["t"] = tcum / 2e9
            elif f2 == 7 and w2 == 2:
                e["text"] = v2.decode("utf-8", "replace")
            elif f2 == 6 and w2 == 0:
                e["priority"] = v2
            elif f2 == 24 and w2 == 2:
                for f3, w3, v3 in protobuf_walk(v2):
                    if w3 == 0 and e["rc"] is None:
                        e["rc"] = v3
                    elif w3 == 2:
                        e["strings"].append(v3.decode("utf-8", "replace"))
            elif w2 == 2:
                for s in re.findall(rb"[\x20-\x7e]{3,}", v2):
                    e["strings"].append(s.decode("latin1"))
        entries.append(e)
    return entries


_RE_MODS_ERR = re.compile(r"^\s*Error\s+(\d{6,12})\s*:\s*(\S+)\s+(.*?)\s*(?:\[([\d.]+) seconds\])?\s*$")
_RE_MODS_TEST = re.compile(r"^\s*(Enter|Exit)\s+([A-Za-z0-9_]+)(.*)$")


def mods_log_summary(text):
    """Extract what matters from a decoded MODS text log (works on power-truncated prefixes too)."""
    lines = text.splitlines()
    s = {"lines": len(lines), "errors": [], "boot_status": None, "tests": [], "last_test": None,
         "complete": any(l.startswith("MODS end") for l in lines), "version": None, "command_line": None,
         "warnings": [], "tail": [l for l in lines if l.strip()][-12:]}
    for l in lines:
        m = _RE_MODS_ERR.match(l)
        if m:
            code = int(m.group(1))
            s["errors"].append({"code": code, "test": code // 1000, "rc": code % 1000,
                                "rc_name": MODS_RC_NAMES.get(code % 1000), "context": m.group(2),
                                "message": m.group(3), "seconds": float(m.group(4)) if m.group(4) else None})
            continue
        m = re.search(r"Boot status\s*=\s*(0x[0-9a-fA-F]+)", l)
        if m:
            s["boot_status"] = m.group(1)
        m = _RE_MODS_TEST.match(l)
        if m:
            s["tests"].append({"event": m.group(1), "name": m.group(2), "rest": m.group(3).strip()})
            s["last_test"] = m.group(2)
        m = re.match(r"^MODS\s*:\s*([0-9.]+)", l)
        if m:
            s["version"] = m.group(1)
        if l.startswith("Command Line :") and "fieldiag -" in l:
            s["command_line"] = l.split(":", 1)[1].strip()
        if l.startswith("WARNING:"):
            s["warnings"].append(l.strip())
    if s["boot_status"]:
        v = int(s["boot_status"], 16)
        s["boot_status_decode"] = {"value": v, "gfw_boot_complete": v == 0xFF,
                                   "progress_name_H": GFW_BOOT_PROGRESS.get(v & 0xFF),
                                   "note": "0xFF = FWSEC wrote boot-complete to NV_PMC_SCRATCH_RESET_PLUS_2 (BAR0 0x5e0); "
                                           "stage names are the PGC6 GFW_BOOT_PROGRESS encoding [H]"}
    return s


# ----------------------------------------------------------------------------------------------------------------
# Record parsers: "KIND {json}" recorder files (gpuload / khzload / sparkdiag telemetry), SPBM logs, sweep and
# killstep step logs, flight-recorder logs.
# ----------------------------------------------------------------------------------------------------------------

_RE_KIND = re.compile(r"^([A-Z][A-Z0-9_]*) (\{.*\})\s*$")


def parse_record_file(path):
    """Parse a recorder file.  Returns None when the file is not in the KIND {json} format."""
    events = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = _RE_KIND.match(line)
            if not m:
                continue
            try:
                events.append((m.group(1), json.loads(m.group(2))))
            except ValueError:
                continue  # a torn last line after a power cut
    if not events:
        return None
    kinds = [k for k, _ in events]
    start = next((v for k, v in events if k == "START"), None)
    hdr = next((v for k, v in events if k == "HDR"), None)
    tel = [v for k, v in events if k == "TEL"]
    rec = {"path": path, "name": os.path.basename(path), "events": events, "tel": tel, "start": start, "hdr": hdr,
           "ended": "END" in kinds, "aborted": "ABORT" in kinds, "launched": "LAUNCHED" in kinds or "ON" in kinds,
           "kinds": sorted(set(kinds))}
    if start and "on_us" in start:
        rec["kind"] = "khzload"
        base = start.get("m")
        la = next((v["m"] for k, v in events if k == "LAUNCHED"), None)
        rec["load_start_m"] = (la if la is not None else base) + 1.5 if (la is not None or base is not None) else None
        rec["load_start_t"] = (next((v["t"] for k, v in events if k == "LAUNCHED"), start.get("t")) or 0) + 1.5
        rec["seconds"] = start.get("seconds")
    elif start and "pattern" in start:
        rec["kind"] = "gpuload"
        ons = [v for k, v in events if k == "ON"]
        rec["load_start_m"] = ons[0]["m"] if ons else None
        rec["load_start_t"] = ons[0]["t"] if ons else None
        rec["seconds"] = start.get("seconds")
    elif hdr:
        rec["kind"] = "sparkdiag"
        rec["load_start_m"] = None
        rec["load_start_t"] = None
    else:
        rec["kind"] = "unknown"
        rec["load_start_m"] = None
        rec["load_start_t"] = None
    rec["tag"] = (start or {}).get("tag") or (hdr or {}).get("tag") or os.path.basename(path).rsplit(".", 1)[0]
    rec["t_first"] = events[0][1].get("t")
    rec["t_last"] = events[-1][1].get("t")
    return rec


_RE_CAP = re.compile(r"(?<![0-9])([123][0-9]{3})(?![0-9])")
PATTERN_NAMES = {(100.0, 0.0): "cont", (10000.0, 10000.0): "10ms", (1000.0, 1000.0): "1ms", (100.0, 100.0): "100-100", (100.0, 20.0): "100-20"}


def safe_tag(tag):
    """File-name-safe form of a step id (used by the GPU recorder and when looking its record up)."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(tag))


def pattern_name(on_us, off_us, seconds=None):
    """One canonical pattern label for the stress plan, khzload records and gpuload records.
    continuous >= 20 s -> 'sustain'; continuous -> 'cont'; second-scale square waves -> 'pulse3s/7s'; the sweep's
    kHz patterns -> '10ms', '1ms', '100-100', '100-20'; anything else '<on>/<off>us'."""
    on, off = float(on_us), float(off_us)
    if off == 0:
        return "sustain" if (seconds or 0) >= 20 else "cont"
    if (on, off) in PATTERN_NAMES:
        return PATTERN_NAMES[(on, off)]
    if on >= 1e6 or off >= 1e6:
        return "pulse%gs/%gs" % (on / 1e6, off / 1e6)
    return "%g/%gus" % (on, off)


def tag_info(tag, start=None):
    """Derive (node, cap_mhz, pattern) from a free-form recorder tag such as 's1-sustain60-1200',
    'spark1-sw-2100-100-20', 's0-pulse-1500', 's1-trip-2100'.  Explicit START fields win when present."""
    info = {"node": None, "cap": None, "pattern": None}
    if start and start.get("cap") is not None:
        info["cap"] = start.get("cap")
    m = re.match(r"^(s0|s1|spark\d+|[a-z0-9]+?)[-_]", tag or "")
    if m:
        p = m.group(1)
        info["node"] = {"s0": "spark0", "s1": "spark1"}.get(p, p if p.startswith("spark") else None)
    if info["cap"] is None:
        caps = [int(c) for c in _RE_CAP.findall(tag or "") if 1000 <= int(c) <= 3100]
        if caps:
            info["cap"] = caps[0]
    if start and "on_us" in start:
        info["pattern"] = pattern_name(start["on_us"], start["off_us"], start.get("seconds"))
        if start.get("ramp_ms"):
            info["pattern"] += "+ramp%gms" % start["ramp_ms"]
        if start.get("sm_frac") not in (None, 1, 1.0):
            info["pattern"] += "+sm%d%%" % round(100 * float(start["sm_frac"]))
    elif start and "pattern" in start:
        if start["pattern"] == "sustain":
            info["pattern"] = "sustain"
        else:
            info["pattern"] = pattern_name(float(start.get("on_ms", 0)) * 1000, float(start.get("off_ms", 0)) * 1000, start.get("seconds"))
    else:
        for key in ("sustain", "pulse", "cont", "trip", "thr", "killstep", "ramp"):
            if key in (tag or ""):
                info["pattern"] = key
                break
    return info


def _zone_c(tel, key="thermal_zone0"):
    v = tel.get(key)
    return v / 1000.0 if isinstance(v, (int, float)) else None


def _nearest(tel, m):
    return min(tel, key=lambda x: abs(x.get("m", 0) - m)) if tel else None


def summarize_run(rec, node=None):
    """Per-run physics summary used by the tables and the findings engine."""
    tel = [x for x in rec["tel"] if "m" in x]
    start = rec.get("start") or {}
    ti = tag_info(rec.get("tag"), start)
    s = {"tag": rec.get("tag"), "path": rec["path"], "kind": rec.get("kind"), "node": node or ti["node"],
         "cap": ti["cap"], "pattern": ti["pattern"], "ramp_ms": start.get("ramp_ms", 0) or 0,
         "sm_frac": start.get("sm_frac", 1.0) if start.get("sm_frac") is not None else 1.0,
         "seconds": rec.get("seconds"), "ended": rec["ended"], "aborted": rec["aborted"],
         "launched": rec["launched"], "n_tel": len(tel), "t_start": rec.get("t_first"), "t_last": rec.get("t_last"),
         "load_start_t": rec.get("load_start_t")}
    s["died"] = bool(rec["launched"] and not rec["ended"])
    if not tel:
        return s
    zones = sorted({k for x in tel for k in x if k.startswith("thermal_zone")}, key=lambda k: int(k[12:]))
    s["zones"] = zones
    z0key = "thermal_zone0" if "thermal_zone0" in zones else (zones[0] if zones else None)
    lm = rec.get("load_start_m")
    pre = [x for x in tel if lm is None or x["m"] < lm]
    base_tel = pre[-1] if pre else tel[0]
    s["z0_base"] = _zone_c(base_tel, z0key) if z0key else None
    s["zones_base"] = {z: _zone_c(base_tel, z) for z in zones}
    s["zones_peak"] = {z: max((_zone_c(x, z) or 0) for x in tel) for z in zones}
    s["z0_peak"] = s["zones_peak"].get(z0key) if z0key else None
    s["gpu_base"] = base_tel.get("gpu_c")
    s["gpu_peak"] = max((x.get("gpu_c") or 0) for x in tel)
    p = [(x.get("p_inst_mw") or 0) / 1000.0 for x in tel]
    s["p_idle"] = (base_tel.get("p_inst_mw") or 0) / 1000.0
    load = [x for x in tel if (lm is None or x["m"] >= lm) and (x.get("p_inst_mw") or 0) > 15000]
    if not load:
        load = [x for x in tel if (x.get("p_inst_mw") or 0) > 15000]
    s["p_mean"] = sum((x["p_inst_mw"] or 0) for x in load) / len(load) / 1000.0 if load else 0.0
    s["p_max"] = max(p) if p else 0.0
    pa = [(x.get("p_avg_mw") or 0) / 1000.0 for x in load]
    s["p_avg_mean"] = sum(pa) / len(pa) if pa else 0.0
    sm = [x.get("sm_mhz") for x in load if x.get("sm_mhz")]
    s["sm_max"] = max(sm) if sm else None
    s["sm_min_load"] = min(sm) if sm else None
    s["fan_end"] = (tel[-1].get("fan1"), tel[-1].get("fan2"))
    # power step detection: first TEL after load start where power exceeds idle + 10 W
    thr = s["p_idle"] + 10.0
    stepx = next((x for x in tel if (lm is None or x["m"] >= lm - 0.1) and (x.get("p_inst_mw") or 0) / 1000.0 > thr), None)
    s["step_detected_m"] = stepx["m"] if stepx else None
    if lm is not None and z0key:
        for sec in (1, 2, 5, 10, 20, 30, 60):
            near = _nearest(tel, lm + sec)
            if near and abs(near["m"] - (lm + sec)) < 0.6 and s["z0_base"] is not None:
                s["z0_rise_%ds" % sec] = round(_zone_c(near, z0key) - s["z0_base"], 2)
                s["p_at_%ds" % sec] = round((near.get("p_inst_mw") or 0) / 1000.0, 1)
        if s["z0_base"] is not None:
            s["z0_rise_end"] = round(s["z0_peak"] - s["z0_base"], 2)
    if s.get("z0_rise_30s") is not None and s["p_mean"] > 5:
        s["c_per_w_30s"] = round(s["z0_rise_30s"] / s["p_mean"], 3)
    if s.get("z0_rise_5s") is not None and s["p_mean"] > 5:
        s["rise_5s_per_w"] = round(s["z0_rise_5s"] / s["p_mean"], 4)
    if s.get("z0_rise_end") is not None and s["p_mean"] > 5:
        s["c_per_w_end"] = round(s["z0_rise_end"] / s["p_mean"], 3)
    # firmware thermal plateau: zone0 held >= 94 C for >= 2 s with the SM clock dithering
    if z0key:
        hot = [x for x in tel if (_zone_c(x, z0key) or 0) >= 94.0]
        if hot and hot[-1]["m"] - hot[0]["m"] >= 2.0:
            hz = [_zone_c(x, z0key) for x in hot]
            hsm = [x.get("sm_mhz") for x in hot if x.get("sm_mhz")]
            hp = [(x.get("p_inst_mw") or 0) / 1000.0 for x in hot]
            s["plateau"] = {"seconds": round(hot[-1]["m"] - hot[0]["m"], 1), "z0_min": min(hz), "z0_max": max(hz),
                            "z0_mean": round(sum(hz) / len(hz), 1), "sm_min": min(hsm) if hsm else None,
                            "sm_max": max(hsm) if hsm else None, "p_min": round(min(hp), 1), "p_max": round(max(hp), 1),
                            "gpu_c_max": max((x.get("gpu_c") or 0) for x in hot)}
    # one sensor exposed twice?
    if "thermal_zone0" in zones and "thermal_zone5" in zones:
        same = sum(1 for x in tel if x.get("thermal_zone0") == x.get("thermal_zone5"))
        s["zone0_eq_zone5_frac"] = round(same / len(tel), 3)
    # pulses: gpuload square waves carry ON events; khzload second-scale square waves get synthesised boundaries
    ons = [v["m"] for k, v in rec["events"] if k == "ON"]
    if not ons and rec.get("kind") == "khzload" and lm is not None and start.get("off_us") and float(start["on_us"]) + float(start["off_us"]) >= 1e6:
        period = (float(start["on_us"]) + float(start["off_us"])) / 1e6
        ons = [lm + k * period for k in range(max(1, int((start.get("seconds") or 0) / period)))]
        if len(ons) == 1:
            ons.append(lm + (start.get("seconds") or period))
    if len(ons) >= 2 and z0key and start.get("pattern") != "sustain":
        pulses = []
        for i, t0 in enumerate(ons):
            t1 = ons[i + 1] if i + 1 < len(ons) else 1e18
            w = [x for x in tel if t0 <= x["m"] < t1]
            if not w:
                continue
            z = [_zone_c(x, z0key) for x in w]
            pw = [(x.get("p_inst_mw") or 0) / 1000.0 for x in w if (x.get("p_inst_mw") or 0) > 10000]
            n1 = _nearest(tel, t0 + 1.0)
            pulses.append({"i": i, "z0_start": z[0], "z0_peak": max(z), "rise": round(max(z) - z[0], 1),
                           "rise_1s": round(_zone_c(n1, z0key) - z[0], 1) if n1 else None,
                           "p_mean": round(sum(pw) / len(pw), 1) if pw else 0.0, "p_max": round(max(pw), 1) if pw else 0.0,
                           "sm_max": max((x.get("sm_mhz") or 0) for x in w)})
        s["pulses"] = pulses
    last = tel[-1]
    s["last_tel"] = {"t": last.get("t"), "m": last.get("m"), "p_w": round((last.get("p_inst_mw") or 0) / 1000.0, 1),
                     "sm_mhz": last.get("sm_mhz"), "gpu_c": last.get("gpu_c"), "z0_c": _zone_c(last, z0key) if z0key else None,
                     "fans": (last.get("fan1"), last.get("fan2"))}
    if s["died"] and lm is not None:
        s["death"] = {"t_after_load_s": round(last["m"] - lm, 3), "p_last_w": s["last_tel"]["p_w"],
                      "z0_last_c": s["last_tel"]["z0_c"], "gpu_last_c": last.get("gpu_c"),
                      "sm_last": last.get("sm_mhz"), "t_last": last.get("t"),
                      "p_max_w": round(max(((x.get("p_inst_mw") or 0) / 1000.0) for x in tel if x["m"] >= lm - 0.1), 1)
                      if any(x["m"] >= lm - 0.1 for x in tel) else None}
    return s


def parse_spbm_log(path):
    """repro/spbmlog.py format: '# start T interval_ms=N keys=a,b,c' then 'ts v1 v2 ...'.  Also accepts
    sparkdiag telemetry files (TEL records with spbm_* keys).  Returns {"keys", "rows": [{"t":..., name: raw}], ...}."""
    keys = None
    rows = []
    interval = None
    with open(path, "r", errors="replace") as f:
        first = f.readline()
        if first.startswith("# start"):
            m = re.search(r"keys=(\S+)", first)
            keys = [SPBM_LEGACY_NAMES.get(k, k) for k in m.group(1).split(",")] if m else None
            m = re.search(r"interval_ms=(\d+)", first)
            interval = int(m.group(1)) if m else None
            for line in f:
                parts = line.split()
                if not keys or len(parts) != len(keys) + 1:
                    continue  # torn last line after a power cut
                try:
                    row = {"t": float(parts[0])}
                    for k, v in zip(keys, parts[1:]):
                        row[k] = int(v)
                except ValueError:
                    continue
                rows.append(row)
        else:
            f.seek(0)
            for line in f:
                m = _RE_KIND.match(line)
                if not m or m.group(1) != "TEL":
                    continue
                try:
                    d = json.loads(m.group(2))
                except ValueError:
                    continue
                sp = {k[5:]: v for k, v in d.items() if k.startswith("spbm_")}
                if sp:
                    sp["t"] = d.get("t")
                    rows.append(sp)
                    keys = keys or sorted(sp)
    return {"path": path, "keys": keys or [], "rows": rows, "interval_ms": interval,
            "t_first": rows[0]["t"] if rows else None, "t_last": rows[-1]["t"] if rows else None}


def spbm_w(row, name):
    v = row.get(name)
    return round(v / 1000.0, 1) if isinstance(v, (int, float)) else None


def spbm_c(row, name):
    v = row.get(name)
    return round(v / 10.0 - 273.15, 1) if isinstance(v, (int, float)) and v > 0 else None


SPBM_PM_STATE_FIELDS = ("pid_win", "pl_lvl", "prochot", "pl1_ec", "spl1_ec", "pl1_eff", "spl1_eff", "pl2_eff", "spl2_eff")


def spbm_window(spbm, t0, t1):
    return [r for r in spbm["rows"] if t0 <= r["t"] <= t1]


def spbm_run_stats(spbm, t0, t1):
    w = spbm_window(spbm, t0, t1)
    if not w:
        return None
    st = {"n": len(w), "t0": w[0]["t"], "t1": w[-1]["t"]}
    for k in ("dc_in", "gpu", "soc_pkg", "sys_tot", "sys_in", "prereg", "vcore"):
        vals = [r[k] for r in w if isinstance(r.get(k), (int, float))]
        if vals:
            st["%s_max_w" % k] = round(max(vals) / 1000.0, 1)
            st["%s_mean_w" % k] = round(sum(vals) / len(vals) / 1000.0, 1)
    for k in ("tj", "t_gpu", "t_soc"):
        vals = [r[k] for r in w if isinstance(r.get(k), (int, float)) and r[k] > 0]
        if vals:
            st["%s_max_c" % k] = round(max(vals) / 10.0 - 273.15, 1)
    st["pm_state"] = spbm_pm_state(w)
    return st


def spbm_pm_state(rows):
    """Power-management state fields: distinct values over the rows (unchanged == one value each)."""
    out = {}
    for k in SPBM_PM_STATE_FIELDS:
        vals = sorted({r[k] for r in rows if k in r})
        if vals:
            out[k] = {"values": vals[:6], "changed": len(vals) > 1}
    out["any_changed"] = any(v["changed"] for v in out.values() if isinstance(v, dict))
    return out


def spbm_tj_cadence(spbm, t0=None, t1=None, field="tj"):
    """Update cadence of the SPBM package-Tj register (the word every ACPI zone reads): intervals between value
    changes.  The register is a filtered maximum of fixed sensor sites that changes every ~60 ms (median) on GB10,
    so a temperature read within one or two intervals of a cut says nothing about an unsensed die region."""
    rows = [r for r in spbm["rows"] if field in r and (t0 is None or r["t"] >= t0) and (t1 is None or r["t"] <= t1)]
    ch = []
    last = lt = None
    for r in rows:
        if last is None:
            last, lt = r[field], r["t"]
            continue
        if r[field] != last:
            ch.append(r["t"] - lt)
            last, lt = r[field], r["t"]
    if len(ch) < 5:
        return None
    ch.sort()
    n = len(ch)
    return {"n": n, "p10_ms": round(ch[n // 10] * 1000), "median_ms": round(ch[n // 2] * 1000), "p90_ms": round(ch[int(n * 0.9)] * 1000),
            "sample_ms": spbm.get("interval_ms")}


def spbm_step_analysis(spbm, t_load, horizon_s=3.0, idle_s=1.0):
    """Around a load step at wall time t_load: onset (dc_in > idle median + 8 W), the samples up to the last one
    written, and whether the log stops (power loss) inside the horizon."""
    rows = spbm["rows"]
    if not rows:
        return None
    pre = [r for r in rows if t_load - idle_s - 0.5 <= r["t"] < t_load - 0.02]
    idle = sorted(r.get("dc_in", 0) for r in pre)
    idle_med = idle[len(idle) // 2] if idle else None
    post = [r for r in rows if t_load - 0.3 <= r["t"] <= t_load + horizon_s + 1.0]
    onset = None
    if idle_med is not None:
        onset = next((r for r in post if r.get("dc_in", 0) > idle_med + 8000), None)
    last = rows[-1]
    log_ends_in_window = t_load - 0.5 <= last["t"] <= t_load + horizon_s + 1.0
    table = []
    if onset:
        for r in rows:
            if onset["t"] - 0.05 <= r["t"] <= onset["t"] + horizon_s:
                table.append({"dt_s": round(r["t"] - onset["t"], 3), "dc_in_w": spbm_w(r, "dc_in"), "gpu_w": spbm_w(r, "gpu"),
                              "soc_pkg_w": spbm_w(r, "soc_pkg"), "sys_tot_w": spbm_w(r, "sys_tot"), "tj_c": spbm_c(r, "tj"),
                              "prochot": r.get("prochot"), "pl_lvl": r.get("pl_lvl"), "pid_win": r.get("pid_win")})
    res = {"idle_dc_in_w": round(idle_med / 1000.0, 1) if idle_med is not None else None,
           "onset_t": onset["t"] if onset else None, "last_t": last["t"], "log_ends_in_window": log_ends_in_window,
           "table": table, "samples_after_onset": len(table)}
    if onset and log_ends_in_window:
        res["ms_onset_to_last"] = round((last["t"] - onset["t"]) * 1000.0, 1)
        res["last"] = table[-1] if table else None
        tj_seq = [r.get("tj") for r in rows if onset["t"] <= r["t"] <= last["t"]]
        res["tj_updates_onset_to_last"] = sum(1 for a, b in zip(tj_seq, tj_seq[1:]) if a != b)
        res["tj_cadence"] = spbm_tj_cadence(spbm)
        cad = res["tj_cadence"]
        if cad:
            res["cut_within_2_tj_updates"] = res["ms_onset_to_last"] <= 2.0 * cad["median_ms"] + cad["p90_ms"] or res["tj_updates_onset_to_last"] <= 2
        else:
            res["cut_within_2_tj_updates"] = res["tj_updates_onset_to_last"] <= 2
        res["pm_state_last_5s"] = spbm_pm_state([r for r in rows if last["t"] - 5.0 <= r["t"] <= last["t"]])
        pm_idle = spbm_pm_state(pre) if pre else {}
        res["pm_state_idle"] = pm_idle
    return res


_RE_STEP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s+(\S+)\s*(.*)$")


def parse_step_log(path):
    """sweep.sh / killstep.sh / sparkdiag steps.log: 'ISO KEYWORD k=v ...'.  BEGIN without a matching RESULT and no
    later END marks the step that was running when the log stopped (power loss)."""
    steps = []
    meta = {"path": path, "starts": [], "ended": False, "lines": 0}
    cur = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = _RE_STEP.match(line.rstrip("\n"))
            if not m:
                continue
            meta["lines"] += 1
            ts, kw, rest = m.groups()
            kv = dict(re.findall(r"(\w+)=(\S+)", rest))
            if kw in ("SWEEP-START", "START"):
                meta["starts"].append({"t": ts, **kv})
            elif kw == "BEGIN":
                cur = {"t_begin": ts, "result": None, **kv}
                steps.append(cur)
            elif kw == "RESULT" and cur is not None:
                cur["result"] = {"t": ts, "raw": rest, **kv}
                cur = None
            elif kw in ("SWEEP-END", "END"):
                meta["ended"] = True
    meta["steps"] = steps
    unfinished = [s for s in steps if s["result"] is None]
    meta["running_at_end"] = unfinished[-1] if unfinished and not meta["ended"] else None
    return meta


def parse_flightrec(path, max_kmsg=200):
    """dgx_flightrec.py log: START / REC {json} / KMSG line / OUT line / ERR line."""
    recs, kmsg, out = [], [], []
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("REC "):
                try:
                    recs.append(json.loads(line[4:]))
                except ValueError:
                    pass
            elif line.startswith("KMSG "):
                kmsg.append(line[5:].rstrip())
            elif line.startswith(("OUT ", "ERR ")):
                out.append(line.rstrip())
    tel = []
    for r in recs:
        d = {"t": float(r.get("wall", 0)), "m": float(r.get("mono", 0))}
        for k, v in (r.get("sensors") or {}).items():
            if k.startswith("tz:thermal_zone"):
                d[k.split(":")[1]] = v
            elif ":fan" in k:
                d["fan" + k.rsplit("fan", 1)[1].split("_")[0]] = v
        tel.append(d)
    res = {"path": path, "n_rec": len(recs), "kmsg": kmsg[-max_kmsg:], "out": out[-40:], "tel": tel,
           "tests": sorted({r.get("test") for r in recs if r.get("test")}),
           "logdirs": sorted({r.get("logdir") for r in recs if r.get("logdir")})}
    if recs:
        res["t_first"] = float(recs[0].get("wall", 0))
        res["t_last"] = float(recs[-1].get("wall", 0))
        res["last_test"] = recs[-1].get("test")
        z0 = [t.get("thermal_zone0") for t in tel if t.get("thermal_zone0") is not None]
        if z0:
            res["z0_max_c"] = max(z0) / 1000.0
            res["z0_last_c"] = z0[-1] / 1000.0
    interesting = [l for l in kmsg if re.search(r"NVRM|Xid|SEC2|GSP|thermal|critical|BERT|Hardware Error|mlx5|watchdog", l)]
    res["kmsg_interesting"] = interesting[-60:]
    return res


# ----------------------------------------------------------------------------------------------------------------
# Cross-run analysis
# ----------------------------------------------------------------------------------------------------------------

def group_key(s):
    return (s.get("cap"), s.get("pattern"))


def compare_nodes(summaries, reference=None):
    """Group runs by (cap, pattern); for groups with >= 2 nodes compute zone0 heating ratios at equal power."""
    groups = {}
    for s in summaries:
        if s.get("cap") is None or not s.get("node"):
            continue
        groups.setdefault(group_key(s), {}).setdefault(s["node"], []).append(s)
    rows = []
    for key, bynode in sorted(groups.items(), key=lambda kv: (kv[0][0] or 0, str(kv[0][1]))):
        if len(bynode) < 2:
            continue
        pick = {n: max(runs, key=lambda r: r.get("n_tel", 0)) for n, runs in bynode.items()}
        nodes = sorted(pick)
        ref = reference if reference in pick else min(nodes, key=lambda n: pick[n].get("z0_rise_5s") or pick[n].get("z0_rise_end") or 0)
        for n in nodes:
            if n == ref:
                continue
            a, b = pick[n], pick[ref]
            row = {"cap": key[0], "pattern": key[1], "node": n, "reference": ref,
                   "p_mean": (a.get("p_mean"), b.get("p_mean")), "z0_base": (a.get("z0_base"), b.get("z0_base")),
                   "z0_peak": (a.get("z0_peak"), b.get("z0_peak"))}
            for metric in ("z0_rise_1s", "z0_rise_5s", "z0_rise_30s", "z0_rise_end", "c_per_w_30s", "c_per_w_end", "rise_5s_per_w"):
                va, vb = a.get(metric), b.get(metric)
                row[metric] = (va, vb)
                floor = 0.02 if metric in ("rise_5s_per_w", "c_per_w_30s", "c_per_w_end") else 1.0   # reference must be measurable
                if va is not None and vb not in (None, 0) and vb > floor:
                    row[metric + "_ratio"] = round(va / vb, 2)
            if a.get("pulses") and b.get("pulses"):
                ra = [p["rise"] for p in a["pulses"][:3]]
                rb = [p["rise"] for p in b["pulses"][:3]]
                row["pulse_rise"] = (ra, rb)
                if rb and max(rb) > 0.5:
                    row["pulse_rise_ratio"] = round(max(ra) / max(rb), 2)
            pa, pb = a.get("p_mean") or 0, b.get("p_mean") or 0
            row["power_equal"] = bool(pa and pb and abs(pa - pb) / max(pa, pb) < 0.25)
            rows.append(row)
    return rows


def clock_band_threshold(summaries, node):
    """Survived vs died caps under full load on one node -> the clock band containing the trigger threshold."""
    runs = [s for s in summaries if s.get("node") == node and s.get("cap") and s.get("launched") and s.get("sm_frac", 1.0) >= 0.99]
    survived = {}
    died = {}
    for s in runs:
        if s.get("died"):
            d = died.setdefault(s["cap"], {"n": 0, "p_last": [], "z0_last": [], "sm": [], "t_after": [], "ramp": set()})
            d["n"] += 1
            dd = s.get("death") or {}
            sp_last = ((dd.get("spbm") or {}).get("last")) or {}
            p_cut = sp_last.get("gpu_w") if sp_last.get("gpu_w") is not None else dd.get("p_last_w")
            tj_cut = sp_last.get("tj_c") if sp_last.get("tj_c") is not None else dd.get("z0_last_c")
            if p_cut is not None:
                d["p_last"].append(p_cut)
            if tj_cut is not None:
                d["z0_last"].append(tj_cut)
            if dd.get("t_after_load_s") is not None:
                d["t_after"].append(round((dd.get("spbm") or {}).get("ms_onset_to_last", dd["t_after_load_s"] * 1000) / 1000.0, 3))
            smv = s.get("sm_max") or dd.get("sm_last")
            if smv:
                d["sm"].append(smv)
            d["ramp"].add(s.get("ramp_ms") or 0)
        elif s.get("ended") and (s.get("p_max") or 0) >= 40:
            v = survived.setdefault(s["cap"], {"n": 0, "p_max": 0, "sm_max": 0, "patterns": set()})
            v["n"] += 1
            v["p_max"] = max(v["p_max"], s.get("p_max") or 0)
            v["sm_max"] = max(v["sm_max"], s.get("sm_max") or 0)
            v["patterns"].add(s.get("pattern"))
    for d in died.values():
        d["ramp"] = sorted(d["ramp"])
    for v in survived.values():
        v["patterns"] = sorted(p for p in v["patterns"] if p)
    res = {"node": node, "survived_caps": survived, "died_caps": died}
    if died and survived:
        max_s = max(survived)
        min_d = min(died)
        res["band"] = (max_s, min_d) if min_d > max_s else None
        res["overlap"] = [c for c in died if c in survived]
    return res


def deaths_summary(summaries):
    rows = [s for s in summaries if s.get("died") and s.get("death")]
    out = []
    for s in rows:
        d = s["death"]
        out.append({"node": s.get("node"), "tag": s.get("tag"), "cap": s.get("cap"), "pattern": s.get("pattern"),
                    "ramp_ms": s.get("ramp_ms"), "sm_frac": s.get("sm_frac"), "t_after_load_s": d.get("t_after_load_s"),
                    "p_last_w": d.get("p_last_w"), "p_max_w": d.get("p_max_w"), "z0_last_c": d.get("z0_last_c"),
                    "gpu_last_c": d.get("gpu_last_c"), "sm_last": d.get("sm_last"), "t_last": d.get("t_last")})
    return out


# ----------------------------------------------------------------------------------------------------------------
# Inventory collectors (all read-only; every item reports availability)
# ----------------------------------------------------------------------------------------------------------------

def find_gpu_bdf(preferred=None):
    """NVIDIA display-class device under /sys/bus/pci/devices (vendor 0x10de, class 0x03xxxx)."""
    if preferred and os.path.isdir("/sys/bus/pci/devices/%s" % preferred):
        return preferred
    found = []
    for d in sorted(glob.glob("/sys/bus/pci/devices/*")):
        if read_text(d + "/vendor") == "0x10de" and (read_text(d + "/class") or "").startswith("0x03"):
            found.append(os.path.basename(d))
    return found[0] if found else None


def parse_nvidia_smi_q(text):
    """nvidia-smi -q output -> nested dict (indentation = 4 spaces per level)."""
    root = {}
    stack = [(-1, root)]
    for line in text.splitlines():
        if not line.strip() or line.startswith("=") or line.startswith("Timestamp"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else root
        if re.match(r"^GPU [0-9A-Fa-f:.]+$", body):   # 'GPU 0000000F:01:00.0' section header (contains colons)
            child = {}
            parent[body] = child
            stack.append((indent, child))
        elif ":" in body:
            k, v = body.split(":", 1)
            k, v = k.strip(), v.strip()
            if v == "":
                child = {}
                parent[k] = child
                stack.append((indent, child))
            else:
                parent[k] = v
        else:
            child = {}
            parent[body] = child
            stack.append((indent, child))
    return root


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def parse_counters_us(perf):
    """'Clocks Event Reasons Counters' block -> {name: microseconds}."""
    out = {}
    for k, v in (perf or {}).items():
        m = re.match(r"(\d+)\s*us", str(v))
        if m:
            out[k] = int(m.group(1))
    return out


def nvidia_smi_query(fields, timeout=20):
    rc, out, err = run_cmd(["nvidia-smi", "--query-gpu=" + ",".join(fields), "--format=csv,noheader,nounits"], timeout=timeout)
    if rc != 0:
        return None, err.strip() or out.strip()
    vals = [v.strip() for v in out.strip().splitlines()[0].split(",")] if out.strip() else []
    return dict(zip(fields, vals)), None


def inv_dmi():
    base = "/sys/class/dmi/id/"
    keys = ["sys_vendor", "product_name", "product_version", "product_family", "product_sku", "board_vendor",
            "board_name", "board_version", "bios_vendor", "bios_version", "bios_date", "bios_release",
            "ec_firmware_release", "chassis_type", "product_serial", "product_uuid", "board_serial", "chassis_serial"]
    d = {}
    missing_root = []
    for k in keys:
        v = read_text(base + k)
        if v is None and k in ("product_serial", "product_uuid", "board_serial", "chassis_serial") and not is_root():
            missing_root.append(k)
        elif v is not None:
            d[k] = v
    if not d:
        return item(False, note="/sys/class/dmi/id not available")
    return item(True, d, note=("needs root for: " + ", ".join(missing_root)) if missing_root else None)


def inv_esrt():
    ents = sorted(glob.glob("/sys/firmware/efi/esrt/entries/entry*"))
    if not ents:
        return item(False, note="no ESRT (/sys/firmware/efi/esrt)")
    out = []
    denied = False
    for e in ents:
        d = {"entry": os.path.basename(e)}
        for k in ("fw_class", "fw_type", "fw_version", "lowest_supported_fw_version", "last_attempt_version", "last_attempt_status", "capsule_flags"):
            v = read_text(os.path.join(e, k))
            if v is None:
                denied = True
            else:
                d[k] = v
                if k.endswith("version") and v.isdigit():
                    d[k + "_hex"] = "0x%08x" % int(v)
        out.append(d)
    if denied and not is_root():
        return item(False, out, note="skipped: needs root (ESRT entry files are 0400)")
    return item(True, out)


def inv_fwupd():
    rc, out, err = run_cmd(["fwupdmgr", "get-devices", "--json"], timeout=40)
    if rc == 127:
        return item(False, note="fwupdmgr not installed")
    if rc != 0 or not out.strip():
        return item(False, note="fwupdmgr get-devices failed: %s" % (err.strip() or out.strip())[:200])
    try:
        j = json.loads(out)
    except ValueError:
        return item(False, note="fwupdmgr output not JSON")
    devs = []
    for dev in j.get("Devices", []):
        devs.append({k: dev.get(k) for k in ("Name", "Version", "VersionLowest", "Plugin", "Vendor", "Guid", "Flags", "DeviceId") if dev.get(k) is not None})
    return item(True, devs)


def secure_boot_state():
    p = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    try:
        with open(p, "rb") as f:
            raw = f.read()
        return {"enabled": bool(raw[4]) if len(raw) >= 5 else None, "raw": raw.hex()}
    except OSError:
        rc, out, _ = run_cmd(["mokutil", "--sb-state"], timeout=10)
        if rc == 0:
            return {"enabled": "enabled" in out, "source": "mokutil"}
        return {"enabled": None, "note": "SecureBoot efivar not readable and mokutil absent"}


def inv_kernel():
    d = {"release": os.uname().release, "version": read_text("/proc/version"), "cmdline": read_text("/proc/cmdline"),
         "lockdown": read_text("/sys/kernel/security/lockdown"), "secure_boot": secure_boot_state(),
         "tainted": read_text("/proc/sys/kernel/tainted"), "hostname": socket.gethostname()}
    m = re.search(r"\[(\w+)\]", d["lockdown"] or "")
    d["lockdown_mode"] = m.group(1) if m else None
    d["dev_mem_possible"] = d["lockdown_mode"] in (None, "none")
    d["modules"] = {m: os.path.isdir("/sys/module/" + m) for m in ("nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm", "mods", "dgx_ec_fan_control", "acpi_call", "spbm")}
    d["acpi_call_proc"] = os.path.exists("/proc/acpi/call")
    return item(True, d)


def inv_nvidia(bdf):
    d = {"proc_version": read_text("/proc/driver/nvidia/version")}
    infos = {}
    for p in glob.glob("/proc/driver/nvidia/gpus/*/information"):
        txt = read_text(p) or ""
        infos[p.split("/")[-2]] = dict(re.findall(r"^([^:\n]+?):\s*(.*)$", txt, re.M))
    d["gpu_information"] = infos
    rc, out, err = run_cmd(["nvidia-smi", "-q"], timeout=40)
    if rc == 127:
        d["nvidia_smi"] = None
        note = "nvidia-smi not installed"
    elif rc != 0:
        d["nvidia_smi"] = None
        note = "nvidia-smi -q failed: %s" % (err.strip() or out.strip())[:300]
    else:
        q = parse_nvidia_smi_q(out)
        gpu = next((v for k, v in q.items() if k.startswith("GPU ")), {})
        d["driver_version"] = q.get("Driver Version")
        d["cuda_version"] = q.get("CUDA Version")
        d["product_name"] = gpu.get("Product Name")
        d["vbios"] = gpu.get("VBIOS Version")
        d["gsp_firmware"] = gpu.get("GSP Firmware Version")
        d["gpu_part_number"] = gpu.get("GPU Part Number")
        d["gpu_uuid"] = gpu.get("GPU UUID")
        d["recovery_action"] = gpu.get("GPU Recovery Action")
        d["reset_status"] = gpu.get("GPU Reset Status")
        d["pci"] = {"device_id": _get(gpu, "PCI", "Device Id"), "bus_id": _get(gpu, "PCI", "Bus Id"),
                    "pcie_gen_current": _get(gpu, "PCI", "GPU Link Info", "PCIe Generation", "Current"),
                    "pcie_gen_max": _get(gpu, "PCI", "GPU Link Info", "PCIe Generation", "Device Max"),
                    "width_current": _get(gpu, "PCI", "GPU Link Info", "Link Width", "Current"),
                    "width_max": _get(gpu, "PCI", "GPU Link Info", "Link Width", "Max")}
        d["performance_state"] = gpu.get("Performance State")
        d["clocks_event_reasons"] = gpu.get("Clocks Event Reasons")
        d["clocks_event_counters_us"] = parse_counters_us(gpu.get("Clocks Event Reasons Counters"))
        d["temperature"] = gpu.get("Temperature")
        d["power"] = gpu.get("GPU Power Readings")
        d["clocks"] = {"current": gpu.get("Clocks"), "applications": gpu.get("Applications Clocks"), "max": gpu.get("Max Clocks")}
        d["ecc_errors"] = gpu.get("ECC Errors")
        note = None
    cur, qerr = nvidia_smi_query(["clocks.sm", "clocks.max.sm", "clocks.applications.graphics", "pstate", "clocks_event_reasons.active"])
    d["clock_lock"] = {"note": "nvidia-smi exposes no 'locked clocks' query; a -lgc lock shows as the SM clock pinned at the cap under load. "
                               "stress records the cap it sets and restores (--restore-cap).", "query": cur, "error": qerr}
    return item(d.get("proc_version") is not None or d.get("driver_version") is not None, d, note=note)


def pci_config_read(bdf, off, size=4):
    """Read PCI config space bytes via sysfs (extended space needs root); setpci fallback.  Returns int or None."""
    p = "/sys/bus/pci/devices/%s/config" % bdf
    try:
        fd = os.open(p, os.O_RDONLY)
        try:
            raw = os.pread(fd, size, off)
        finally:
            os.close(fd)
        if len(raw) == size:
            return int.from_bytes(raw, "little")
    except OSError:
        pass
    rc, out, _ = run_cmd(["setpci", "-s", bdf, "%#x.%s" % (off, {1: "b", 2: "w", 4: "l"}[size])], timeout=10)
    if rc == 0 and out.strip():
        try:
            return int(out.strip().splitlines()[0], 16)
        except ValueError:
            return None
    return None


def decode_vsec_debug_sec(val, chip="GB20B"):
    bits = VSEC_DEBUG_SEC_BITS_GB20B if chip == "GB20B" else VSEC_DEBUG_SEC_BITS_GB10B
    fault = val & 0xFFFF
    iff = (val >> 16) & 0x7F
    names = [n for b, n in bits.items() if fault & (1 << b)]
    unknown = [b for b in range(16) if fault & (1 << b) and b not in bits]
    return {"raw": "0x%08x" % val, "fault_error": "0x%04x" % fault, "fault_bits": names, "unknown_bits": unknown,
            "iff_pos": iff, "sec_fault_latched": fault != 0, "note": "sticky until cold reset; VMON bits = on-die voltage monitor trips"}


def inv_pci(bdf):
    if not bdf:
        return item(False, note="no NVIDIA display-class PCI device found")
    base = "/sys/bus/pci/devices/%s/" % bdf
    d = {"bdf": bdf}
    for k in ("vendor", "device", "class", "revision", "subsystem_vendor", "subsystem_device", "current_link_speed",
              "current_link_width", "max_link_speed", "max_link_width", "numa_node", "enable", "d3cold_allowed", "power_state"):
        v = read_text(base + k)
        if v is not None:
            d[k] = v
    drv = base + "driver"
    d["driver"] = os.path.basename(os.readlink(drv)) if os.path.islink(drv) else None
    aer = {}
    for k in ("aer_dev_correctable", "aer_dev_nonfatal", "aer_dev_fatal"):
        v = read_text(base + k)
        if v:
            aer[k] = dict(re.findall(r"(\S+)\s+(\d+)", v))
    d["aer"] = aer or None
    cmd = pci_config_read(bdf, 0x04, 2)
    d["command"] = "0x%04x" % cmd if cmd is not None else None
    d["memory_space_enabled"] = bool(cmd & 0x2) if cmd is not None else None
    try:
        d["resource0_size"] = os.stat(base + "resource0").st_size
    except OSError:
        d["resource0_size"] = None
    rc, out, _ = run_cmd(["lspci", "-nn", "-vvv", "-s", bdf], timeout=15)
    if rc == 0:
        for key in ("DevSta", "LnkSta", "UESta", "CESta", "LnkCap"):
            m = re.search(r"^\s*%s:\s*(.*)$" % key, out, re.M)
            if m:
                d["lspci_" + key] = m.group(1).strip()
        d["lspci_header"] = out.splitlines()[0] if out else None
    return item(True, d)


def inv_acpi():
    tdir = "/sys/firmware/acpi/tables"
    names = []
    try:
        names = sorted(n for n in os.listdir(tdir) if os.path.isfile(os.path.join(tdir, n)))
    except OSError:
        return item(False, note="%s not listable" % tdir)
    d = {"tables": names, "bert_present": "BERT" in names, "hest_present": "HEST" in names, "erst_present": "ERST" in names}
    if is_root():
        d["sha256"] = {n: sha256_file(os.path.join(tdir, n)) for n in names}
        return item(True, d)
    return item(True, d, note="table hashes skipped: needs root")


def inv_thermal():
    zones = []
    for z in sorted(glob.glob("/sys/class/thermal/thermal_zone*"), key=lambda p: int(p.rsplit("zone", 1)[1])):
        name = os.path.basename(z)
        path = read_text(z + "/device/path")
        acpi = path.rsplit(".", 1)[-1] if path else None
        zd = {"zone": name, "type": read_text(z + "/type"), "acpi_path": path, "acpi_name": acpi,
              "spbm_field": ACPI_TZ_TO_SPBM.get(acpi) if acpi else None, "temp_mc": read_int(z + "/temp"),
              "trips": {}}
        for tp in sorted(glob.glob(z + "/trip_point_*_type")):
            idx = tp.rsplit("_", 2)[-2]
            zd["trips"][read_text(tp) or idx] = read_int(z + "/trip_point_%s_temp" % idx)
        if zd["spbm_field"] is None and zd["type"] == "acpitz" and not path:
            i = int(name[12:])
            if i < len(ACPI_TZ_INDEX_ORDER):
                zd["acpi_name_H"] = ACPI_TZ_INDEX_ORDER[i]
                zd["spbm_field"] = ACPI_TZ_TO_SPBM[ACPI_TZ_INDEX_ORDER[i]]
        zones.append(zd)
    cds = []
    for c in sorted(glob.glob("/sys/class/thermal/cooling_device*")):
        cds.append({"dev": os.path.basename(c), "type": read_text(c + "/type"), "cur_state": read_int(c + "/cur_state"),
                    "max_state": read_int(c + "/max_state")})
    return item(bool(zones), {"zones": zones, "cooling_devices": cds}, note=None if zones else "no thermal zones")


def fan_state():
    """dgx_ec_fan_control driver state (hwmon dgx_ec_fan + cooling device dgx_ec_fan_floor) and the userspace daemon."""
    d = {"module_loaded": os.path.isdir("/sys/module/dgx_ec_fan_control"), "cli": shutil.which("dgx-fan-control"),
         "hwmon": None, "cooling_device": None, "service_active": None}
    for h in glob.glob("/sys/class/hwmon/hwmon*"):
        if read_text(h + "/name") == "dgx_ec_fan":
            d["hwmon"] = {"path": h, "fan1_rpm": read_int(h + "/fan1_input"), "fan2_rpm": read_int(h + "/fan2_input")}
    for c in glob.glob("/sys/class/thermal/cooling_device*"):
        if read_text(c + "/type") == "dgx_ec_fan_floor":
            d["cooling_device"] = {"path": c, "cur_state": read_int(c + "/cur_state"), "max_state": read_int(c + "/max_state")}
    rc, out, _ = run_cmd(["systemctl", "is-active", "dgx-fan-control"], timeout=10)
    d["service_active"] = out.strip() if rc in (0, 3) else None
    d["present"] = bool(d["module_loaded"] or d["hwmon"] or d["cooling_device"])
    return d


def inv_fan():
    d = fan_state()
    return item(d["present"], d, note=None if d["present"] else "fan driver (dgx_ec_fan_control) not present: factory EC fan curve")


def inv_nvme():
    devs = sorted(glob.glob("/dev/nvme*n1"))
    if not devs:
        return item(False, note="no NVMe namespaces")
    if shutil.which("nvme") is None:
        return item(False, {"devices": devs}, note="nvme-cli not installed (needed for unsafe_shutdowns/power_cycles)")
    if not is_root():
        return item(False, {"devices": devs}, note="skipped: needs root (nvme smart-log)")
    out = {}
    for dev in devs:
        rc, o, e = run_cmd(["nvme", "smart-log", dev, "-o", "json"], timeout=20)
        if rc == 0:
            try:
                j = json.loads(o)
                out[dev] = {k: j.get(k) for k in ("critical_warning", "temperature", "power_cycles", "power_on_hours",
                                                   "unsafe_shutdowns", "media_errors", "num_err_log_entries", "warning_temp_time",
                                                   "critical_comp_time") if k in j}
                continue
            except ValueError:
                pass
        rc, o, e = run_cmd(["nvme", "smart-log", dev], timeout=20)
        if rc == 0:
            out[dev] = {k.strip().lower().replace(" ", "_"): v.strip() for k, v in re.findall(r"^([A-Za-z_ ]+?)\s*:\s*(.+)$", o, re.M)}
        else:
            out[dev] = {"error": (e or o).strip()[:200]}
    return item(True, out)


_SHUTDOWN_RE = re.compile(r"Journal stopped|Reached target .*(Shutdown|Power-Off|Reboot|Halt)|systemd-shutdown|Shutting down\.|"
                          r"reboot: (Power down|Restarting)|Powering off|Stopped Journal Service|Finished .*Power-Off|"
                          r"Stopping .*Journal Service|Deactivated swap|Unmounting", re.I)


def list_boots():
    rc, out, _ = run_cmd(["journalctl", "--list-boots", "-o", "json", "--no-pager"], timeout=30)
    boots = []
    if rc == 0 and out.strip().startswith("["):
        try:
            for b in json.loads(out):
                boots.append({"index": b.get("index"), "boot_id": b.get("boot_id"),
                              "first": b.get("first_entry", 0) / 1e6, "last": b.get("last_entry", 0) / 1e6})
            return boots, None
        except ValueError:
            pass
    rc, out, err = run_cmd(["journalctl", "--list-boots", "--no-pager", "--utc"], timeout=30)
    if rc != 0:
        return [], (err or out).strip()[:200]
    return parse_list_boots_text(out), None


def parse_list_boots_text(out):
    """Text form of journalctl --list-boots (older systemd): 'IDX BOOTID DAY DATE TIME TZ DAY DATE TIME TZ'."""
    boots = []
    for line in out.splitlines():
        m = re.match(r"^\s*(-?\d+)\s+([0-9a-f]{32})\s+(\S+ \S+ \S+)(?: \S+)?\s+(\S+ \S+ \S+)", line)
        if not m:
            continue

        def ts(sv):
            try:
                return datetime.datetime.strptime(sv, "%a %Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()
            except ValueError:
                return None
        boots.append({"index": int(m.group(1)), "boot_id": m.group(2), "first": ts(m.group(3)), "last": ts(m.group(4))})
    return boots


def classify_boots(boots, check_last=12):
    """Mark boots whose journal does not end with a shutdown sequence (abrupt end = power loss / crash) and the
    gap to the next boot."""
    boots = sorted(boots, key=lambda b: b["index"])
    for i, b in enumerate(boots):
        nxt = boots[i + 1] if i + 1 < len(boots) else None
        b["gap_to_next_s"] = round(nxt["first"] - b["last"], 1) if nxt and b.get("last") and nxt.get("first") else None
        b["duration_s"] = round(b["last"] - b["first"], 1) if b.get("first") and b.get("last") else None
    current = boots[-1] if boots else None
    for b in boots[-check_last - 1:]:
        if b is current:
            b["clean_shutdown"] = None
            continue
        rc, out, _ = run_cmd(["journalctl", "-b", b["boot_id"], "-n", "40", "--no-pager", "-o", "short-iso", "--utc"], timeout=30)
        if rc != 0:
            b["clean_shutdown"] = None
            continue
        tail = out.strip().splitlines()
        b["clean_shutdown"] = bool(_SHUTDOWN_RE.search("\n".join(tail[-40:])))
        b["last_lines"] = [l[:200] for l in tail[-3:]]
    uncl = [b for b in boots if b.get("clean_shutdown") is False]
    return {"boots": boots, "unclean_count_checked": len(uncl), "checked": min(check_last, max(0, len(boots) - 1)),
            "unclean": [{"index": b["index"], "last": iso(b["last"]) if b.get("last") else None, "gap_to_next_s": b.get("gap_to_next_s")} for b in uncl]}


def inv_boots(check_last=12):
    boots, err = list_boots()
    if err or not boots:
        return item(False, note="journalctl --list-boots: %s" % (err or "no boots"))
    return item(True, classify_boots(boots, check_last))


def inv_fieldiag(mods_bin):
    d = {"root": FIELDIAG_ROOT, "installed": os.path.isdir(FIELDIAG_ROOT)}
    rc, out, _ = run_cmd(["dpkg-query", "-W", "-f=${Version}", "dgx-spark-fieldiag"], timeout=10)
    d["package_version"] = out.strip() if rc == 0 and out.strip() else None
    tgz = glob.glob(os.path.join(FIELDIAG_ROOT, "onediagfield.*.tgz"))
    d["onediag_release"] = [re.sub(r"^onediagfield\.|\.tgz$", "", os.path.basename(t)) for t in tgz]
    d["relnotes_head"] = (read_text(os.path.join(FIELDIAG_ROOT, "relnotes.txt")) or "")[:300] or None
    d["mods_binary"] = mods_bin
    d["mods_binary_present"] = os.path.isfile(mods_bin) if mods_bin else False
    d["blacklist_file"] = MODS_BLACKLIST
    d["blacklist_present"] = os.path.exists(MODS_BLACKLIST)
    d["blacklist_content"] = read_text(MODS_BLACKLIST) if d["blacklist_present"] else None
    d["mods_module_loaded"] = os.path.isdir("/sys/module/mods")
    d["dev_mods_present"] = os.path.exists("/dev/mods")
    d["nvidia_module_loaded"] = os.path.isdir("/sys/module/nvidia")
    runs = sorted(glob.glob(os.path.join(FIELDIAG_ROOT, "dgx", "logs-*")) + glob.glob(os.path.join(FIELDIAG_ROOT, "logs", "*", "logs-*")) + glob.glob(os.path.join(FIELDIAG_ROOT, "logs", "logs-*")))
    d["run_dirs"] = [os.path.relpath(r, FIELDIAG_ROOT) for r in runs]
    d["flightrec_dir"] = "/var/log/fieldiag-flightrec" if os.path.isdir("/var/log/fieldiag-flightrec") else None
    ok = d["installed"] or d["package_version"] is not None
    return item(ok, d, note=None if ok else "dgx-spark-fieldiag not installed")


def cdi_uvm_major(text):
    """Find the major number recorded for /dev/nvidia-uvm in a CDI spec (YAML or JSON) without a yaml module."""
    try:
        j = json.loads(text)
        for dev in j.get("devices", []) + [{"containerEdits": j.get("containerEdits", {})}]:
            for n in (dev.get("containerEdits") or {}).get("deviceNodes", []) or []:
                if n.get("path") == "/dev/nvidia-uvm":
                    return n.get("major"), "json"
        return None, "json"
    except ValueError:
        pass
    lines = text.splitlines()
    for i, l in enumerate(lines):
        if re.search(r"path:\s*/dev/nvidia-uvm\s*$", l):
            # the node's own fields follow (or precede) its path line; stop at the next/previous node's path
            for rng in (range(i + 1, min(len(lines), i + 8)), range(i - 1, max(-1, i - 8), -1)):
                for j in rng:
                    if re.search(r"\bpath:", lines[j]):
                        break
                    m = re.match(r"\s*-?\s*major:\s*(\d+)", lines[j])
                    if m:
                        return int(m.group(1)), "yaml"
            return None, "yaml"
    return None, "yaml"


def inv_cdi():
    specs = sorted(glob.glob("/etc/cdi/*.yaml") + glob.glob("/etc/cdi/*.json") + glob.glob("/var/run/cdi/*.yaml") + glob.glob("/var/run/cdi/*.json"))
    live = None
    for l in (read_text("/proc/devices") or "").splitlines():
        m = re.match(r"\s*(\d+)\s+nvidia-uvm\s*$", l)
        if m:
            live = int(m.group(1))
    node_major = None
    try:
        node_major = os.major(os.stat("/dev/nvidia-uvm").st_rdev)
    except OSError:
        pass
    d = {"spec_files": [], "live_major_proc_devices": live, "dev_node_major": node_major}
    stale = []
    for s in specs:
        txt = read_text(s, strip=False) or ""
        maj, fmt = cdi_uvm_major(txt)
        e = {"path": s, "format": fmt, "uvm_major_in_spec": maj}
        if maj is not None and live is not None and maj != live:
            e["stale"] = True
            stale.append(s)
        d["spec_files"].append(e)
    d["stale_specs"] = stale
    if not specs:
        return item(False, d, note="no CDI spec files (/etc/cdi, /var/run/cdi)")
    return item(True, d)


def inv_docker(image):
    rc, out, _ = run_cmd(["docker", "--version"], timeout=10)
    if rc != 0:
        return item(False, note="docker not available")
    d = {"version": out.strip()}
    rc, out, err = run_cmd(["docker", "image", "inspect", image, "--format", "{{.Id}} {{.Size}}"], timeout=20)
    d["image"] = image
    d["image_present"] = rc == 0
    d["image_id"] = out.strip() if rc == 0 else None
    return item(True, d)


def inv_mlx5():
    rc, out, _ = run_cmd(["journalctl", "-k", "-b", "--no-pager", "-g", "insufficient power|mlx5.*power", "-o", "short-iso"], timeout=30)
    if rc != 0:
        return item(False, note="journalctl unavailable")
    lines = [l[:200] for l in out.strip().splitlines() if l.strip() and not l.startswith("-- ")]
    return item(True, {"count": len(lines), "lines": lines[-10:]})


def collect_inventory(args):
    bdf = find_gpu_bdf(getattr(args, "bdf", None))
    inv = {"sparkdiag": {"version": VERSION, "build": BUILD}, "collected_at": iso(), "hostname": socket.gethostname(),
           "euid": os.geteuid(), "gpu_bdf": bdf, "items": {}}
    steps = [("dmi", inv_dmi), ("esrt", inv_esrt), ("fwupd", inv_fwupd), ("kernel", inv_kernel),
             ("nvidia", lambda: inv_nvidia(bdf)), ("pci", lambda: inv_pci(bdf)), ("acpi", inv_acpi),
             ("thermal", inv_thermal), ("fan", inv_fan), ("nvme", inv_nvme),
             ("boots", lambda: inv_boots(getattr(args, "boots", 12))),
             ("fieldiag", lambda: inv_fieldiag(getattr(args, "mods_bin", DEFAULT_MODS_BIN))), ("cdi", inv_cdi),
             ("docker", lambda: inv_docker(getattr(args, "image", DEFAULT_IMAGE))), ("mlx5_power", inv_mlx5)]
    for name, fn in steps:
        Log.debug("inventory: %s" % name)
        try:
            inv["items"][name] = fn()
        except Exception as e:  # a collector must never abort the run
            inv["items"][name] = item(False, note="collector error: %r" % e)
    return inv


# ----------------------------------------------------------------------------------------------------------------
# Forensics collectors
# ----------------------------------------------------------------------------------------------------------------

_RE_RMINIT = re.compile(r"RmInitAdapter failed!\s*\((0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+):(\d+)\)")
_RE_XID = re.compile(r"Xid \(([^)]+)\):\s*(\d+),\s*(.*)")
NVRM_GREP = r"NVRM|Xid|nvidia-nvswitch|GSP|SEC2|ksec2|GB20B|GB10B|SEC_FAULT|fallen off|RmInitAdapter|GPU has fallen|" \
            r"critical temperature|thermal_zone|BERT|Hardware Error|APEI|insufficient power|watchdog|NVDA8800|arm_ffa|FF-A|" \
            r"mods:|dgx-ec-fan|Emergency|poweroff|orderly"


def decode_nvrm_line(line):
    out = {}
    m = _RE_RMINIT.search(line)
    if m:
        init, rm, ln = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3))
        out["rminit"] = {"initStatus": "0x%x" % init, "initStatus_name": RM_INIT_STATUS.get(init, "unknown"),
                         "rmStatus": "0x%x" % rm, "rmStatus_name": NV_STATUS.get(rm, "unknown"), "line": ln,
                         "line_hint": RM_INIT_LINE_HINTS.get(ln)}
    m = _RE_XID.search(line)
    if m:
        out["xid"] = {"pci": m.group(1), "code": int(m.group(2)), "text": m.group(3)[:160]}
    if "ksec2PrepareBootCommands_GB20B" in line or "SEC2 secure boot partition timed out" in line:
        out["sec2_boot_timeout_gb20b"] = True
    m = re.search(r"Check failed: (\S+) \((0x[0-9a-fA-F]+)\) returned from (\S+)", line)
    if m:
        out["check_failed"] = {"status": m.group(1), "code": m.group(2), "expr": m.group(3)}
    if "GPU_IN_FULLCHIP_RESET" in line:
        out["fullchip_reset_assert"] = True
    if re.search(r"critical temperature reached", line):
        out["acpi_critical_trip"] = True
    return out


def forensic_boot(boot_id, index, max_lines=400):
    """Grep one boot's journal for the interesting lines and keep its tail."""
    rc, out, _ = run_cmd(["journalctl", "-b", boot_id, "--no-pager", "-o", "short-iso", "--utc", "-g", NVRM_GREP], timeout=60)
    lines = [l[:300] for l in out.splitlines() if l.strip() and not l.startswith("-- ")] if rc == 0 else []
    decoded = []
    for l in lines:
        dec = decode_nvrm_line(l)
        if dec:
            decoded.append({"line": l, "decode": dec})
    rc, tail, _ = run_cmd(["journalctl", "-b", boot_id, "-n", "25", "--no-pager", "-o", "short-iso", "--utc"], timeout=30)
    tail_lines = [l[:300] for l in tail.splitlines() if not l.startswith("-- ")] if rc == 0 else []
    xids = [d["decode"]["xid"]["code"] for d in decoded if "xid" in d["decode"]]
    return {"boot_id": boot_id, "index": index, "matches": len(lines), "lines": lines[-max_lines:], "decoded": decoded[-80:],
            "tail": tail_lines, "clean_shutdown": bool(_SHUTDOWN_RE.search("\n".join(tail_lines))),
            "xids": sorted(set(xids)), "rminit_failures": [d["decode"]["rminit"] for d in decoded if "rminit" in d["decode"]],
            "sec2_timeout_seen": any(d["decode"].get("sec2_boot_timeout_gb20b") for d in decoded),
            "acpi_critical_trip": any(d["decode"].get("acpi_critical_trip") for d in decoded)}


def forensic_bert():
    d = {"bert_table": os.path.exists("/sys/firmware/acpi/tables/BERT"), "bert_data": os.path.exists("/sys/firmware/acpi/tables/data/BERT"),
         "hest_table": os.path.exists("/sys/firmware/acpi/tables/HEST"), "erst_table": os.path.exists("/sys/firmware/acpi/tables/ERST")}
    rc, out, _ = run_cmd(["journalctl", "-k", "-b", "--no-pager", "-g", "BERT|Hardware Error|APEI|GHES", "-o", "short-iso"], timeout=30)
    d["kernel_lines"] = [l[:300] for l in out.splitlines() if l.strip() and not l.startswith("-- ")][-40:] if rc == 0 else []
    if d["bert_data"] and is_root():
        try:
            with open("/sys/firmware/acpi/tables/data/BERT", "rb") as f:
                raw = f.read(4096)
            d["bert_data_hex_head"] = raw[:256].hex()
            d["bert_data_has_MTKID"] = b"MTKID" in raw
        except OSError as e:
            d["bert_data_error"] = str(e)
    return item(True, d)


def forensic_pstore():
    try:
        names = sorted(os.listdir("/sys/fs/pstore"))
    except OSError:
        return item(False, note="/sys/fs/pstore not available")
    files = []
    for n in names:
        p = os.path.join("/sys/fs/pstore", n)
        try:
            st = os.stat(p)
            e = {"name": n, "size": st.st_size, "mtime": iso(st.st_mtime)}
            if n.startswith(("dmesg", "console")):
                e["head"] = (read_text(p) or "")[:600]
            files.append(e)
        except OSError:
            pass
    return item(True, {"files": files, "count": len(files)})


def forensic_pci_cfg(bdf, chip="GB20B"):
    if not bdf:
        return item(False, note="no GPU PCI device")
    val = pci_config_read(bdf, VSEC_OFFSET, 4)
    if val is None:
        if not is_root():
            return needs_root("PCI config 0x2B4 is in extended config space")
        return item(False, note="cannot read config 0x2B4 (device off bus or CRS?)")
    d = {"vsec_debug_sec": decode_vsec_debug_sec(val, chip)}
    v0 = pci_config_read(bdf, 0x0, 4)
    d["vendor_device"] = "0x%08x" % v0 if v0 is not None else None
    d["all_ones"] = v0 == 0xFFFFFFFF
    return item(True, d)


def forensic_bar0(bdf, lockdown_mode, memory_space_enabled, force=False):
    """READ-ONLY BAR0 plan (gpu-boot/REPORT.md 5.1).  Requires root, lockdown none, Memory Space Enable set."""
    if not bdf:
        return item(False, note="no GPU PCI device")
    if not is_root():
        return needs_root("BAR0 mmap")
    if lockdown_mode not in (None, "none") and not force:
        return item(False, note="kernel lockdown=%s: BAR0 mmap is refused; nothing attempted" % lockdown_mode)
    if memory_space_enabled is False:
        return item(False, note="PCI COMMAND Memory Space Enable is clear: refusing to read BAR0 (enabling it is not read-only)")
    res = "/sys/bus/pci/devices/%s/resource0" % bdf
    need = max(off for off, _, _ in BAR0_PLAN) + 4
    reads = []
    stop = None
    try:
        fd = os.open(res, os.O_RDONLY | os.O_SYNC)
    except OSError as e:
        return item(False, note="open %s: %s" % (res, e))
    try:
        try:
            size = os.fstat(fd).st_size
            mm = mmap.mmap(fd, min(size, (need + 0xFFF) & ~0xFFF), mmap.MAP_SHARED, mmap.PROT_READ)
        except (OSError, ValueError) as e:
            return item(False, note="mmap BAR0: %s" % e)
        try:
            for off, name, meaning in BAR0_PLAN:
                if off + 4 > len(mm):
                    reads.append({"offset": "0x%06x" % off, "name": name, "skipped": "beyond mapped size"})
                    continue
                v = struct.unpack_from("<I", mm, off)[0]
                e = {"offset": "0x%06x" % off, "name": name, "value": "0x%08x" % v, "meaning": meaning}
                if (v & 0xFFF00000) == 0xBAD00000:
                    e["pri_error"] = BAR0_PRI_ERRORS.get(v >> 8, "PRI error") if v != BAR0_SCPM_DUMMY else "SCPM dummy (SEC_FAULT lockdown)"
                if off == 0x5E0:
                    e["decode"] = {"gfw_boot_complete": v == 0xFF, "progress_name_H": GFW_BOOT_PROGRESS.get(v & 0xFF)}
                if off == 0xA00:
                    arch, impl = (v >> 24) & 0x3F, (v >> 20) & 0xF
                    e["decode"] = {"arch": "0x%x" % arch, "impl": "0x%x" % impl,
                                   "chip": {(0x1A, 0xB): "GB10B", (0x1B, 0xB): "GB20B", (0x1B, 0xC): "GB20C"}.get((arch, impl), "?")}
                if off == 0x2B4 // 1:  # never (config space); kept for clarity
                    pass
                reads.append(e)
                if off == 0x0 and v == 0xFFFFFFFF:
                    stop = "NV_PMC_BOOT_0 == 0xFFFFFFFF: device off the bus; stopped"
                    break
                if off == 0x0 and v == BAR0_SCPM_DUMMY:
                    stop = "NV_PMC_BOOT_0 == 0xBADF0200: SEC_FAULT lockdown, every read returns the dummy; stopped"
                    break
        finally:
            mm.close()
    finally:
        os.close(fd)
    return item(True, {"reads": reads, "stopped": stop, "plan_note": "one aligned 32-bit read per register, no writes; excluded ports never touched"})


def discover_mods_runs(extra_roots):
    roots = [os.path.join(FIELDIAG_ROOT, "dgx"), os.path.join(FIELDIAG_ROOT, "logs")] + list(extra_roots or [])
    found = []
    for r in roots:
        if not os.path.isdir(r):
            continue
        if re.match(r"^logs-\d{8}-\d{6}$", os.path.basename(r)):
            found.append(r)
        for depth in ("logs-*", "*/logs-*", "*/*/logs-*"):
            found += [d for d in glob.glob(os.path.join(r, depth)) if os.path.isdir(d)]
    seen = set()
    out = []
    for d in sorted(found):
        rp = os.path.realpath(d)
        if rp not in seen:
            seen.add(rp)
            out.append(d)
    return out


def analyze_mods_rundir(d, keyring, decode_dir=None):
    """One fieldiag run directory (logs-YYYYMMDD-HHMMSS): wrapper status files + decoded MODS logs."""
    r = {"dir": d, "name": os.path.basename(d)}
    ts = load_json(os.path.join(d, "test_status.log"), [])
    r["tests"] = [{"name": t.get("name"), "start": t.get("startTime"), "end": t.get("endTime"), "duration_s": t.get("durationInSecs")} for t in ts] if isinstance(ts, list) else []
    r["unfinished_tests"] = [t["name"] for t in r["tests"] if not t.get("end")]
    us = load_json(os.path.join(d, "unified_summary.json"), {})
    ri = (us or {}).get("runInfo", {})
    r["diag_version"] = ri.get("diagVersion")
    r["final_result"] = ri.get("finalResult")
    r["error_code"] = ri.get("errorCode")
    sm = load_json(os.path.join(d, "summary.json"), [])
    r["errors"] = [{"code": e.get("Error Code"), "test": e.get("Virtual ID"), "notes": e.get("Notes")} for e in sm] if isinstance(sm, list) else []
    runlog = read_text(os.path.join(d, "run.log")) or ""
    m = re.search(r"Serial Number\s+(\S+)", runlog)
    r["serial"] = m.group(1) if m else None
    m = re.search(r"^Version\s+(\S+)", runlog, re.M)
    r["onediag_version"] = m.group(1) if m else None
    r["wrapper_complete"] = "Final Result" in runlog
    r["truncated"] = bool(r["unfinished_tests"]) or (bool(runlog) and not r["wrapper_complete"])
    r["mods_files"] = []
    for p in sorted(glob.glob(os.path.join(d, "*", "fieldiag.log")) + glob.glob(os.path.join(d, "*", "fieldiag.mle"))):
        e = {"path": p, "size": os.path.getsize(p)}
        if e["size"] == 0:
            e.update(decoded=False, reason="empty file (0 bytes: written after the power loss, nothing flushed)")
            r["mods_files"].append(e)
            continue
        with open(p, "rb") as f:
            data = f.read()
        hdr = mods_parse_header(data)
        e["mods_version"] = hdr.get("version")
        e["arch"] = hdr.get("arch")
        if keyring is None:
            e.update(decoded=False, reason="MODS decoding disabled")
            r["mods_files"].append(e)
            continue
        dec = mods_decode(data, keyring)
        e["decoded"] = dec["ok"]
        if not dec["ok"]:
            e["reason"] = dec.get("reason")
            e["status"] = "MODS log present, not decoded"
            r["mods_files"].append(e)
            continue
        e["key_source"] = dec.get("key_source")
        pt = dec["plaintext"]
        if p.endswith(".log"):
            text = pt.decode("utf-8", "replace")
            e["summary"] = mods_log_summary(text)
            if decode_dir:
                outp = os.path.join(decode_dir, r["name"] + "-" + os.path.basename(os.path.dirname(p)) + "-fieldiag.log.txt")
                os.makedirs(decode_dir, exist_ok=True)
                with open(outp, "w") as f:
                    f.write(text)
                e["decoded_to"] = outp
        else:
            ents = mle_entries(pt)
            texts = [x["text"] for x in ents if x.get("text")]
            rcs = [{"rc": x["rc"], "strings": x["strings"][:3], "t": x.get("t")} for x in ents if x.get("rc") is not None]
            strings = [s for x in ents for s in x["strings"]]
            e["summary"] = {"entries": len(ents), "rc_records": rcs[:10], "t_first": ents[0].get("t") if ents else None,
                            "t_last": ents[-1].get("t") if ents else None,
                            "chip": next((s for s in strings if re.fullmatch(r"GB\d0[A-Z]", s)), None),
                            "last_text": texts[-8:], "boot_status": next((re.search(r"Boot status\s*=\s*(0x[0-9a-fA-F]+)", t).group(1) for t in texts if "Boot status" in t), None),
                            "tests": [re.match(_RE_MODS_TEST, t).group(2) for t in texts if _RE_MODS_TEST.match(t)]}
            if decode_dir:
                outp = os.path.join(decode_dir, r["name"] + "-" + os.path.basename(os.path.dirname(p)) + "-fieldiag.mle.bin")
                os.makedirs(decode_dir, exist_ok=True)
                with open(outp, "wb") as f:
                    f.write(pt)
                e["decoded_to"] = outp
        r["mods_files"].append(e)
    bs = [f["summary"].get("boot_status") for f in r["mods_files"] if f.get("summary") and f["summary"].get("boot_status")]
    r["boot_status"] = bs[0] if bs else None
    lt = [f["summary"].get("last_test") for f in r["mods_files"] if f.get("summary") and f["summary"].get("last_test")]
    r["last_mods_test"] = lt[-1] if lt else None
    return r


def collect_forensics(args, inventory=None):
    bdf = find_gpu_bdf(getattr(args, "bdf", None))
    kern = (inventory or {}).get("items", {}).get("kernel", {}).get("data") if inventory else None
    if kern is None:
        kern = inv_kernel()["data"]
    f = {"sparkdiag": {"version": VERSION, "build": BUILD}, "collected_at": iso(), "hostname": socket.gethostname(),
         "euid": os.geteuid(), "gpu_bdf": bdf, "lockdown_mode": kern.get("lockdown_mode"), "items": {}}
    try:
        boots, err = list_boots()
        if boots:
            cls = classify_boots(boots, getattr(args, "boots", 12))
            f["items"]["boots"] = item(True, cls)
            nprev = getattr(args, "prev_boots", 3)
            prev = []
            ordered = sorted(boots, key=lambda b: b["index"])
            for b in ordered[-(nprev + 1):-1]:
                prev.append(forensic_boot(b["boot_id"], b["index"]))
            prev.append(forensic_boot(ordered[-1]["boot_id"], ordered[-1]["index"]))
            f["items"]["journal"] = item(True, {"boots": prev})
        else:
            f["items"]["boots"] = item(False, note="journalctl: %s" % err)
    except Exception as e:
        f["items"]["boots"] = item(False, note="collector error: %r" % e)
    f["items"]["bert"] = forensic_bert()
    f["items"]["pstore"] = forensic_pstore()
    f["items"]["pci_cfg"] = forensic_pci_cfg(bdf)
    if getattr(args, "bar0", False):
        mse = None
        try:
            cmd = pci_config_read(bdf, 0x04, 2) if bdf else None
            mse = bool(cmd & 0x2) if cmd is not None else None
        except Exception:
            pass
        f["items"]["bar0"] = forensic_bar0(bdf, kern.get("lockdown_mode"), mse)
    else:
        f["items"]["bar0"] = item(False, note="not requested (pass --bar0; read-only plan, lockdown none + root required)")
    # MODS field-diag runs
    mods_bin = getattr(args, "mods_bin", DEFAULT_MODS_BIN)
    keyring = None
    kr_note = None
    if getattr(args, "no_mods_decode", False):
        kr_note = "MODS decoding disabled (--no-mods-decode)"
    else:
        keyring = ModsKeyring.from_binary(mods_bin)
        kr_note = "; ".join(keyring.notes)
        if MODS_KNOWN_KEYS:
            kr_note += "; embedded keys available for builds: %s" % ", ".join(sorted(MODS_KNOWN_KEYS))
    runs = discover_mods_runs(getattr(args, "mods_logs", None) or [])
    decode_dir = os.path.join(getattr(args, "out", "."), "mods-decoded") if getattr(args, "out", None) else None
    analyzed = []
    for d in runs[-int(getattr(args, "mods_max_runs", 30)):]:
        try:
            analyzed.append(analyze_mods_rundir(d, keyring, decode_dir))
        except Exception as e:
            analyzed.append({"dir": d, "error": repr(e)})
    f["items"]["mods"] = item(bool(runs), {"binary": mods_bin, "binary_present": os.path.isfile(mods_bin) if mods_bin else False,
                                           "binary_versions": keyring.binary_versions if keyring else [], "keyring_note": kr_note,
                                           "runs": analyzed, "run_count": len(runs)},
                              note=None if runs else "no fieldiag run directories found")
    fr_dir = getattr(args, "flightrec_dir", "/var/log/fieldiag-flightrec")
    frs = sorted(glob.glob(os.path.join(fr_dir, "flightrec-*.log")))[-3:] if fr_dir and os.path.isdir(fr_dir) else []
    f["items"]["flightrec"] = item(bool(frs), [{k: v for k, v in parse_flightrec(p).items() if k not in ("tel", "out")} for p in frs],
                                   note=None if frs else "no flight-recorder logs")
    return f


# ----------------------------------------------------------------------------------------------------------------
# Telemetry: NVML (ctypes), ACPI thermal zones, fans, SPBM, kmsg -> one crash-survivable record file
# ----------------------------------------------------------------------------------------------------------------

class _NvmlFieldValue(ctypes.Structure):
    _fields_ = [("fieldId", ctypes.c_uint), ("scopeId", ctypes.c_uint), ("timestamp", ctypes.c_longlong),
                ("latencyUsec", ctypes.c_longlong), ("valueType", ctypes.c_uint), ("nvmlReturn", ctypes.c_uint),
                ("value", ctypes.c_ulonglong)]


NVML_FI_DEV_POWER_AVERAGE = 185
NVML_FI_DEV_POWER_INSTANT = 186


class NvmlReader:
    """libnvidia-ml via ctypes.  Primary path uses the stable calls (PowerUsage, ClockInfo, Temperature); the
    field-value API (instant/average power) is an enhancement that is dropped if it does not validate."""

    def __init__(self, index=0):
        self.lib = ctypes.CDLL("libnvidia-ml.so.1")
        rc = self.lib.nvmlInit_v2()
        if rc != 0:
            raise OSError("nvmlInit_v2 failed: %d" % rc)
        self.h = ctypes.c_void_p()
        rc = self.lib.nvmlDeviceGetHandleByIndex_v2(ctypes.c_uint(index), ctypes.byref(self.h))
        if rc != 0:
            raise OSError("nvmlDeviceGetHandleByIndex_v2 failed: %d" % rc)
        self.evr_fn = None
        for name in ("nvmlDeviceGetCurrentClocksEventReasons", "nvmlDeviceGetCurrentClocksThrottleReasons"):
            if hasattr(self.lib, name):
                self.evr_fn = getattr(self.lib, name)
                break
        self.fields_ok = False
        self.mode = "nvml-ctypes"
        try:
            base = self._power_usage()
            fv = self._fields()
            if fv and fv.get("p_inst_mw") and base and 0.2 * base <= fv["p_inst_mw"] <= 5 * base:
                self.fields_ok = True
        except Exception:
            self.fields_ok = False

    def _power_usage(self):
        v = ctypes.c_uint()
        return v.value if self.lib.nvmlDeviceGetPowerUsage(self.h, ctypes.byref(v)) == 0 else None

    def _fields(self):
        arr = (_NvmlFieldValue * 2)()
        arr[0].fieldId = NVML_FI_DEV_POWER_INSTANT
        arr[1].fieldId = NVML_FI_DEV_POWER_AVERAGE
        if self.lib.nvmlDeviceGetFieldValues(self.h, ctypes.c_int(2), arr) != 0:
            return None
        out = {}
        for key, fv in (("p_inst_mw", arr[0]), ("p_avg_mw", arr[1])):
            if fv.nvmlReturn == 0 and fv.valueType in (1, 2, 3):
                out[key] = int(fv.value & 0xFFFFFFFF) if fv.valueType == 1 else int(fv.value)
        return out

    def read(self):
        d = {}
        if self.fields_ok:
            fv = self._fields() or {}
            d.update(fv)
        if "p_inst_mw" not in d:
            p = self._power_usage()
            d["p_inst_mw"] = p
            d.setdefault("p_avg_mw", None)
        v = ctypes.c_uint()
        d["sm_mhz"] = v.value if self.lib.nvmlDeviceGetClockInfo(self.h, ctypes.c_uint(1), ctypes.byref(v)) == 0 else None
        d["gpu_c"] = v.value if self.lib.nvmlDeviceGetTemperature(self.h, ctypes.c_uint(0), ctypes.byref(v)) == 0 else None
        if self.evr_fn:
            e = ctypes.c_ulonglong()
            if self.evr_fn(self.h, ctypes.byref(e)) == 0:
                d["evr"] = "0x%x" % e.value
        return d

    def close(self):
        try:
            self.lib.nvmlShutdown()
        except Exception:
            pass


class NvidiaSmiStream:
    """Fallback: nvidia-smi --query-gpu ... -lms N as a subprocess; the latest line is served to the sampler."""
    FIELDS = ["power.draw.instant", "power.draw.average", "clocks.sm", "temperature.gpu", "clocks_event_reasons.active"]

    def __init__(self, interval_ms):
        self.mode = "nvidia-smi-stream"
        self.latest = {}
        self.proc = subprocess.Popen(["nvidia-smi", "--query-gpu=" + ",".join(self.FIELDS), "--format=csv,noheader,nounits",
                                      "-lms", str(max(20, int(interval_ms)))], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != len(self.FIELDS):
                continue
            def num(x, scale=1.0):
                try:
                    return int(float(x) * scale)
                except ValueError:
                    return None
            self.latest = {"p_inst_mw": num(parts[0], 1000), "p_avg_mw": num(parts[1], 1000), "sm_mhz": num(parts[2]),
                           "gpu_c": num(parts[3]), "evr": parts[4] if parts[4].startswith("0x") else None}

    def read(self):
        return dict(self.latest)

    def close(self):
        try:
            self.proc.terminate()
        except OSError:
            pass


def open_gpu_reader(interval_ms):
    try:
        return NvmlReader()
    except Exception as e:
        Log.debug("NVML ctypes unavailable: %s" % e)
    if shutil.which("nvidia-smi"):
        try:
            return NvidiaSmiStream(interval_ms)
        except OSError:
            pass
    return None


class ThermalReader:
    def __init__(self):
        self.zones = []  # (key, path, acpi_name, spbm_field)
        for z in sorted(glob.glob("/sys/class/thermal/thermal_zone*"), key=lambda p: int(p.rsplit("zone", 1)[1])):
            path = read_text(z + "/device/path")
            acpi = path.rsplit(".", 1)[-1] if path else None
            self.zones.append((os.path.basename(z), z + "/temp", acpi, ACPI_TZ_TO_SPBM.get(acpi) if acpi else None))
        self.fans = []
        for h in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
            name = read_text(h + "/name") or "?"
            if name == "dgx_ec_fan":
                self.fans += [("fan%d" % i, "%s/fan%d_input" % (h, i)) for i in (1, 2) if os.path.exists("%s/fan%d_input" % (h, i))]
            else:
                for p in sorted(glob.glob(h + "/fan*_input")):
                    self.fans.append(("fan_%s_%s" % (name, os.path.basename(p)[:-6]), p))

    def describe(self):
        return {"zones": [{"zone": k, "acpi_name": a, "spbm_field": s} for k, _, a, s in self.zones],
                "fans": [k for k, _ in self.fans]}

    def read(self):
        d = {}
        for k, p, _, _ in self.zones:
            try:
                with open(p) as f:
                    d[k] = int(f.read())
            except (OSError, ValueError):
                pass
        for k, p in self.fans:
            try:
                with open(p) as f:
                    d[k] = int(f.read())
            except (OSError, ValueError):
                pass
        return d


class SpbmReader:
    """Read-only SPBM telemetry.  'devmem': /dev/mem opened O_RDONLY, PROT_READ mmap of the 4 KiB page (lockdown none).
    'acpi_call': \\_TZ.RREG <phys> through /proc/acpi/call (the DSDT's own 32-bit read gadget; needs the acpi_call
    module).  Nothing is ever written to the page."""

    def __init__(self, mode="auto", fields=None, lockdown_mode=None):
        for lo, hi, why in NEVER_TOUCH_PHYS:
            assert hi <= SPBM_BASE or lo >= SPBM_BASE + SPBM_SIZE, "SPBM page overlaps a never-touch range (%s)" % why
        self.fields = [SPBM_BY_NAME[n] for n in (fields or [f[0] for f in SPBM_FIELDS]) if n in SPBM_BY_NAME]
        self.mode = "off"
        self.note = None
        self.mm = None
        self.fd = None
        if mode == "off":
            self.note = "disabled"
            return
        if mode in ("auto", "devmem"):
            if lockdown_mode not in (None, "none"):
                self.note = "lockdown=%s: /dev/mem not usable" % lockdown_mode
            elif not is_root():
                self.note = "/dev/mem needs root"
            else:
                try:
                    self.fd = os.open("/dev/mem", os.O_RDONLY | os.O_SYNC)
                    self.mm = mmap.mmap(self.fd, SPBM_SIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=SPBM_BASE)
                    self.mode = "devmem"
                    return
                except (OSError, ValueError) as e:
                    self.note = "/dev/mem mmap failed: %s" % e
                    if self.fd is not None:
                        os.close(self.fd)
                        self.fd = None
        if mode in ("auto", "acpi_call"):
            if os.path.exists("/proc/acpi/call") and is_root():
                try:
                    v = self._acpi_read(SPBM_BASE + 0x818)
                    if v is not None:
                        self.mode = "acpi_call"
                        self.note = (self.note + "; " if self.note else "") + "using \\_TZ.RREG via /proc/acpi/call"
                        core = {"dc_in", "gpu", "soc_pkg", "sys_tot", "tj", "t_gpu", "prochot", "pl_lvl", "pid_win", "pl1_eff", "spl1_eff", "pl1_ec", "spl1_ec"}
                        self.fields = [f for f in self.fields if f[0] in core]
                        return
                except OSError as e:
                    self.note = (self.note + "; " if self.note else "") + "acpi_call failed: %s" % e
            else:
                self.note = (self.note + "; " if self.note else "") + "/proc/acpi/call absent (acpi_call module) or not root"
        self.note = self.note or "SPBM unavailable"

    def _acpi_read(self, phys):
        with open("/proc/acpi/call", "w") as f:
            f.write("\\_TZ.RREG 0x%08X" % phys)
        with open("/proc/acpi/call") as f:
            s = f.read().strip("\0 \n")
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.isdigit():
            return int(s)
        return None

    def read(self):
        d = {}
        if self.mode == "devmem":
            for name, off, _u, _a in self.fields:
                d["spbm_" + name] = struct.unpack_from("<I", self.mm, off)[0]
        elif self.mode == "acpi_call":
            for name, off, _u, _a in self.fields:
                try:
                    v = self._acpi_read(SPBM_BASE + off)
                except OSError:
                    v = None
                if v is not None:
                    d["spbm_" + name] = v
        return d

    def describe(self):
        return {"mode": self.mode, "note": self.note, "base": "0x%08X" % SPBM_BASE,
                "fields": {f[0]: {"offset": "0x%03X" % f[1], "unit": f[2], "acpi": f[3]} for f in self.fields}}

    def close(self):
        if self.mm is not None:
            self.mm.close()
        if self.fd is not None:
            os.close(self.fd)


class KmsgReader:
    def __init__(self):
        try:
            self.fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
            os.lseek(self.fd, 0, os.SEEK_END)
        except OSError:
            self.fd = None

    def drain(self):
        out = []
        if self.fd is None:
            return out
        while True:
            try:
                rec = os.read(self.fd, 8192)
            except BlockingIOError:
                break
            except OSError:
                continue
            if not rec:
                break
            out.append(rec.decode("utf-8", "replace").rstrip("\n"))
        return out


class Sampler:
    """Unified sampler thread.  Every interval: NVML + zones + fans + SPBM -> one TEL record (O_DSYNC), new kmsg
    lines -> KMSG records, clock-event counters (nvidia-smi -q -d PERFORMANCE) -> CTR records at counters_s,
    then os.sync() so every other writer's data is on disk too.  Thermal guard: abort when any zone or the GPU
    exceeds abort_c; hard_stop when it stays above for > hard_stop_s after the abort."""

    def __init__(self, path, interval_ms=20, spbm_mode="auto", udp=None, counters_s=1.0, abort_c=None, hard_stop_s=1.0,
                 tag=None, sync_every=1, lockdown_mode=None, spbm_fields=None, kmsg=True):
        self.w = SyncWriter(path, udp)
        self.interval = max(0.005, interval_ms / 1000.0)
        self.gpu = open_gpu_reader(interval_ms)
        self.thermal = ThermalReader()
        self.spbm = SpbmReader(spbm_mode, spbm_fields, lockdown_mode)
        self.kmsg = KmsgReader() if kmsg else None
        self.counters_s = counters_s
        self.abort_c = abort_c
        self.hard_stop_s = hard_stop_s
        self.sync_every = max(1, int(sync_every))
        self.stop_ev = threading.Event()
        self.abort = threading.Event()
        self.hard_stop = threading.Event()
        self.latest = {}
        self.latest_ctr = {}
        self.n = 0
        self.hot_since = None
        self.abort_cb = None
        self.hard_cb = None
        self.thread = None
        self.ctr_thread = None
        self.w.rec("HDR", tag=tag, sparkdiag=VERSION, build=BUILD, host=socket.gethostname(), interval_ms=interval_ms,
                   gpu_reader=self.gpu.mode if self.gpu else None, gpu_fields_api=getattr(self.gpu, "fields_ok", None),
                   thermal=self.thermal.describe(), spbm=self.spbm.describe(), kmsg=bool(self.kmsg and self.kmsg.fd is not None),
                   abort_c=abort_c, hard_stop_s=hard_stop_s, euid=os.geteuid())

    def describe(self):
        return {"gpu_reader": self.gpu.mode if self.gpu else "none", "spbm": self.spbm.mode, "spbm_note": self.spbm.note,
                "zones": len(self.thermal.zones), "fans": len(self.thermal.fans), "kmsg": bool(self.kmsg and self.kmsg.fd is not None)}

    def mark(self, **kw):
        self.w.rec("MARK", **kw)
        try:
            os.sync()
        except OSError:
            pass

    def start(self):
        self.thread = threading.Thread(target=self._loop, name="sampler", daemon=True)
        self.thread.start()
        if self.counters_s and shutil.which("nvidia-smi"):
            self.ctr_thread = threading.Thread(target=self._counters, name="counters", daemon=True)
            self.ctr_thread.start()
        return self

    def _loop(self):
        while not self.stop_ev.is_set():
            t0 = time.monotonic()
            d = {}
            if self.gpu:
                try:
                    d.update(self.gpu.read())
                except Exception as e:
                    d["nvml_err"] = str(e)[:80]
            d.update(self.thermal.read())
            try:
                d.update(self.spbm.read())
            except Exception as e:
                d["spbm_err"] = str(e)[:80]
            hot = max([v / 1000.0 for k, v in d.items() if k.startswith("thermal_zone")] + [float(d.get("gpu_c") or 0)] or [0.0])
            d["hot_c"] = round(hot, 1)
            if self.abort_c is not None:
                if hot > self.abort_c:
                    if not self.abort.is_set():
                        self.abort.set()
                        self.hot_since = t0
                        self.w.rec("ABORT", hot_c=hot, limit=self.abort_c)
                        if self.abort_cb:
                            try:
                                self.abort_cb(hot)
                            except Exception:
                                pass
                    elif self.hot_since and t0 - self.hot_since > self.hard_stop_s and not self.hard_stop.is_set():
                        self.hard_stop.set()
                        self.w.rec("HARDSTOP", hot_c=hot, limit=self.abort_c, after_s=round(t0 - self.hot_since, 2))
                        if self.hard_cb:
                            try:
                                self.hard_cb(hot)
                            except Exception:
                                pass
                else:
                    self.hot_since = None
            self.w.rec("TEL", **d)
            self.latest = d
            if self.kmsg:
                for line in self.kmsg.drain():
                    self.w.rec("KMSG", line=line[:400])
            self.n += 1
            if self.n % self.sync_every == 0:
                try:
                    os.sync()
                except OSError:
                    pass
            time.sleep(max(0.0, self.interval - (time.monotonic() - t0)))

    def _counters(self):
        while not self.stop_ev.is_set():
            t0 = time.monotonic()
            rc, out, _ = run_cmd(["nvidia-smi", "-q", "-d", "PERFORMANCE"], timeout=10)
            if rc == 0:
                q = parse_nvidia_smi_q(out)
                gpu = next((v for k, v in q.items() if k.startswith("GPU ")), {})
                ctr = parse_counters_us(gpu.get("Clocks Event Reasons Counters"))
                if ctr:
                    self.latest_ctr = ctr
                    self.w.rec("CTR", **{k.replace(" ", "_").lower(): v for k, v in ctr.items()})
            self.stop_ev.wait(max(0.2, self.counters_s - (time.monotonic() - t0)))

    def stop(self):
        self.stop_ev.set()
        if self.thread:
            self.thread.join(timeout=5)
        if self.ctr_thread:
            self.ctr_thread.join(timeout=12)
        self.w.rec("END", samples=self.n)
        try:
            os.sync()
        except OSError:
            pass
        if self.gpu:
            self.gpu.close()
        self.spbm.close()
        self.w.close()


def cmd_telemetry(args):
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "telemetry-%s-%s.log" % (utc_stamp(), args.tag or "tel"))
    kern = inv_kernel()["data"]
    udp = tuple(args.udp.split(":")) if args.udp else None
    s = Sampler(path, interval_ms=args.rate_ms, spbm_mode=args.spbm, udp=udp, counters_s=args.counters_s,
                abort_c=None, tag=args.tag, sync_every=args.sync_every, lockdown_mode=kern.get("lockdown_mode"))
    Log.info("telemetry -> %s  (%s)" % (path, json.dumps(s.describe())))
    s.start()
    t_end = time.monotonic() + args.seconds if args.seconds > 0 else None
    try:
        last_print = 0
        while t_end is None or time.monotonic() < t_end:
            time.sleep(0.2)
            if args.print_every and time.monotonic() - last_print >= args.print_every:
                last_print = time.monotonic()
                d = s.latest
                zones = " ".join("%s=%.1f" % (k[12:], v / 1000.0) for k, v in sorted(d.items()) if k.startswith("thermal_zone"))
                sp = ""
                if "spbm_dc_in" in d:
                    sp = " dc_in=%.1fW gpu=%.1fW tj=%.1fC" % (d["spbm_dc_in"] / 1000.0, d.get("spbm_gpu", 0) / 1000.0, d.get("spbm_tj", 0) / 10.0 - 273.15)
                Log.info("P=%.1fW sm=%s gpu=%sC z[%s] fans=%s/%s%s" % ((d.get("p_inst_mw") or 0) / 1000.0, d.get("sm_mhz"), d.get("gpu_c"),
                                                                  zones, d.get("fan1"), d.get("fan2"), sp))
    except KeyboardInterrupt:
        pass
    finally:
        s.stop()
    Log.info("telemetry stopped: %d samples in %s" % (s.n, path))
    return 0


# ----------------------------------------------------------------------------------------------------------------
# GPU-side load generator (runs inside the serving image or directly when cupy + pynvml import).  Derived from
# repro/khzload.py; the abort flag lives in host-mapped pinned memory so a host store reaches the running
# persistent kernel on its next poll (the original CuPy fill on another stream never did).
# ----------------------------------------------------------------------------------------------------------------

GPU_LOAD_SRC = r'''#!/usr/bin/env python3
"""sparkdiag GPU load generator: persistent bf16 tensor-core MMA square wave switched on %globaltimer.

    python3 sparkdiag_gpuload.py --tag NAME --on-us 100 --off-us 20 --seconds 10 [--ramp-ms 0] [--sm-frac 1.0]

--off-us 0 = continuous load.  --ramp-ms W: blocks join progressively over W ms (step vs ramp).  --sm-frac F:
only F of the blocks run (partial-load step).  Edges and (optionally) NVML/zone telemetry go to --out as
'KIND {json}' lines written O_DSYNC + os.sync().  Thermal guard: ABORT writes the abort flag (host-mapped pinned
memory, visible to the kernel within microseconds); if the sensors stay above the limit for --hard-stop-s the
process hard-exits (HARDSTOP), which destroys the CUDA context and kills the kernel.
"""
import argparse
import ctypes
import glob
import json
import os
import threading
import time

import cupy as cp
import pynvml

ap = argparse.ArgumentParser()
ap.add_argument("--tag", required=True)
ap.add_argument("--on-us", type=float, default=100)
ap.add_argument("--off-us", type=float, default=20)
ap.add_argument("--seconds", type=float, default=10)
ap.add_argument("--blocks-per-sm", type=int, default=2)
ap.add_argument("--warps", type=int, default=8)
ap.add_argument("--ramp-ms", type=float, default=0.0, help="blocks join progressively over this window (0 = instant step)")
ap.add_argument("--sm-frac", type=float, default=1.0, help="fraction of blocks that run load (partial-load step)")
ap.add_argument("--telemetry-ms", type=float, default=20)
ap.add_argument("--no-telemetry", action="store_true", help="edges only (the host sampler records telemetry)")
ap.add_argument("--abort-c", type=float, default=95.0)
ap.add_argument("--hard-stop-s", type=float, default=1.0)
ap.add_argument("--idle-s", type=float, default=1.5, help="idle baseline before the load starts")
ap.add_argument("--out", default="/rec")
args = ap.parse_args()

SRC = r"""
#include <mma.h>
#include <cuda_bf16.h>
using namespace nvcuda;
__device__ __forceinline__ unsigned long long gtime() {
    unsigned long long t; asm volatile("mov.u64 %0, %globaltimer;" : "=l"(t)); return t;
}
extern "C" __global__ void square(unsigned long long t_start, unsigned long long t_end,
                                  unsigned long long on_ns, unsigned long long period_ns,
                                  volatile int *abort_flag, float *sink, const unsigned short *rnd,
                                  unsigned long long ramp_ns, unsigned int active_blocks) {
    __shared__ __align__(32) unsigned short tiles[16][256];
    for (int i = threadIdx.x; i < 16 * 256; i += blockDim.x)
        tiles[i / 256][i % 256] = rnd[(blockIdx.x * 4096 + i) % (1 << 20)];
    __syncthreads();
    wmma::fragment<wmma::matrix_a, 16, 16, 16, __nv_bfloat16, wmma::row_major> a;
    wmma::fragment<wmma::matrix_b, 16, 16, 16, __nv_bfloat16, wmma::col_major> b;
    wmma::fragment<wmma::accumulator, 16, 16, 16, float> c[8];
    #pragma unroll
    for (int j = 0; j < 8; ++j) wmma::fill_fragment(c[j], 0.0f);
    int warp = threadIdx.x / 32;
    if (blockIdx.x >= active_blocks) return;  // partial-load step: inactive blocks exit at once
    unsigned long long my_start = t_start + (ramp_ns * blockIdx.x) / active_blocks;  // staggered join for a ramp
    while (gtime() < my_start) { if (*abort_flag) return; __nanosleep(1000); }
    unsigned int iter = 0;
    for (;;) {
        unsigned long long now = gtime();
        if (now >= t_end) break;
        if ((iter++ & 255) == 0 && *abort_flag) break;   // abort_flag is host-mapped pinned memory
        unsigned long long phase = (now - t_start) % period_ns;
        if (phase < on_ns) {
            #pragma unroll
            for (int k = 0; k < 8; ++k) {
                int t = (k + warp + iter) & 7;
                wmma::load_matrix_sync(a, (const __nv_bfloat16 *)tiles[t], 16);
                wmma::load_matrix_sync(b, (const __nv_bfloat16 *)tiles[8 + ((t * 3 + 1) & 7)], 16);
                #pragma unroll
                for (int j = 0; j < 8; ++j) wmma::mma_sync(c[j], a, b, c[j]);
            }
        } else {
            unsigned long long left = period_ns - phase;
            __nanosleep(left > 1000000ull ? 1000000u : (unsigned int)left);
        }
    }
    float acc = 0.0f;
    #pragma unroll
    for (int j = 0; j < 8; ++j) acc += c[j].x[0];
    if (acc == 12345.0f) sink[blockIdx.x] = acc;
}
"""

os.makedirs(args.out, exist_ok=True)
path = os.path.join(args.out, "%s-%s.log" % (time.strftime("%Y%m%d-%H%M%S", time.gmtime()), args.tag))
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_DSYNC, 0o644)
try:
    dfd = os.open(args.out, os.O_RDONLY)
    os.fsync(dfd)
    os.close(dfd)
except OSError:
    pass
lock = threading.Lock()


def rec(kind, **kw):
    kw.update(t=round(time.time(), 4), m=round(time.monotonic(), 4))
    with lock:
        os.write(fd, ("%s %s\n" % (kind, json.dumps(kw, separators=(",", ":")))).encode())


# --- abort flag in host-mapped pinned memory ---------------------------------------------------------------------
HOST_ALLOC_MAPPED = 2  # cudaHostAllocMapped
flag_host = cp.cuda.runtime.hostAlloc(4, HOST_ALLOC_MAPPED)
def _mapped_device_ptr(host_ptr):
    """Device address of a cudaHostAllocMapped buffer. CuPy 14 does not wrap cudaHostGetDevicePointer; on devices with
    unified addressing (all 64-bit CUDA, incl. GB10) the mapped device address equals the host address; otherwise call
    libcudart through ctypes."""
    fn = getattr(cp.cuda.runtime, "hostGetDevicePointer", None)
    if fn is not None:
        return int(fn(host_ptr, 0))
    if cp.cuda.runtime.deviceGetAttribute(cp.cuda.runtime.cudaDevAttrUnifiedAddressing, 0):
        return int(host_ptr)
    import ctypes.util
    lib = ctypes.CDLL(ctypes.util.find_library("cudart") or "libcudart.so")
    out = ctypes.c_void_p()
    rc = lib.cudaHostGetDevicePointer(ctypes.byref(out), ctypes.c_void_p(host_ptr), 0)
    if rc != 0:
        raise RuntimeError("cudaHostGetDevicePointer failed: %d" % rc)
    return int(out.value)


flag_dev = _mapped_device_ptr(flag_host)
flag = ctypes.c_int.from_address(flag_host)
flag.value = 0
_chk = cp.RawKernel(r"""extern "C" __global__ void chk(volatile int *f, int *o){ o[0] = *f; }""", "chk")
_o = cp.zeros(1, dtype=cp.int32)
flag.value = 7
_chk((1,), (1,), (cp.uint64(flag_dev), _o))
cp.cuda.runtime.deviceSynchronize()
MAPPED_OK = int(_o.get()[0]) == 7
flag.value = 0
rec("FLAGCHECK", mapped=MAPPED_OK, host_ptr=hex(flag_host), dev_ptr=hex(flag_dev))
if not MAPPED_OK:
    rec("END", error="abort flag not visible through mapped memory; refusing to run without a working guard")
    os.close(fd)
    print(path)
    raise SystemExit(4)


def set_abort():
    flag.value = 1   # plain host store; the kernel polls the mapped word every 256 iterations


SENS = [(os.path.basename(z), os.path.join(z, "temp")) for z in sorted(glob.glob("/sys/class/thermal/thermal_zone*"))]
for h in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
    try:
        if open(os.path.join(h, "name")).read().strip() == "dgx_ec_fan":
            SENS += [("fan%d" % i, os.path.join(h, "fan%d_input" % i)) for i in (1, 2)]
    except OSError:
        pass
pynvml.nvmlInit()
NVH = pynvml.nvmlDeviceGetHandleByIndex(0)
FIELDS = [pynvml.NVML_FI_DEV_POWER_INSTANT, pynvml.NVML_FI_DEV_POWER_AVERAGE]
stop = threading.Event()
abort_host = threading.Event()
hot_since = [None]


def telemetry():
    while not stop.is_set():
        t0 = time.monotonic()
        d = {}
        try:
            fv = pynvml.nvmlDeviceGetFieldValues(NVH, FIELDS)
            d["p_inst_mw"] = fv[0].value.uiVal if fv[0].nvmlReturn == 0 else None
            d["p_avg_mw"] = fv[1].value.uiVal if fv[1].nvmlReturn == 0 else None
            d["sm_mhz"] = pynvml.nvmlDeviceGetClockInfo(NVH, pynvml.NVML_CLOCK_SM)
            d["gpu_c"] = pynvml.nvmlDeviceGetTemperature(NVH, pynvml.NVML_TEMPERATURE_GPU)
        except pynvml.NVMLError as e:
            d["nvml_err"] = str(e)
        for k, p in SENS:
            try:
                d[k] = int(open(p).read())
            except (OSError, ValueError):
                pass
        hot = max([v / 1000 for k, v in d.items() if k.startswith("thermal_zone")] + [d.get("gpu_c") or 0])
        if hot > args.abort_c:
            if not abort_host.is_set():
                abort_host.set()
                hot_since[0] = t0
                set_abort()
                rec("ABORT", hot_c=hot, limit=args.abort_c)
            elif hot_since[0] is not None and t0 - hot_since[0] > args.hard_stop_s:
                rec("HARDSTOP", hot_c=hot, limit=args.abort_c, after_s=round(t0 - hot_since[0], 2))
                try:
                    os.sync()
                except OSError:
                    pass
                os._exit(3)   # second layer: kill the process (and with it the CUDA context and the kernel)
        else:
            hot_since[0] = None
        if not args.no_telemetry:
            rec("TEL", **d)
        try:
            os.sync()
        except OSError:
            pass
        time.sleep(max(0.0, args.telemetry_ms / 1000 - (time.monotonic() - t0)))


mod = cp.RawModule(code=SRC, options=("--std=c++17",), name_expressions=["square"])
kern = mod.get_function("square")
sms = cp.cuda.Device(0).attributes["MultiProcessorCount"]
blocks = sms * args.blocks_per_sm
active_blocks = max(1, int(round(blocks * args.sm_frac)))
sink = cp.zeros(blocks, dtype=cp.float32)
rnd = (cp.random.randint(0, 1 << 16, size=1 << 20, dtype=cp.uint32) & 0x807F | (cp.random.randint(0x70, 0x88, size=1 << 20, dtype=cp.uint32) << 7)).astype(cp.uint16)
gt = cp.RawKernel(r"""extern "C" __global__ void g(unsigned long long *o){unsigned long long t;
  asm volatile("mov.u64 %0, %globaltimer;" : "=l"(t)); o[0]=t;}""", "g")
o = cp.zeros(1, dtype=cp.uint64)
gt((1,), (1,), (o,))
cp.cuda.runtime.deviceSynchronize()
g0 = int(o.get()[0])
on_ns = int(args.on_us * 1000)
period_ns = int((args.on_us + args.off_us) * 1000)
t_start = g0 + int(args.idle_s * 1e9)
t_end = t_start + int(args.seconds * 1e9)
rec("START", tag=args.tag, warps=args.warps, ramp_ms=args.ramp_ms, sm_frac=args.sm_frac, on_us=args.on_us, off_us=args.off_us,
    seconds=args.seconds, sms=sms, blocks=blocks, active_blocks=active_blocks, idle_s=args.idle_s,
    period_us=period_ns / 1000, freq_khz=round(1e6 / period_ns, 3), duty=round(on_ns / period_ns, 4), abort_flag="host-mapped")
threading.Thread(target=telemetry, daemon=True).start()
stream = cp.cuda.Stream(non_blocking=True)
with stream:
    kern((blocks,), (32 * args.warps,), (cp.uint64(t_start), cp.uint64(t_end), cp.uint64(on_ns), cp.uint64(period_ns),
                                        cp.uint64(flag_dev), sink, rnd, cp.uint64(int(args.ramp_ms * 1e6)), cp.uint32(active_blocks)))
rec("LAUNCHED", load_start_in_s=args.idle_s)
stream.synchronize()
rec("DONE", aborted=abort_host.is_set())
stop.set()
time.sleep(args.telemetry_ms / 1000 * 3)
rec("END")
os.close(fd)
cp.cuda.runtime.freeHost(flag_host)
print(path)
'''

STRESS_PATTERNS = [("cont", 100, 0), ("10ms", 10000, 10000), ("1ms", 1000, 1000), ("100-100", 100, 100), ("100-20", 100, 20)]
CONSENT_FLAG = "--i-understand-this-can-power-off-the-node"


def build_plan(args):
    """Experiment plan: list of step dicts.  Every step is one GPU-load run with its own record + telemetry marks."""
    exps = [e.strip() for e in args.experiments.split(",") if e.strip()]
    caps = [int(c) for c in str(args.caps).split(",") if c.strip()] if args.caps else [1200, 1500, 1800, 2100]
    cap1 = int(args.cap) if args.cap else 2400
    steps = []

    def add(exp, cap, pattern, on_us, off_us, seconds, ramp_ms=0.0, sm_frac=1.0, note=""):
        sid = "%02d-%s-%s-%s" % (len(steps) + 1, exp, "uncapped" if cap in (0, None, 3003) else cap, pattern)
        if ramp_ms:
            sid += "-ramp%g" % ramp_ms
        if sm_frac != 1.0:
            sid += "-sm%d" % round(sm_frac * 100)
        steps.append({"id": sid, "experiment": exp, "cap": cap, "pattern": pattern, "on_us": on_us, "off_us": off_us,
                      "seconds": seconds, "ramp_ms": ramp_ms, "sm_frac": sm_frac, "note": note, "status": "pending"})

    for exp in exps:
        if exp == "thermal":
            for cap in caps:
                add("thermal", cap, pattern_name(100, 0, args.sustain_s), 100, 0, args.sustain_s, note="thermal step response, continuous")
                add("thermal", cap, pattern_name(3_000_000, 7_000_000), 3_000_000, 7_000_000, 30, note="3 s on / 7 s off pulses")
        elif exp == "sweep":
            for cap in caps:
                for name, on, off in STRESS_PATTERNS:
                    add("sweep", cap, pattern_name(on, off, args.seconds), on, off, args.seconds, note="transient sweep")
        elif exp == "killstep":
            for cap in ([cap1] if not args.kill_caps else [int(c) for c in args.kill_caps.split(",")]):
                add("killstep", cap, "cont", 100, 0, args.seconds, note="idle -> continuous full-GPU step")
        elif exp == "ramp":
            for r in (0, 50, 200, 1000):
                add("ramp", cap1, "cont", 100, 0, args.seconds, ramp_ms=float(r), note="step vs ramp (blocks join over the window)")
        elif exp == "partial":
            for f in (0.25, 0.5, 0.75, 1.0):
                add("partial", cap1, "cont", 100, 0, args.seconds, sm_frac=f, note="partial-load step")
        else:
            raise SystemExit("unknown experiment %r (thermal, sweep, killstep, ramp, partial)" % exp)
    skip = set((args.skip_steps or "").split(",")) - {""}
    for s in steps:
        if s["id"] in skip or any(s["id"].startswith(k) for k in skip):
            s["status"] = "skipped"
    return steps


class GpuRunner:
    """Launch the GPU-side script directly (cupy + pynvml importable) or inside a docker image."""

    def __init__(self, mode, image, script_path, rec_dir):
        self.image = image
        self.script = script_path
        self.rec_dir = rec_dir
        self.mode = mode
        self.proc = None
        self.name = None
        if mode == "auto":
            rc, _, _ = run_cmd([sys.executable, "-c", "import cupy, pynvml"], timeout=60)
            self.mode = "direct" if rc == 0 else "docker"
        if self.mode == "docker":
            rc, _, _ = run_cmd(["docker", "image", "inspect", image], timeout=20)
            self.available = rc == 0
            self.note = "docker image %s %s" % (image, "present" if rc == 0 else "MISSING")
        else:
            self.available = True
            self.note = "direct python (%s)" % sys.executable

    def launch(self, step, abort_c, hard_stop_s, extra=()):
        tag = safe_tag(step["id"])  # step ids such as 'pulse3s/7s' become file names inside the GPU script
        a = ["--tag", tag, "--on-us", str(step["on_us"]), "--off-us", str(step["off_us"]), "--seconds", str(step["seconds"]),
             "--ramp-ms", str(step.get("ramp_ms", 0) or 0), "--sm-frac", str(step.get("sm_frac", 1.0)), "--abort-c", str(abort_c),
             "--hard-stop-s", str(hard_stop_s)] + list(extra)
        if self.mode == "docker":
            self.name = "sparkdiag-%s" % re.sub(r"[^A-Za-z0-9_.-]", "_", tag)
            cmd = ["docker", "run", "--rm", "--name", self.name, "--gpus", "all", "--ipc=host", "--network", "none",
                   "-v", "%s:/rec" % self.rec_dir, "-v", "%s:/sparkdiag_gpuload.py:ro" % self.script,
                   "--entrypoint", "python3", self.image, "/sparkdiag_gpuload.py", "--out", "/rec"] + a
        else:
            cmd = [sys.executable, "-I", self.script, "--out", self.rec_dir] + a
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return cmd

    def poll(self):
        return self.proc.poll() if self.proc else None

    def kill(self, hard=False):
        if self.mode == "docker" and self.name:
            run_cmd(["docker", "kill", self.name], timeout=20)
        if self.proc and self.proc.poll() is None:
            try:
                (self.proc.kill if hard else self.proc.terminate)()
            except OSError:
                pass

    def wait(self, timeout=None):
        try:
            out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, "", ""
        return self.proc.returncode, out, err


def set_clock_cap(cap):
    """nvidia-smi -lgc 0,<cap> or -rgc for uncapped/None.  Returns (ok, output)."""
    if cap in (None, 0, 3003, "none", "uncapped"):
        rc, out, err = run_cmd(["nvidia-smi", "-rgc"], timeout=30)
    else:
        rc, out, err = run_cmd(["nvidia-smi", "-lgc", "0,%d" % int(cap)], timeout=30)
    return rc == 0, (out + err).strip()[:200]


def journal_marker(text):
    run_cmd(["logger", "-t", PROG, text], timeout=5)
    run_cmd(["sync"], timeout=30)


class FanControl:
    """Fan floor through the dgx_ec_fan_control driver only (sysfs cooling device / dgx-fan-control CLI).  No EC
    traffic of our own."""

    def __init__(self, mode):
        self.mode = mode
        self.state = fan_state()
        self.cd = (self.state.get("cooling_device") or {}).get("path")
        self.service_was_active = self.state.get("service_active") == "active"
        self.prev_state = (self.state.get("cooling_device") or {}).get("cur_state")
        self.applied = None

    def apply(self):
        if self.mode == "keep" or not self.cd:
            self.applied = "keep (%s)" % ("no fan driver" if not self.cd else "unchanged")
            return self.applied
        if self.service_was_active:
            run_cmd(["systemctl", "stop", "dgx-fan-control"], timeout=40)
        target = (self.state["cooling_device"].get("max_state") or 12) if self.mode == "max" else 0
        self._write(target)
        self.applied = "%s -> cooling state %d" % (self.mode, target)
        return self.applied

    def _write(self, state):
        if self.state.get("cli"):
            rc, _, _ = run_cmd([self.state["cli"], "set-state", str(state)] if state else [self.state["cli"], "automatic"], timeout=20)
            if rc == 0:
                return
        try:
            with open(os.path.join(self.cd, "cur_state"), "w") as f:
                f.write("%d\n" % state)
        except OSError as e:
            Log.info("fan: cannot write cooling state: %s" % e)

    def restore(self):
        if self.mode == "keep" or not self.cd:
            return
        self._write(0)
        if self.service_was_active:
            run_cmd(["systemctl", "start", "dgx-fan-control"], timeout=40)


class StressSession:
    def __init__(self, args):
        self.args = args
        self.root = os.path.join(args.out, "stress")
        self.rec_dir = os.path.join(self.root, "rec")
        os.makedirs(self.rec_dir, exist_ok=True)
        self.state_path = os.path.join(self.root, "state.json")
        self.steps_log = os.path.join(self.root, "steps.log")
        self.script = os.path.join(self.root, "sparkdiag_gpuload.py")
        with open(self.script, "w") as f:
            f.write(GPU_LOAD_SRC)
        self.kern = inv_kernel()["data"]
        self.sampler = None
        self.runner = None
        self.fan = None

    def note(self, text):
        line = "%s %s\n" % (iso(), text)
        with open(self.steps_log, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        journal_marker(text)
        if self.sampler:
            self.sampler.mark(text=text)
        Log.info(text)

    def save_state(self, state):
        state["updated"] = iso()
        write_json_durable(self.state_path, state)

    def zone0_c(self):
        d = self.sampler.latest if self.sampler else {}
        v = d.get("thermal_zone0")
        if v is None:
            v = read_int("/sys/class/thermal/thermal_zone0/temp")
        return v / 1000.0 if v is not None else None

    def cool_down(self, below, timeout=180):
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            z = self.zone0_c()
            if z is None or z < below:
                return z
            time.sleep(2)
        return self.zone0_c()

    def run(self, state):
        a = self.args
        udp = tuple(a.udp.split(":")) if a.udp else None
        tel_path = os.path.join(self.root, "telemetry-%s.log" % utc_stamp())
        self.sampler = Sampler(tel_path, interval_ms=a.rate_ms, spbm_mode=a.spbm, udp=udp, counters_s=a.counters_s,
                               abort_c=a.abort_c, hard_stop_s=a.hard_stop_s, tag="stress", lockdown_mode=self.kern.get("lockdown_mode"))
        self.sampler.abort_cb = lambda hot: self.note("ABORT thermal guard hot=%.1fC > %.1fC: killing the GPU job" % (hot, a.abort_c)) or (self.runner and self.runner.kill())
        self.sampler.hard_cb = lambda hot: self.note("HARDSTOP still hot=%.1fC after %.1fs: hard kill" % (hot, a.hard_stop_s)) or (self.runner and self.runner.kill(hard=True))
        self.sampler.start()
        state["telemetry_file"] = tel_path
        state["sampler"] = self.sampler.describe()
        self.runner = GpuRunner(a.mode, a.image, self.script, self.rec_dir)
        state["runner"] = {"mode": self.runner.mode, "note": self.runner.note}
        if not self.runner.available:
            self.note("GPU runner unavailable: %s" % self.runner.note)
            state["status"] = "error"
            self.save_state(state)
            self.sampler.stop()
            return 2
        self.fan = FanControl(a.fan)
        state["fan"] = {"mode": a.fan, "before": self.fan.state.get("cooling_device"), "applied": self.fan.apply()}
        self.note("SESSION-START host=%s runner=%s fan=%s spbm=%s abort_c=%s restore_cap=%s" % (
            socket.gethostname(), self.runner.mode, state["fan"]["applied"], self.sampler.spbm.mode, a.abort_c, a.restore_cap))
        state["status"] = "running"
        self.save_state(state)
        rc_all = 0
        try:
            for step in state["plan"]:
                if step["status"] in ("done", "skipped", "died", "aborted"):
                    continue
                if self.sampler.hard_stop.is_set():
                    self.note("hard stop latched; not starting further steps")
                    break
                z = self.cool_down(a.cool_below, a.cool_timeout)
                ok, msg = set_clock_cap(step["cap"])
                step["cap_set"] = ok
                if not ok:
                    self.note("cannot set clock cap %s: %s" % (step["cap"], msg))
                    step["status"] = "error"
                    self.save_state(state)
                    rc_all = 2
                    continue
                time.sleep(1.0)
                self.sampler.abort.clear()
                self.sampler.hot_since = None
                step["status"] = "running"
                step["started"] = iso()
                step["z0_before_c"] = z
                state["current"] = step["id"]
                self.save_state(state)
                self.note("BEGIN step=%s cap=%s pattern=%s on_us=%s off_us=%s ramp_ms=%s sm_frac=%s seconds=%s z0=%s" % (
                    step["id"], step["cap"], step["pattern"], step["on_us"], step["off_us"], step["ramp_ms"], step["sm_frac"], step["seconds"], z))
                cmd = self.runner.launch(step, a.abort_c, a.hard_stop_s, extra=(["--no-telemetry"] if a.no_gpu_telemetry else []))
                step["cmd"] = " ".join(cmd)
                deadline = time.monotonic() + step["seconds"] + 90
                while self.runner.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.25)
                if self.runner.poll() is None:
                    self.note("step %s overran; killing" % step["id"])
                    self.runner.kill(hard=True)
                rc, out, err = self.runner.wait(timeout=30)
                step["rc"] = rc
                step["stdout_tail"] = (out or "")[-400:]
                step["stderr_tail"] = (err or "")[-600:]
                recs = sorted(glob.glob(os.path.join(self.rec_dir, "*-%s.log" % safe_tag(step["id"]))))
                step["record"] = recs[-1] if recs else None
                summ = None
                if step["record"]:
                    try:
                        summ = summarize_run(parse_record_file(step["record"]), node=socket.gethostname())
                    except Exception as e:
                        summ = {"error": repr(e)}
                step["summary"] = {k: summ.get(k) for k in ("ended", "aborted", "z0_base", "z0_peak", "z0_rise_1s", "z0_rise_5s", "z0_rise_30s",
                                                            "p_mean", "p_max", "sm_max", "plateau", "c_per_w_30s")} if summ else None
                step["status"] = "aborted" if (self.sampler.abort.is_set() or (summ and summ.get("aborted"))) else ("done" if rc == 0 else "error")
                step["ended"] = iso()
                state["current"] = None
                self.save_state(state)
                self.note("RESULT step=%s status=%s rc=%s summary=%s" % (step["id"], step["status"], rc, json.dumps(step["summary"], default=str)))
                if rc not in (0, None):
                    rc_all = 2
        except KeyboardInterrupt:
            self.note("interrupted by user")
            if self.runner:
                self.runner.kill(hard=True)
            rc_all = 130
        finally:
            ok, msg = set_clock_cap(a.restore_cap if a.restore_cap != "none" else None)
            self.note("restore clock cap=%s ok=%s %s" % (a.restore_cap, ok, msg))
            if self.fan:
                self.fan.restore()
                self.note("fan restored (mode was %s)" % a.fan)
            state["status"] = "finished" if rc_all == 0 else "finished-with-errors"
            state["current"] = None
            state["finished"] = iso()
            self.save_state(state)
            self.note("SESSION-END status=%s" % state["status"])
            self.sampler.stop()
        return rc_all


def preflight_stress(args):
    problems = []
    if os.geteuid() != 0:
        problems.append("stress needs root (nvidia-smi -lgc, /dev/mem, fan driver)")
    if not shutil.which("nvidia-smi"):
        problems.append("nvidia-smi not found")
    if not glob.glob("/sys/class/thermal/thermal_zone*"):
        problems.append("no thermal zones (thermal guard impossible)")
    rc, out, err = run_cmd(["nvidia-smi", "-L"], timeout=20)
    if rc != 0:
        problems.append("nvidia-smi -L failed: %s" % (err or out).strip()[:120])
    return problems


def cmd_stress(args):
    if not args.consent:
        Log.info("refusing: stress is DESTRUCTIVE (the characterised fault powers the node off). Re-run with %s" % CONSENT_FLAG)
        return 3
    plan = build_plan(args)
    if args.dry_run:
        print(json.dumps({"plan": plan, "out": args.out, "image": args.image, "mode": args.mode, "fan": args.fan,
                          "abort_c": args.abort_c, "restore_cap": args.restore_cap}, indent=1))
        return 0
    problems = preflight_stress(args)
    if problems:
        for p in problems:
            Log.info("preflight: %s" % p)
        return 2
    sess = StressSession(args)
    state = {"sparkdiag": VERSION, "build": BUILD, "host": socket.gethostname(), "created": iso(), "args": {k: v for k, v in vars(args).items() if k != "func"},
             "plan": plan, "status": "created", "current": None}
    sess.save_state(state)
    return sess.run(state)


def describe_resume(root):
    state = load_json(os.path.join(root, "stress", "state.json"))
    if not state:
        return None, "no stress/state.json under %s" % root
    info = {"status": state.get("status"), "host": state.get("host"), "created": state.get("created"), "updated": state.get("updated"),
            "steps_total": len(state.get("plan", [])), "steps_done": sum(1 for s in state.get("plan", []) if s["status"] == "done"),
            "running_step": None, "last_tel": None, "last_spbm": None, "last_marks": []}
    running = [s for s in state.get("plan", []) if s["status"] == "running"]
    if running:
        info["running_step"] = running[-1]
    tel = state.get("telemetry_file")
    if tel and os.path.exists(tel):
        rec = parse_record_file(tel)
        if rec and rec["tel"]:
            last = rec["tel"][-1]
            info["last_tel"] = last
            sp = {k: v for k, v in last.items() if k.startswith("spbm_")}
            if sp:
                info["last_spbm"] = {"dc_in_w": sp.get("spbm_dc_in", 0) / 1000.0, "gpu_w": sp.get("spbm_gpu", 0) / 1000.0,
                                     "tj_c": round(sp.get("spbm_tj", 0) / 10.0 - 273.15, 1) if sp.get("spbm_tj") else None,
                                     "prochot": sp.get("spbm_prochot"), "pl_lvl": sp.get("spbm_pl_lvl"), "pid_win": sp.get("spbm_pid_win")}
            info["last_marks"] = [v.get("text") for k, v in rec["events"] if k == "MARK"][-5:]
            info["telemetry_ended_cleanly"] = rec["ended"]
            info["last_tel_time"] = iso(last["t"]) if last.get("t") else None
    return state, info


def cmd_resume(args):
    state, info = describe_resume(args.out)
    if state is None:
        Log.info(info)
        return 2
    print(json.dumps(info, indent=1, default=str))
    if info["running_step"] and not info.get("telemetry_ended_cleanly", True):
        print("\n=> step %s was RUNNING when the records stop (power loss / crash): cap=%s pattern=%s ramp_ms=%s sm_frac=%s" % (
            info["running_step"]["id"], info["running_step"]["cap"], info["running_step"]["pattern"],
            info["running_step"]["ramp_ms"], info["running_step"]["sm_frac"]))
    if not args.cont:
        return 0
    if not args.consent:
        Log.info("refusing to continue the plan without %s" % CONSENT_FLAG)
        return 3
    for s in state["plan"]:
        if s["status"] == "running":
            s["status"] = "died"
            s["note_resume"] = "was running when the previous session ended abruptly; marked died, skipped on resume"
    ns = argparse.Namespace(**state["args"])
    ns.out = args.out
    ns.consent = True
    sess = StressSession(ns)
    state["resumed"] = iso()
    sess.save_state(state)
    return sess.run(state)


# ----------------------------------------------------------------------------------------------------------------
# Report / compare: ingest result directories, derive findings, render Markdown + JSON
# ----------------------------------------------------------------------------------------------------------------

def ingest_dir(d, label=None):
    b = {"label": label or os.path.basename(os.path.normpath(d)), "dir": d, "inventory": None, "forensics": None,
         "runs": [], "spbm": [], "step_logs": [], "flightrecs": [], "stress_state": None, "telemetry": [], "errors": [],
         "files": 0}
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in ("mods-decoded", "__pycache__")]
        for n in sorted(files):
            p = os.path.join(root, n)
            try:
                b["files"] += 1
                if n == "inventory.json":
                    b["inventory"] = load_json(p)
                elif n == "forensics.json":
                    b["forensics"] = load_json(p)
                elif n == "state.json" and os.path.basename(root) == "stress":
                    b["stress_state"] = load_json(p)
                elif n.startswith("spbm-") and n.endswith(".log"):
                    b["spbm"].append(parse_spbm_log(p))
                elif n.startswith(("sweep-", "killstep-")) or n == "steps.log":
                    b["step_logs"].append(parse_step_log(p))
                elif n.startswith("flightrec-") and n.endswith(".log"):
                    b["flightrecs"].append(parse_flightrec(p))
                elif n.endswith((".log", ".jsonl")) and os.path.getsize(p) > 0:
                    rec = parse_record_file(p)
                    if not rec:
                        continue
                    if rec["kind"] in ("khzload", "gpuload"):
                        b["runs"].append(summarize_run(rec, node=b["label"]))
                        b["runs"][-1]["_rec_tail"] = rec["tel"][-30:]
                    elif rec["kind"] == "sparkdiag":
                        sp = parse_spbm_log(p)
                        if sp["rows"]:
                            b["spbm"].append(sp)
                        ctr = [v for k, v in rec["events"] if k == "CTR"]
                        b["telemetry"].append({"path": p, "n_tel": len(rec["tel"]), "ended": rec["ended"], "ctr_first": ctr[0] if ctr else None,
                                               "ctr_last": ctr[-1] if ctr else None, "marks": [v.get("text") for k, v in rec["events"] if k == "MARK"][-20:],
                                               "aborts": [v for k, v in rec["events"] if k in ("ABORT", "HARDSTOP")],
                                               "kmsg": [v.get("line") for k, v in rec["events"] if k == "KMSG"][-30:]})
            except Exception as e:
                b["errors"].append("%s: %r" % (p, e))
    # attach step metadata from a sparkdiag stress plan
    if b["stress_state"]:
        meta = {s["id"]: s for s in b["stress_state"].get("plan", [])}
        for r in b["runs"]:
            m = meta.get(r.get("tag"))
            if m:
                r["cap"] = m.get("cap") if m.get("cap") not in (None, 0, 3003) else 3003
                r["experiment"] = m.get("experiment")
                r["step_status"] = m.get("status")
                if m.get("pattern"):
                    suffix = r["pattern"][r["pattern"].index("+"):] if r.get("pattern") and "+" in r["pattern"] else ""
                    r["pattern"] = m["pattern"] + suffix
    b["runs"].sort(key=lambda r: (r.get("t_start") or 0))
    return b


def find_spbm_for(b, t0, t1):
    for sp in b["spbm"]:
        if sp["t_first"] is not None and sp["t_first"] - 1 <= t0 and sp["t_last"] + 1 >= t0:
            return sp
    return None


def F(fid, severity, tag, title, evidence=None, nodes=None, detail=None):
    return {"id": fid, "severity": severity, "tag": tag, "title": title, "evidence": evidence or [], "nodes": nodes or [], "detail": detail}


def derive_findings(bundles, reference=None):
    findings = []
    all_runs = [r for b in bundles for r in b["runs"]]
    labels = [b["label"] for b in bundles]

    # --- heat path: cross-node comparison at equal power
    rows = compare_nodes(all_runs, reference)
    bad = {}
    for row in rows:
        # robust metrics only: per-watt rise at 5 s and C/W at 30 s for sustained runs, per-pulse rise for pulses
        # (the 1 s rise is excluded: a 0.3 C reference value makes any ratio meaningless)
        if row.get("pulse_rise"):
            ratios = [row.get("pulse_rise_ratio")]
        else:
            ratios = [row.get("rise_5s_per_w_ratio"), row.get("c_per_w_30s_ratio")]
        ratios = [r for r in ratios if r]
        if row["power_equal"] and ratios and max(ratios) >= 2.0:
            row["_ratio"] = max(ratios)
            bad.setdefault(row["node"], []).append(row)
    for node, rws in bad.items():
        ref = rws[0]["reference"]
        ev = []
        for r in sorted(rws, key=lambda x: (x["cap"], str(x["pattern"]))):
            if r.get("pulse_rise"):
                ev.append("[O] cap %s %s: %s zone0 rises +%s C per pulse vs %s +%s C (P %.1f vs %.1f W): %.1fx" % (
                    r["cap"], r["pattern"], node, r["pulse_rise"][0], ref, r["pulse_rise"][1], r["p_mean"][0] or 0, r["p_mean"][1] or 0, r["_ratio"]))
            else:
                part30 = ""
                if r["z0_rise_30s"][0] is not None and r["z0_rise_30s"][1] is not None:
                    part30 = ", +%s vs +%s C at 30 s (%s vs %s C/W)" % (r["z0_rise_30s"][0], r["z0_rise_30s"][1], r["c_per_w_30s"][0], r["c_per_w_30s"][1])
                ev.append("[O] cap %s %s: %s zone0 +%s C vs %s +%s C at 5 s%s (P %.1f vs %.1f W): %.1fx per watt" % (
                    r["cap"], r["pattern"], node, r["z0_rise_5s"][0], ref, r["z0_rise_5s"][1], part30, r["p_mean"][0] or 0, r["p_mean"][1] or 0, r["_ratio"]))
        rat = [r["_ratio"] for r in rws]
        ev.append("[C] zone0 (ACPI TSOC = SPBM PKG_TJ_MAX, the package hotspot = GPU) heats %.1f-%.1fx faster per watt on %s than on %s at the same cap, load, firmware and fan curve (%d cap/pattern groups)" % (min(rat), max(rat), node, ref, len(rws)))
        other = []
        for r in rws:
            a = next((x for x in all_runs if x["node"] == node and x["cap"] == r["cap"] and x["pattern"] == r["pattern"]), None)
            bb = next((x for x in all_runs if x["node"] == ref and x["cap"] == r["cap"] and x["pattern"] == r["pattern"]), None)
            if a and bb:
                for z in a.get("zones_peak", {}):
                    if z in ("thermal_zone0", "thermal_zone5"):
                        continue
                    if z in bb.get("zones_peak", {}) and a["zones_peak"][z] > bb["zones_peak"][z] + 4:
                        other.append("%s cap %s" % (z, r["cap"]))
        ev.append("[O] other zones (CPU clusters, SoC) on %s %s" % (node, "stay at or below the reference's values: the excess heating is local to the zone0/zone5 sensor" if not other else "also hotter: " + ", ".join(other)))
        ev.append("[H] a local heat-path fault at the GPU die (thermal interface / heatsink contact / vapor chamber at that spot), not fans, airflow, ambient or the power adapter")
        ev.append("[C] this is the primary diagnostic: hotspot rise per watt at a fixed clock lock versus a reference; a power-off that a cooling intervention (repaste) removes is thermal (compare --before/--after)")
        findings.append(F("heat-path", "critical", "[C]", "Localized heat-path fault on %s: zone0 rises %.1fx faster than %s at equal power (primary diagnostic)" % (node, max(rat), ref), ev, [node, ref]))
    if not bad:
        for b in bundles:
            cands = [r for r in b["runs"] if r.get("pattern") in ("sustain", "cont") and r.get("ended") and (r.get("c_per_w_30s") is not None or r.get("c_per_w_end") is not None) and (r.get("seconds") or 0) >= 20]
            worst = max(cands, key=lambda r: r.get("c_per_w_30s") if r.get("c_per_w_30s") is not None else r.get("c_per_w_end"), default=None)
            wv = (worst.get("c_per_w_30s") if worst and worst.get("c_per_w_30s") is not None else (worst or {}).get("c_per_w_end"))
            if worst and wv is not None and wv > REFERENCE_HEALTHY["zone0_c_per_w_30s_max"]:
                findings.append(F("heat-path-single", "warn", "[H]", "%s: zone0 heating %.2f C/W (sustained load) exceeds the healthy reference envelope (%.2f C/W at 30 s)" % (
                    b["label"], wv, REFERENCE_HEALTHY["zone0_c_per_w_30s_max"]),
                    ["[O] %s cap %s: zone0 %s -> %s C at %.1f W" % (worst["tag"], worst["cap"], worst["z0_base"], worst["z0_peak"], worst["p_mean"]),
                     "[H] reference = built-in healthy-unit envelope (0.30 C/W at 52 W); run a second unit for a direct comparison"], [b["label"]]))

    # --- power loss on a load step (+ SPBM window, PM state, Tj register cadence)
    heat_nodes = {n for f in findings if f["id"].startswith("heat-path") for n in f["nodes"][:1]}
    for b in bundles:
        deaths = [r for r in b["runs"] if r.get("died") and r.get("death")]
        if not deaths:
            continue
        survived = [r for r in b["runs"] if r.get("ended") and (r.get("p_max") or 0) > 40]
        for r in deaths:
            d = r["death"]
            ev = ["[O] %s cap %s %s: records stop %.3f s after the load step (NVML last: %.1f W, SM %s MHz, zone0 %s C, GPU %s C); no END record, no kernel message" % (
                r["tag"], r["cap"], r["pattern"], d["t_after_load_s"], d["p_last_w"], d["sm_last"], d["z0_last_c"], d["gpu_last_c"])]
            sp = find_spbm_for(b, r["load_start_t"] or r["t_start"], r["t_last"])
            st = spbm_step_analysis(sp, r["load_start_t"]) if sp and r.get("load_start_t") else None
            tj = d["z0_last_c"]
            thermal_excluded = False
            if st and st.get("log_ends_in_window") and st.get("last"):
                last = st["last"]
                tj = last["tj_c"] if last["tj_c"] is not None else tj
                ev.append("[O] SPBM (%s ms samples, O_DSYNC): DC input %.1f -> %.1f W, GPU rail %s W, SoC pkg %s W within %.0f ms of the step; last sample Tj register %s C, then the log stops (power lost before the next write)" % (
                    sp.get("interval_ms") or "?", st["idle_dc_in_w"], last["dc_in_w"], last["gpu_w"], last["soc_pkg_w"], st["ms_onset_to_last"], last["tj_c"]))
                pm = st.get("pm_state_last_5s", {})
                if pm and not pm.get("any_changed"):
                    vals = ", ".join("%s=%s" % (k, v["values"][0]) for k, v in pm.items() if isinstance(v, dict))
                    ev.append("[O] SPBM power-management state did not change before the cut (identical in every sample incl. the last): %s -- the platform power manager (SPBM/EC limits, PROCHOT, PID winner) never acted; the cut came from something faster and lower" % vals)
                cad = st.get("tj_cadence")
                if cad:
                    ev.append("[C] SPBM package-Tj register cadence (the word every ACPI zone reads): changes every ~%d ms median (p10 %d, p90 %d ms); it updated %d time(s) between the step and the cut" % (
                        cad["median_ms"], cad["p10_ms"], cad["p90_ms"], st.get("tj_updates_onset_to_last", 0)))
                if st.get("cut_within_2_tj_updates"):
                    ev.append("[C] THERMAL NOT EXCLUDED: the cut happened within ~2 Tj-register update intervals of the load step; the register is a filtered maximum of fixed sensor sites and cannot show an unsensed die region, which can rise tens of degrees within ~100 ms at ~95 W")
                else:
                    ev.append("[C] the Tj register updated several times before the cut, but it reports fixed sensor sites only: a local die hotspot is still not excluded")
                r["death"]["spbm"] = {k: v for k, v in st.items() if k != "table"}
                r["death"]["spbm_table"] = st["table"]
            elif sp and st and not st.get("onset_t"):
                ev.append("[O] an SPBM log covers this run but no load-step onset was detected in it (idle DC input %s W); the OS-visible temperatures update every ~0.25-0.5 s and cannot exclude a local die hotspot" % st.get("idle_dc_in_w"))
            elif sp and st:
                ev.append("[O] an SPBM log covers this run but does not stop inside the step window (last SPBM sample %s); the OS-visible temperatures cannot exclude a local die hotspot" % iso(st["last_t"]))
            else:
                ev.append("[O] no SPBM log covers this cut; the OS-visible temperatures update every ~0.25-0.5 s and cannot exclude a local die hotspot")
            lower = [x for x in survived if x.get("cap") and r.get("cap") and x["cap"] < r["cap"]]
            if lower:
                best = max(lower, key=lambda x: x.get("p_max") or 0)
                ev.append("[O] the same unit sustained NVML %.1f W (max) for %s s at cap %s (%s) and ended normally" % (best["p_max"], best.get("seconds"), best["cap"], best["pattern"]))
                sps = [spbm_run_stats(find_spbm_for(b, x["t_start"], x["t_last"]), x["t_start"], x["t_last"]) for x in lower if find_spbm_for(b, x["t_start"], x["t_last"])]
                sps = [x for x in sps if x and x.get("dc_in_max_w")]
                if sps:
                    mx = max(sps, key=lambda x: x["dc_in_max_w"])
                    ev.append("[O] SPBM at lower caps: DC input up to %.1f W, GPU rail %.1f W, Tj %.1f C sustained without a cut" % (mx["dc_in_max_w"], mx.get("gpu_max_w") or 0, mx.get("tj_max_c") or 0))
                ev.append("[C] the trigger depends on the clock operating point rather than on steady power: a higher V/F point means higher power density and leakage on the die")
            if b["label"] in heat_nodes:
                ev.append("[H] most consistent mechanism on this unit (it also shows the heat-path fault): the GB10 hardware thermal shutdown firing on a local GPU-die hotspot faster than any OS-visible sensor; alternative: GPU rail / PMIC protection. Discriminator: a cooling intervention (repaste) and the same steps again (compare --before/--after)")
            else:
                ev.append("[H] mechanisms consistent with the data: a hardware thermal shutdown on a local GPU-die hotspot (not visible to the package sensors), or GPU rail / PMIC protection; no OS-visible log is produced. Discriminators: hotspot rise per watt vs a reference (heat-path), a cooling intervention and re-test")
            findings.append(F("load-step-poweroff", "critical", "[O]", "%s: power lost within %s ms of a load step at cap %s MHz (Tj register %s C at the last sample%s)" % (
                b["label"], (st or {}).get("ms_onset_to_last", round(d["t_after_load_s"] * 1000)), r["cap"], tj,
                "; thermal not excluded" if (st or {}).get("cut_within_2_tj_updates", True) else ""), ev, [b["label"]]))

    # --- clock-band threshold, ramp, power/temperature spread
    for b in bundles:
        cb = clock_band_threshold(all_runs, b["label"])
        if cb.get("died_caps"):
            ev = []
            for cap, v in sorted(cb["survived_caps"].items()):
                ev.append("[O] survived cap %s: %d run(s), NVML max %.1f W, SM up to %s MHz (%s)" % (cap, v["n"], v["p_max"], v["sm_max"], ", ".join(v["patterns"])))
            for cap, v in sorted(cb["died_caps"].items()):
                ev.append("[O] died cap %s: %d run(s), GPU power at the cut %s W (SPBM rail where logged, else NVML), Tj %s C, SM %s MHz, %s s after load, ramps %s ms" % (
                    cap, v["n"], v["p_last"], v["z0_last"], v["sm"], v["t_after"], v["ramp"]))
            if cb.get("band"):
                title = "%s: load-step power-off depends on the clock operating point: survived <= %s MHz, died at >= %s MHz under load (V/F-dependent power density)" % (b["label"], cb["band"][0], cb["band"][1])
                ev.append("[C] every fatal run held %s+ MHz under load; every run at <= %s MHz survived full load: the trigger lies in that clock band" % (cb["band"][1], cb["band"][0]))
                ev.append("[C] a higher V/F point raises power density and leakage on the die; the clock dependence fits a local thermal trigger as well as an electrical limit and is not by itself proof of an electrical fault")
            elif cb.get("overlap"):
                title = "%s: deaths and survivals at the same cap %s (not a clean clock threshold)" % (b["label"], cb["overlap"])
            else:
                title = "%s: deaths at caps %s" % (b["label"], sorted(cb["died_caps"]))
            p_died = [p for v in cb["died_caps"].values() for p in v["p_last"]]
            p_surv = [v["p_max"] for v in cb["survived_caps"].values()]
            if p_died and p_surv and min(p_died) < max(p_surv):
                ev.append("[C] no single steady-power or package-temperature threshold explains it: deaths at %.0f-%.0f W while %.0f W survived at a lower cap; what the deaths share is the operating point. A higher V/F point raises power density and leakage on the die, which fits a local thermal trigger as well as an electrical limit: this is not by itself proof of an electrical fault" % (min(p_died), max(p_died), max(p_surv)))
            ramps = sorted({x for v in cb["died_caps"].values() for x in v["ramp"]})
            if len(ramps) > 1:
                ev.append("[O] ramping the load over %s ms did not prevent the trip (not a ms-scale slew-rate effect)" % ramps)
            findings.append(F("clock-band", "warn", "[C]", title, ev, [b["label"]]))

    # --- firmware thermal plateau
    heat_nodes = {n for f in findings if f["id"].startswith("heat-path") for n in f["nodes"][:1]}
    for b in bundles:
        pl = [r for r in b["runs"] if r.get("plateau") and r["plateau"]["seconds"] >= 3]
        if pl:
            r = max(pl, key=lambda x: x["plateau"]["seconds"])
            p = r["plateau"]
            interp = ("[H] on this unit (which also shows the heat-path fault) the loop is the same thermal fault seen at lower power density: it keeps the node alive at the plateau, while load steps at a higher V/F point cut power before the package sensors move (see load-step-poweroff)"
                      if b["label"] in heat_nodes else "[O] firmware thermal loop observed; cause not determined by this run alone (a healthy unit can reach it uncapped)")
            findings.append(F("thermal-plateau", "warn", "[O]", "%s: a firmware loop holds zone0 at ~%.1f C (%.1f-%.1f) below the 104.85 C ACPI _CRT; node did not power off" % (
                b["label"], p["z0_mean"], p["z0_min"], p["z0_max"]),
                ["[O] %s cap %s: %.1f s above 94 C, SM dithering %s-%s MHz, NVML %.1f-%.1f W, NVML GPU sensor max %s C" % (
                    r["tag"], r["cap"], p["seconds"], p["sm_min"], p["sm_max"], p["p_min"], p["p_max"], p["gpu_c_max"]),
                 interp,
                 "[O] the NVML GPU temperature (%s C) is a different, much cooler reading than the SPBM package hotspot" % p["gpu_c_max"]], [b["label"]]))

    # --- zone identity
    for b in bundles:
        fr = [r["zone0_eq_zone5_frac"] for r in b["runs"] if r.get("zone0_eq_zone5_frac") is not None and r.get("n_tel", 0) > 200]
        if fr and max(fr) >= 0.9:
            findings.append(F("zone-identity", "info", "[O]", "%s: thermal_zone0 and thermal_zone5 read identically in %.0f%% of samples (TSOC=PKG_TJ_MAX and TGPU=TEMP_GPU: the package hotspot is the GPU)" % (b["label"], 100 * max(fr)), [], [b["label"]]))

    # --- forensics-derived findings
    for b in bundles:
        fo = b.get("forensics") or {}
        it = fo.get("items", {})
        mods = (it.get("mods") or {}).get("data") or {}
        for run in mods.get("runs", []):
            bs = run.get("boot_status")
            if bs and int(bs, 16) != 0xFF:
                v = int(bs, 16)
                findings.append(F("gfw-boot-stall", "critical", "[O]", "%s: GFW boot stall -- MODS read NV_PMC_SCRATCH_RESET_PLUS_2 (BAR0 0x5e0) = %s, expected 0xFF (fieldiag run %s)" % (b["label"], bs, run["name"]),
                                  ["[O] MODS error %s = test 900 (Gpu.Initialize) rc 167 GFW_BOOT_FAILURE after the 16 s PollGFWBootCompleteMs at 10 Hz" % (run.get("error_code") or "900167"),
                                   "[H] 0x%02x = %s if FWSEC uses the PGC6 GFW_BOOT_PROGRESS encoding (stalled before the final 0xFF)" % (v & 0xFF, GFW_BOOT_PROGRESS.get(v & 0xFF, "unknown")),
                                   "[O] the nvidia driver fails the same register in ksec2WaitForSecureBoot_GB20B (4 s) -> RmInitAdapter failed (0x62:0x65:2028); only AC removal clears it"], [b["label"]]))
            if run.get("truncated") and run.get("unfinished_tests"):
                last = run.get("last_mods_test")
                nd = [f for f in run.get("mods_files", []) if f.get("decoded") is False and f.get("size", 0) > 0]
                findings.append(F("fieldiag-truncated", "warn", "[O]", "%s: fieldiag run %s ended abruptly during %s%s" % (
                    b["label"], run["name"], ", ".join(run["unfinished_tests"]), (" (last MODS test reached: %s)" % last) if last else ""),
                    (["[O] MODS logs present, not decoded: %s" % nd[0].get("reason")] if nd else []) +
                    [("[O] test started %s, no endTime recorded" % t["start"]) for t in run.get("tests", []) if not t.get("end")], [b["label"]]))
        for f in [x for r in mods.get("runs", []) for x in r.get("mods_files", []) if x.get("decoded") is False and x.get("size", 0) > 0 and x.get("mods_version")]:
            findings.append(F("mods-not-decoded", "info", "[O]", "%s: MODS log %s (build %s) present, not decoded" % (b["label"], os.path.relpath(f["path"], b["dir"]) if f["path"].startswith(b["dir"]) else f["path"], f.get("mods_version")), [f.get("reason") or ""], [b["label"]]))
            break
        jn = (it.get("journal") or {}).get("data") or {}
        for boot in jn.get("boots", []):
            for rm in boot.get("rminit_failures", []):
                findings.append(F("rminit", "critical", "[O]", "%s: boot %s: RmInitAdapter failed (%s:%s:%s) = %s / %s" % (
                    b["label"], boot["index"], rm["initStatus"], rm["rmStatus"], rm["line"], rm["initStatus_name"], rm["rmStatus_name"]),
                    [rm.get("line_hint") or "", "[O] SEC2 secure-boot timeout seen: %s" % boot.get("sec2_timeout_seen")], [b["label"]]))
            if boot.get("xids"):
                findings.append(F("xid", "warn", "[O]", "%s: boot %s logged Xid %s" % (b["label"], boot["index"], boot["xids"]), boot["lines"][-5:], [b["label"]]))
        pc = (it.get("pci_cfg") or {}).get("data") or {}
        vs = pc.get("vsec_debug_sec")
        if vs:
            if vs.get("sec_fault_latched"):
                findings.append(F("sec-fault", "critical", "[O]", "%s: SEC_FAULT latched in PCI cfg 0x2B4 = %s: %s (IFF pos %s)" % (b["label"], vs["raw"], ", ".join(vs["fault_bits"]) or "unknown bits", vs["iff_pos"]),
                                  ["[O] sticky until cold reset; VMON bits = on-die voltage-monitor trips on the GPC/GPM rails"], [b["label"]]))
            else:
                findings.append(F("sec-fault-clear", "info", "[O]", "%s: no SEC_FAULT latched (PCI cfg 0x2B4 = %s)" % (b["label"], vs["raw"]), [], [b["label"]]))
        b0 = (it.get("bar0") or {}).get("data") or {}
        for rd in b0.get("reads", []):
            if rd.get("offset") == "0x0005e0" and rd.get("decode") and not rd["decode"]["gfw_boot_complete"]:
                findings.append(F("gfw-boot-stall-bar0", "critical", "[O]", "%s: BAR0 0x5e0 = %s (GFW boot not complete; [H] stage %s)" % (b["label"], rd["value"], rd["decode"]["progress_name_H"]), [], [b["label"]]))
        bt = (it.get("bert") or {}).get("data") or {}
        if bt.get("bert_table") or bt.get("kernel_lines"):
            findings.append(F("bert", "warn", "[O]", "%s: BERT/APEI error record present on this boot" % b["label"], bt.get("kernel_lines", [])[:5] + (["[O] payload contains 'MTKID'"] if bt.get("bert_data_has_MTKID") else []), [b["label"]]))
        boots = ((it.get("boots") or (b.get("inventory") or {}).get("items", {}).get("boots") or {}).get("data")) or {}
        if boots.get("unclean"):
            findings.append(F("unclean-boots", "warn", "[O]", "%s: %d of the last %d boots ended without a shutdown sequence (abrupt power loss / crash)" % (
                b["label"], len(boots["unclean"]), boots.get("checked", 0)),
                ["[O] boot %s: journal ends %s, next boot %s s later" % (u["index"], u["last"], u["gap_to_next_s"]) for u in boots["unclean"][-8:]], [b["label"]]))
        for fr in ((it.get("flightrec") or {}).get("data") or []):
            if fr.get("z0_max_c"):
                findings.append(F("flightrec", "info", "[O]", "%s: flight recorder %s: zone0 peaked %.1f C during fieldiag %s (last record %s, last test %s)" % (
                    b["label"], os.path.basename(fr["path"]), fr["z0_max_c"], ", ".join(fr.get("tests", [])), iso(fr["t_last"]) if fr.get("t_last") else "?", fr.get("last_test")), fr.get("kmsg_interesting", [])[-5:], [b["label"]]))
    # --- inventory-derived findings
    for b in bundles:
        inv = b.get("inventory") or {}
        it = inv.get("items", {})
        cdi = (it.get("cdi") or {}).get("data") or {}
        if cdi.get("stale_specs"):
            spec = next(s for s in cdi["spec_files"] if s.get("stale"))
            findings.append(F("stale-cdi", "warn", "[O]", "%s: stale CDI spec -- nvidia-uvm major %s in %s vs live %s (/proc/devices)" % (
                b["label"], spec["uvm_major_in_spec"], spec["path"], cdi["live_major_proc_devices"]),
                ["[C] docker --gpus / CDI device injection fails until the spec is regenerated: nvidia-ctk cdi generate --output=%s" % spec["path"],
                 "[H] the nvidia modules were reloaded (e.g. by fieldiag) and nvidia-uvm got a new dynamic major"], [b["label"]]))
        fd_ = (it.get("fieldiag") or {}).get("data") or {}
        if fd_.get("blacklist_present"):
            findings.append(F("fieldiag-blacklist", "warn", "[O]", "%s: fieldiag blacklist left behind: %s (%s)" % (b["label"], MODS_BLACKLIST, (fd_.get("blacklist_content") or "").strip()),
                              ["[C] the nvidia driver will not load at boot until the file is removed (a crashed fieldiag run never reached UnblacklistNvidiaDriver)"], [b["label"]]))
        if fd_.get("mods_module_loaded"):
            findings.append(F("mods-module", "warn", "[O]", "%s: the MODS diagnostic driver is loaded (fieldiag did not clean up)" % b["label"], [], [b["label"]]))
        kern = (it.get("kernel") or {}).get("data") or {}
        if kern:
            findings.append(F("access", "info", "[O]", "%s: lockdown=%s, Secure Boot=%s -> /dev/mem SPBM telemetry and BAR0 reads %s" % (
                b["label"], kern.get("lockdown_mode"), (kern.get("secure_boot") or {}).get("enabled"), "possible" if kern.get("dev_mem_possible") else "not possible (use acpi_call for SPBM)"), [], [b["label"]]))
        nv = (it.get("nvme") or {}).get("data") or {}
        for dev, sm in nv.items():
            if isinstance(sm, dict) and sm.get("unsafe_shutdowns") is not None:
                findings.append(F("nvme-unsafe", "info", "[O]", "%s: NVMe %s unsafe_shutdowns=%s power_cycles=%s" % (b["label"], dev, sm["unsafe_shutdowns"], sm.get("power_cycles")), [], [b["label"]]))
        fan = (it.get("fan") or {}).get("data") or {}
        if it.get("fan") and not fan.get("present"):
            findings.append(F("no-fan-driver", "info", "[O]", "%s: no dgx_ec_fan_control driver: factory EC fan curve, fan RPM not visible" % b["label"], [], [b["label"]]))
    # --- inventory diffs across nodes
    if len(bundles) >= 2:
        diffs = inventory_diff(bundles)
        if diffs:
            findings.append(F("inventory-diff", "info", "[O]", "inventory differs between %s in %d field(s)" % (" / ".join(labels), len(diffs)),
                              ["%s: %s" % (k, " | ".join("%s=%s" % (n, v) for n, v in vals.items())) for k, vals in diffs[:25]], labels))
    order = {"critical": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    return findings


def intervention_findings(before, after, ref=None):
    """Same unit, same tests, two points in time (e.g. before/after a repaste): did the intervention remove the
    power-offs and normalise the hotspot rise per watt?"""
    out = []
    ev = []
    b_runs, a_runs = before["runs"], after["runs"]
    # power-offs removed?
    died_caps = sorted({r["cap"] for r in b_runs if r.get("died") and r.get("cap")})
    removed, remaining = [], []
    for cap in died_caps:
        after_same = [r for r in a_runs if r.get("cap") == cap and r.get("launched") and r.get("sm_frac", 1.0) >= 0.99]
        surv = [r for r in after_same if r.get("ended") and (r.get("p_max") or 0) >= 40]
        dead = [r for r in after_same if r.get("died")]
        if surv and not dead:
            best = max(surv, key=lambda r: r.get("p_max") or 0)
            removed.append(cap)
            ev.append("[O] cap %s: before = power lost (%d run(s)); after = survived %d/%d at NVML max %.1f W for %s s (zone0 peak %s C)" % (
                cap, sum(1 for r in b_runs if r.get("died") and r.get("cap") == cap), len(surv), len(after_same), best["p_max"], best.get("seconds"), best.get("z0_peak")))
        elif dead:
            remaining.append(cap)
            ev.append("[O] cap %s: power lost before and after (%d/%d after runs died)" % (cap, len(dead), len(after_same)))
        else:
            ev.append("[O] cap %s: died before; not re-tested after" % cap)
    # hotspot rise per watt before/after (and vs reference)
    ratios = []
    for key in sorted({group_key(r) for r in b_runs if r.get("cap")}, key=lambda k: (k[0] or 0, str(k[1]))):
        rb = [r for r in b_runs if group_key(r) == key and r.get("ended")]
        ra = [r for r in a_runs if group_key(r) == key and r.get("ended")]
        rr = [r for r in (ref["runs"] if ref else []) if group_key(r) == key and r.get("ended")]
        if not rb or not ra:
            continue
        pb, pa = max(rb, key=lambda r: r.get("n_tel", 0)), max(ra, key=lambda r: r.get("n_tel", 0))
        pr = max(rr, key=lambda r: r.get("n_tel", 0)) if rr else None
        if pb.get("pulses") and pa.get("pulses"):
            mb, ma = max(p["rise"] for p in pb["pulses"][:3]), max(p["rise"] for p in pa["pulses"][:3])
            mr = max(p["rise"] for p in pr["pulses"][:3]) if pr and pr.get("pulses") else None
            metric = "pulse rise"
        else:
            mb, ma = pb.get("rise_5s_per_w"), pa.get("rise_5s_per_w")
            mr = pr.get("rise_5s_per_w") if pr else None
            metric = "zone0 rise per watt at 5 s"
        if mb and ma and mb > 0:
            ratios.append(ma / mb)
            ev.append("[O] cap %s %s: %s before %s, after %s%s (P %.1f vs %.1f W)" % (key[0], key[1], metric, mb, ma, (", reference %s" % mr) if mr is not None else "", pb.get("p_mean") or 0, pa.get("p_mean") or 0))
    normalised = bool(ratios) and max(ratios) <= 0.5
    if not ev:
        return out
    if removed and not remaining and (normalised or not ratios):
        title = "%s -> %s: the intervention removed the power-off at cap %s%s" % (before["label"], after["label"], ", ".join(str(c) for c in removed),
                                                                                " and normalised the hotspot heating (%.1f-%.1fx of before)" % (min(ratios), max(ratios)) if ratios else "")
        ev.append("[C] a power-off that a cooling intervention removes, with the hotspot heating normalised at the same power, is thermal: the fault was at the GPU thermal interface")
        sev, tag = "critical", "[C]"
    elif normalised and not died_caps:
        title = "%s -> %s: hotspot heating normalised after the intervention (%.1f-%.1fx of before)" % (before["label"], after["label"], min(ratios), max(ratios))
        sev, tag = "warn", "[C]"
    elif remaining:
        title = "%s -> %s: the intervention did not remove the power-off (caps %s still die)" % (before["label"], after["label"], remaining)
        ev.append("[C] a cooling change that leaves the power-off in place points away from the thermal interface (electrical or silicon)")
        sev, tag = "critical", "[C]"
    else:
        title = "%s -> %s: before/after comparison (no clear change)" % (before["label"], after["label"])
        sev, tag = "info", "[O]"
    out.append(F("intervention-effect", sev, tag, title, ev, [before["label"], after["label"]]))
    return out


INV_DIFF_KEYS = [("dmi.bios_version", "dmi", "bios_version"), ("dmi.bios_date", "dmi", "bios_date"), ("dmi.ec_firmware_release", "dmi", "ec_firmware_release"),
                 ("dmi.product_serial", "dmi", "product_serial"), ("dmi.board_serial", "dmi", "board_serial"),
                 ("kernel.release", "kernel", "release"), ("kernel.cmdline", "kernel", "cmdline"), ("kernel.lockdown", "kernel", "lockdown_mode"),
                 ("nvidia.driver", "nvidia", "driver_version"), ("nvidia.gsp", "nvidia", "gsp_firmware"), ("nvidia.vbios", "nvidia", "vbios"),
                 ("nvidia.recovery_action", "nvidia", "recovery_action"), ("pci.link", "pci", "current_link_speed"),
                 ("pci.driver", "pci", "driver"), ("fieldiag.version", "fieldiag", "package_version"), ("fieldiag.blacklist", "fieldiag", "blacklist_present")]


def inventory_diff(bundles):
    out = []
    invs = [(b["label"], (b.get("inventory") or {}).get("items", {})) for b in bundles if b.get("inventory")]
    if len(invs) < 2:
        return out
    for name, it, key in INV_DIFF_KEYS:
        vals = {}
        for label, items in invs:
            d = (items.get(it) or {}).get("data") or {}
            vals[label] = d.get(key)
        if len({json.dumps(v, sort_keys=True, default=str) for v in vals.values()}) > 1:
            out.append((name, vals))
    # ESRT versions, ACPI hashes, NVMe counters, clocks-event counters
    for label_items in ("esrt", "acpi", "nvme"):
        vals = {}
        for label, items in invs:
            d = (items.get(label_items) or {}).get("data")
            if label_items == "esrt" and isinstance(d, list):
                vals[label] = {e.get("fw_class", e.get("entry")): e.get("fw_version_hex") or e.get("fw_version") for e in d}
            elif label_items == "acpi" and isinstance(d, dict):
                vals[label] = d.get("sha256")
            elif label_items == "nvme" and isinstance(d, dict):
                vals[label] = {dev: (s.get("unsafe_shutdowns"), s.get("power_cycles")) for dev, s in d.items() if isinstance(s, dict)}
        if vals and len({json.dumps(v, sort_keys=True, default=str) for v in vals.values()}) > 1:
            if label_items == "acpi" and all(isinstance(v, dict) for v in vals.values() if v):
                tables = sorted({t for v in vals.values() if v for t in v})
                for t in tables:
                    tv = {l: (v or {}).get(t) for l, v in vals.items()}
                    if len(set(tv.values())) > 1:
                        out.append(("acpi.sha256." + t, {l: (x[:12] if isinstance(x, str) else x) for l, x in tv.items()}))
            else:
                out.append((label_items, vals))
    return out


def recipe(bundles, findings):
    """Reproduction recipe generated from the data."""
    lines = []
    deaths = [(b["label"], r) for b in bundles for r in b["runs"] if r.get("died") and r.get("death")]
    if deaths:
        label, r = max(deaths, key=lambda x: x[1].get("t_start") or 0)
        cap = r.get("cap")
        st = (r.get("death") or {}).get("spbm") or {}
        lines += ["### Load-step power-off (reproduces the hard power-off)",
                  "On **%s** (expect power loss within ~%s ms of the step; have remote console/PDU access, nothing unsaved):" % (label, st.get("ms_onset_to_last", round(r["death"]["t_after_load_s"] * 1000))),
                  "", "```",
                  "sudo ./sparkdiag.py stress --experiments killstep --cap %s --fan max --cool-below 45 --out /var/log/sparkdiag %s" % (cap, CONSENT_FLAG),
                  "```",
                  "Equivalent by hand: `nvidia-smi -lgc 0,%s`; wait until thermal_zone0 < 45 C; run the embedded load generator continuous "
                  "(`--on-us 100 --off-us 0 --seconds 10`, 2 blocks/SM x 8 warps, bf16 tensor-core MMA on all SMs) with the 50 Hz SPBM logger running. "
                  "After the cut: `sudo ./sparkdiag.py resume --out /var/log/sparkdiag` shows the step and the last samples." % cap,
                  ""]
        cb = clock_band_threshold([x for b in bundles for x in b["runs"]], label)
        lines += ["### After a cooling intervention (repaste / heatsink reseat)",
                  "Re-run exactly the same steps on the same unit and compare the two result directories: "
                  "`./sparkdiag.py compare --before /path/before --after /path/after --reference spark0 --out ./report`. "
                  "If the power-off is gone and the hotspot rise per watt matches the reference, the fault was thermal.", ""]
        if cb.get("band"):
            lo, hi = cb["band"]
            mids = sorted({c for c in (lo + 100, lo + 200, hi - 100) if lo < c < hi})
            lines += ["### Clock-band discriminators",
                      "- cap threshold: `--experiments killstep --kill-caps %s` (survived %s, died %s)" % (",".join(str(c) for c in mids) or "%d" % ((lo + hi) // 2), lo, hi),
                      "- light load at the killing cap: `--experiments partial --cap %s` (25/50/75/100 %% of SMs)" % hi,
                      "- slew rate: `--experiments ramp --cap %s` (0/50/200/1000 ms ramps)" % hi, ""]
    hp = [f for f in findings if f["id"].startswith("heat-path")]
    if hp:
        nodes = hp[0]["nodes"]
        lines += ["### Heat-path comparison (non-destructive at <= 1800 MHz with the 95 C guard)",
                  "Run the same thermal step response on the suspect unit and a healthy reference, same image/load/fan curve, and compare zone0 rise per watt:",
                  "", "```",
                  "sudo ./sparkdiag.py stress --experiments thermal --caps 1200,1500,1800 --sustain-s 30 --out /var/log/sparkdiag %s   # on each node" % CONSENT_FLAG,
                  "./sparkdiag.py compare --label %s=/path/node-a --label %s=/path/node-b --out ./report" % tuple((nodes + ["ref", "ref"])[:2]),
                  "```", "Expected on a faulty unit: zone0 +15 C at 5 s vs +3 C at ~30 W; ~0.8 vs ~0.3 C/W at 30 s; other zones equal.", ""]
    gfw = [f for f in findings if f["id"].startswith("gfw-boot-stall")]
    if gfw:
        lines += ["### GFW boot stall",
                  "After an abrupt cut, if `nvidia-smi` fails: `sudo ./sparkdiag.py forensics --bar0 --out DIR` (lockdown none) reads BAR0 0x5e0; 0xFF = booted, "
                  "anything else = FWSEC stalled. PCI cfg 0x2B4 shows a latched SEC_FAULT (VMON bits = rail voltage monitor). Full AC removal (not a reboot) clears the stall.", ""]
    if not lines:
        lines = ["No fault was reproduced in the ingested data. Suggested first pass on a suspect unit:",
                 "", "```", "sudo ./sparkdiag.py all --out /var/log/sparkdiag",
                 "sudo ./sparkdiag.py stress --experiments thermal,sweep --caps 1200,1500,1800,2100 --out /var/log/sparkdiag %s" % CONSENT_FLAG, "```", ""]
    return "\n".join(lines)


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join("" if v is None else str(v) for v in r) + " |")
    return "\n".join(out)


def fmt(v, nd=1):
    if v is None:
        return ""
    if isinstance(v, float):
        return ("%%.%df" % nd) % v
    return str(v)


def render_markdown(bundles, findings, rep):
    L = []
    L.append("# sparkdiag report\n")
    L.append("Generated %s by sparkdiag %s (%s build). Nodes: %s.\n" % (iso(), VERSION, BUILD, ", ".join("**%s** (`%s`)" % (b["label"], b["dir"]) for b in bundles)))
    L.append("Evidence tags: **[O]** observed in the data, **[C]** calculated from observations, **[H]** hypothesis / inference.\n")
    L.append("## Findings\n")
    if not findings:
        L.append("_No findings._\n")
    for f in findings:
        L.append("### %s %s — %s\n" % ({"critical": "CRITICAL", "warn": "WARNING", "info": "INFO"}.get(f["severity"], f["severity"]), f["tag"], f["title"]))
        for e in f["evidence"]:
            if e:
                L.append("- %s" % e)
        L.append("")
    # inventory
    L.append("## Inventory\n")
    rows = []
    keys = [("BIOS", "dmi", "bios_version"), ("BIOS date", "dmi", "bios_date"), ("EC fw (dmi)", "dmi", "ec_firmware_release"), ("Product", "dmi", "product_name"),
            ("Serial", "dmi", "product_serial"), ("Kernel", "kernel", "release"), ("Lockdown", "kernel", "lockdown_mode"),
            ("Driver", "nvidia", "driver_version"), ("GSP", "nvidia", "gsp_firmware"), ("VBIOS", "nvidia", "vbios"), ("GPU", "nvidia", "product_name"),
            ("PCI link", "pci", "current_link_speed"), ("PCI driver", "pci", "driver"), ("fieldiag", "fieldiag", "package_version"),
            ("MODS blacklist", "fieldiag", "blacklist_present"), ("fan driver", "fan", "present")]
    for name, it, key in keys:
        row = [name]
        for b in bundles:
            d = (((b.get("inventory") or {}).get("items", {})).get(it) or {}).get("data") or {}
            row.append(d.get(key))
        rows.append(row)
    for b in bundles:
        inv = b.get("inventory")
        if inv:
            es = (inv["items"].get("esrt") or {})
            if es.get("data"):
                rows.append(["ESRT"] + [", ".join("%s=%s" % (e.get("fw_class", "?")[:8], e.get("fw_version_hex") or e.get("fw_version")) for e in es["data"])])
            break
    L.append(md_table(["item"] + [b["label"] for b in bundles], rows))
    L.append("")
    for b in bundles:
        inv = b.get("inventory")
        if not inv:
            L.append("- %s: no inventory.json ingested" % b["label"])
            continue
        missing = ["%s (%s)" % (k, v.get("note")) for k, v in inv["items"].items() if not v.get("ok")]
        if missing:
            L.append("- %s: unavailable items: %s" % (b["label"], "; ".join(missing)))
        sec = (inv["items"].get("kernel") or {}).get("data") or {}
        L.append("- %s: Secure Boot %s, lockdown %s, modules %s" % (b["label"], (sec.get("secure_boot") or {}).get("enabled"), sec.get("lockdown"), ", ".join(k for k, v in (sec.get("modules") or {}).items() if v)))
        nv = (inv["items"].get("nvidia") or {}).get("data") or {}
        if nv.get("clocks_event_counters_us"):
            L.append("- %s: clocks-event counters (us): %s" % (b["label"], json.dumps(nv["clocks_event_counters_us"])))
        th = (inv["items"].get("thermal") or {}).get("data") or {}
        if th.get("zones"):
            L.append("- %s: thermal zones: %s" % (b["label"], ", ".join("%s=%s(%s)" % (z["zone"][12:], z.get("acpi_name") or z.get("acpi_name_H", "?"), z.get("spbm_field")) for z in th["zones"])))
    L.append("")
    # forensics
    L.append("## Forensics\n")
    for b in bundles:
        fo = b.get("forensics")
        if not fo:
            L.append("- %s: no forensics.json ingested\n" % b["label"])
            continue
        it = fo["items"]
        L.append("### %s\n" % b["label"])
        boots = (it.get("boots") or {}).get("data") or {}
        if boots.get("boots"):
            rows = [[x["index"], iso(x["first"]) if x.get("first") else "", iso(x["last"]) if x.get("last") else "", x.get("duration_s"), x.get("gap_to_next_s"),
                     {True: "clean", False: "ABRUPT", None: "?"}.get(x.get("clean_shutdown"))] for x in boots["boots"][-12:]]
            L.append(md_table(["boot", "first entry", "last entry", "duration s", "gap to next s", "shutdown"], rows))
            L.append("")
        jn = (it.get("journal") or {}).get("data") or {}
        for boot in jn.get("boots", []):
            dec = [d for d in boot.get("decoded", []) if any(k in d["decode"] for k in ("rminit", "xid", "check_failed", "sec2_boot_timeout_gb20b", "acpi_critical_trip"))]
            if dec or boot.get("matches"):
                L.append("- boot %s: %d matching journal lines; clean shutdown: %s" % (boot["index"], boot["matches"], boot.get("clean_shutdown")))
                for d in dec[-8:]:
                    L.append("    - `%s` -> %s" % (d["line"][-160:], json.dumps(d["decode"], default=str)))
                if boot.get("tail"):
                    L.append("    - last line: `%s`" % boot["tail"][-1][-160:])
        pc = (it.get("pci_cfg") or {})
        L.append("- PCI cfg 0x2B4 VSEC_DEBUG_SEC: %s" % (json.dumps(pc.get("data", {}).get("vsec_debug_sec"), default=str) if pc.get("ok") else pc.get("note")))
        b0 = it.get("bar0") or {}
        if b0.get("ok"):
            L.append("- BAR0 read-only plan (%s):" % (b0["data"].get("stopped") or "complete"))
            L.append(md_table(["offset", "register", "value", "decode / PRI error"], [[r.get("offset"), r.get("name"), r.get("value", r.get("skipped")), json.dumps(r.get("decode") or r.get("pri_error") or "", default=str)] for r in b0["data"]["reads"]]))
        else:
            L.append("- BAR0: %s" % b0.get("note"))
        bt = (it.get("bert") or {}).get("data") or {}
        L.append("- BERT table: %s, HEST: %s, ERST: %s; APEI kernel lines: %d" % (bt.get("bert_table"), bt.get("hest_table"), bt.get("erst_table"), len(bt.get("kernel_lines", []))))
        ps = it.get("pstore") or {}
        L.append("- pstore: %s" % (("%d file(s)" % ps["data"]["count"]) if ps.get("ok") else ps.get("note")))
        mods = (it.get("mods") or {}).get("data") or {}
        if mods.get("runs"):
            L.append("- MODS binary %s (%s); %s" % (mods.get("binary"), "present, builds %s" % mods.get("binary_versions") if mods.get("binary_present") else "absent", mods.get("keyring_note")))
            rows = []
            for r in mods["runs"]:
                files = r.get("mods_files", [])
                dec = "%d/%d decoded" % (sum(1 for f in files if f.get("decoded")), len(files))
                rows.append([r["name"], r.get("onediag_version") or r.get("diag_version"), ", ".join(t["name"] for t in r.get("tests", [])), r.get("final_result") or ("TRUNCATED" if r.get("truncated") else ""),
                             r.get("error_code") or "", r.get("boot_status") or "", r.get("last_mods_test") or "", dec])
            L.append(md_table(["run", "onediag", "tests", "result", "error", "boot status", "last MODS test", "logs"], rows))
            for r in mods["runs"]:
                for f in r.get("mods_files", []):
                    if f.get("decoded") and f["path"].endswith(".log"):
                        s = f["summary"]
                        L.append("    - %s/%s: MODS %s, %d errors, complete=%s; tail: `%s`" % (r["name"], os.path.basename(os.path.dirname(f["path"])), s.get("version"), len(s.get("errors", [])), s.get("complete"), " / ".join(s.get("tail", [])[-3:])[:220]))
        else:
            L.append("- MODS field-diag runs: %s" % (it.get("mods") or {}).get("note"))
        L.append("")
    # experiments
    L.append("## Experiments\n")
    for b in bundles:
        if not b["runs"]:
            continue
        L.append("### %s (%d runs)\n" % (b["label"], len(b["runs"])))
        rows = []
        for r in b["runs"]:
            status = "DIED" if r.get("died") else ("aborted" if r.get("aborted") else ("ok" if r.get("ended") else "incomplete"))
            pl = r.get("plateau")
            rows.append([r["tag"], r.get("cap"), r.get("pattern"), fmt(r.get("p_mean")), fmt(r.get("p_max")), fmt(r.get("z0_base")), fmt(r.get("z0_peak")),
                         fmt(r.get("z0_rise_1s")), fmt(r.get("z0_rise_5s")), fmt(r.get("z0_rise_30s")), fmt(r.get("c_per_w_30s"), 2), r.get("sm_max"),
                         ("%.0f C x %.0fs" % (pl["z0_mean"], pl["seconds"])) if pl else "", status])
        L.append(md_table(["run", "cap", "pattern", "P mean W", "P max W", "z0 base", "z0 peak", "+1s", "+5s", "+30s", "C/W 30s", "SM max", "plateau", "status"], rows))
        L.append("")
        pulses = [r for r in b["runs"] if r.get("pulses") and r.get("pattern", "").startswith("pulse")]
        if pulses:
            rows = []
            for r in pulses:
                for p in r["pulses"][:4]:
                    rows.append([r["tag"], r.get("cap"), p["i"], fmt(p["z0_start"]), fmt(p["z0_peak"]), fmt(p["rise"]), fmt(p["rise_1s"]), fmt(p["p_mean"]), p["sm_max"]])
            L.append("Per-pulse zone0 response:\n")
            L.append(md_table(["run", "cap", "pulse", "z0 start", "z0 peak", "rise", "rise 1 s", "P mean W", "SM"], rows))
            L.append("")
    cmp_rows = rep.get("comparison") or []
    if cmp_rows:
        L.append("### Cross-node comparison (same cap and pattern)\n")
        rows = [[r["cap"], r["pattern"], r["node"], r["reference"], "%s / %s" % (fmt(r["p_mean"][0]), fmt(r["p_mean"][1])), "%s / %s" % r["z0_rise_5s"],
                 r.get("z0_rise_5s_ratio"), "%s / %s" % r["c_per_w_30s"], r.get("c_per_w_30s_ratio"), r.get("pulse_rise_ratio"), "yes" if r["power_equal"] else "no"] for r in cmp_rows]
        L.append(md_table(["cap", "pattern", "node", "ref", "P mean W", "+5 s C", "ratio", "C/W 30 s", "ratio", "pulse ratio", "equal power"], rows))
        L.append("")
    if rep.get("deaths"):
        L.append("### Power-loss events\n")
        rows = [[d["node"], d["tag"], d["cap"], d["pattern"], d.get("ramp_ms"), d.get("sm_frac"), d.get("t_after_load_s"), d.get("p_last_w"), d.get("z0_last_c"), d.get("gpu_last_c"), d.get("sm_last"), iso(d["t_last"]) if d.get("t_last") else ""] for d in rep["deaths"]]
        L.append(md_table(["node", "run", "cap", "pattern", "ramp ms", "SM frac", "s after load", "P last W", "zone0 C", "GPU C", "SM MHz", "last record"], rows))
        L.append("")
    for b in bundles:
        for sl in b["step_logs"]:
            if sl.get("running_at_end"):
                s = sl["running_at_end"]
                L.append("- %s: step log `%s` stops inside step cap=%s pattern=%s (BEGIN %s, no RESULT) [O]" % (b["label"], os.path.basename(sl["path"]), s.get("cap"), s.get("pattern"), s.get("t_begin")))
    for b in bundles:
        st = b.get("stress_state")
        if st:
            L.append("- %s: sparkdiag stress session status=%s, steps: %s" % (b["label"], st.get("status"), ", ".join("%s=%s" % (s["id"], s["status"]) for s in st.get("plan", []))))
    L.append("")
    # last window before power loss
    win = rep.get("last_window") or []
    if win:
        L.append("## Last %d ms before power loss\n" % rep.get("window_ms", 500))
        for w in win:
            L.append("### %s: %s (cap %s, %s)\n" % (w["node"], w["tag"], w["cap"], w["pattern"]))
            if w.get("nvml"):
                L.append("NVML/ACPI samples (host recorder, O_DSYNC):\n")
                L.append(md_table(["t rel s", "P W", "SM", "GPU C", "zone0 C", "zone1", "zone3", "fans"], [[fmt(x["dt"], 3), fmt(x["p_w"]), x["sm"], x["gpu_c"], fmt(x["z0"]), fmt(x["z1"]), fmt(x["z3"]), x["fans"]] for x in w["nvml"]]))
                L.append("")
            if w.get("spbm"):
                L.append("SPBM samples from the load-step onset (DC input / GPU rail / SoC package / Tj / PROCHOT / PL level / PID winner):\n")
                L.append(md_table(["dt s", "DC in W", "GPU W", "SoC pkg W", "sys W", "Tj C", "PROCHOT", "PL lvl", "PID win"], [[fmt(x["dt_s"], 3), x["dc_in_w"], x["gpu_w"], x["soc_pkg_w"], x["sys_tot_w"], x["tj_c"], x["prochot"], x["pl_lvl"], x["pid_win"]] for x in w["spbm"]]))
                L.append("")
            if w.get("kmsg"):
                L.append("Kernel messages in the window: " + ("; ".join(w["kmsg"][-5:]) if w["kmsg"] else "none"))
                L.append("")
    L.append("## Reproduction recipe\n")
    L.append(rep.get("recipe", ""))
    L.append("## Data sources and limitations\n")
    for b in bundles:
        L.append("- %s: %d files; %d load runs, %d SPBM logs, %d step logs, %d flight-recorder logs, %d sparkdiag telemetry files; inventory %s, forensics %s%s" % (
            b["label"], b["files"], len(b["runs"]), len(b["spbm"]), len(b["step_logs"]), len(b["flightrecs"]), len(b["telemetry"]),
            "yes" if b.get("inventory") else "no", "yes" if b.get("forensics") else "no", ("; parse errors: %d" % len(b["errors"])) if b["errors"] else ""))
    L.append("")
    L.append("What sparkdiag reads: sysfs/procfs, journal, NVML, nvidia-smi, PCI config space, optional read-only BAR0 and /dev/mem (SPBM page) mappings, MODS logs decoded with keys derived from the installed MODS binary. "
             "It never writes to hardware registers, never talks to the EC (no FF-A/eSPI traffic), never touches SPMI/PMIC, SPM, SSPM, HFRP or ESPI ranges.\n")
    return "\n".join(L)


def build_report(dirs, labels=None, out=None, window_ms=500, reference=None, before=None, after=None):
    bundles = []
    roles = {}
    for d in list(dirs) + [x for x in (before, after) if x and x not in dirs]:
        lab = (labels or {}).get(d) if isinstance(labels, dict) else None
        if lab is None and d == before:
            lab = "before"
        if lab is None and d == after:
            lab = "after"
        b = ingest_dir(d, lab)
        bundles.append(b)
        if d == before:
            roles["before"] = b
        if d == after:
            roles["after"] = b
    all_runs = [r for b in bundles for r in b["runs"]]
    findings = derive_findings(bundles, reference)
    if "before" in roles and "after" in roles:
        refb = next((b for b in bundles if b["label"] == reference), None)
        findings = intervention_findings(roles["before"], roles["after"], refb) + findings
    rep = {"generated": iso(), "sparkdiag": {"version": VERSION, "build": BUILD}, "nodes": [{"label": b["label"], "dir": b["dir"]} for b in bundles],
           "findings": findings, "comparison": compare_nodes(all_runs, reference), "deaths": deaths_summary(all_runs),
           "clock_band": {b["label"]: clock_band_threshold(all_runs, b["label"]) for b in bundles if any(r.get("died") for r in b["runs"])},
           "runs": {b["label"]: [{k: v for k, v in r.items() if k != "_rec_tail"} for r in b["runs"]] for b in bundles},
           "inventory": {b["label"]: b.get("inventory") for b in bundles}, "forensics": {b["label"]: b.get("forensics") for b in bundles},
           "inventory_diff": inventory_diff(bundles), "step_logs": {b["label"]: [{k: v for k, v in s.items() if k != "steps"} for s in b["step_logs"]] for b in bundles},
           "flightrecs": {b["label"]: [{k: v for k, v in f.items() if k not in ("tel", "out")} for f in b["flightrecs"]] for b in bundles},
           "telemetry": {b["label"]: b["telemetry"] for b in bundles}, "stress_state": {b["label"]: b.get("stress_state") for b in bundles},
           "window_ms": window_ms, "errors": {b["label"]: b["errors"] for b in bundles},
           "intervention": {"before": roles["before"]["label"], "after": roles["after"]["label"]} if "before" in roles and "after" in roles else None}
    # last-N-ms window before each power loss
    win = []
    for b in bundles:
        for r in b["runs"]:
            if not r.get("died"):
                continue
            tail = r.get("_rec_tail") or []
            t_end = r["t_last"]
            nv = []
            for x in tail:
                if t_end - x.get("t", 0) <= window_ms / 1000.0 + 0.001:
                    nv.append({"dt": round(x["t"] - t_end, 3), "p_w": (x.get("p_inst_mw") or 0) / 1000.0, "sm": x.get("sm_mhz"), "gpu_c": x.get("gpu_c"),
                               "z0": _zone_c(x, "thermal_zone0"), "z1": _zone_c(x, "thermal_zone1"), "z3": _zone_c(x, "thermal_zone3"), "fans": "%s/%s" % (x.get("fan1"), x.get("fan2"))})
            w = {"node": b["label"], "tag": r["tag"], "cap": r.get("cap"), "pattern": r.get("pattern"), "nvml": nv, "spbm": ((r.get("death") or {}).get("spbm_table") or [])[-30:], "kmsg": []}
            for t in b["telemetry"]:
                w["kmsg"] += [k for k in t.get("kmsg", []) if k]
            win.append(w)
    rep["last_window"] = win
    rep["recipe"] = recipe(bundles, findings)
    md = render_markdown(bundles, findings, rep)
    if out:
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "report.md"), "w") as f:
            f.write(md)
        with open(os.path.join(out, "report.json"), "w") as f:
            json.dump(rep, f, indent=1, default=str)
    return rep, md


# ----------------------------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------------------------

def cmd_inventory(args):
    inv = collect_inventory(args)
    os.makedirs(args.out, exist_ok=True)
    p = os.path.join(args.out, "inventory.json")
    write_json_durable(p, inv)
    bad = [k for k, v in inv["items"].items() if not v.get("ok")]
    Log.info("inventory -> %s (%d items, unavailable: %s)" % (p, len(inv["items"]), ", ".join(bad) or "none"))
    if args.print:
        print(json.dumps(inv, indent=1, default=str))
    return 0


def cmd_forensics(args):
    inv = load_json(os.path.join(args.out, "inventory.json"))
    fo = collect_forensics(args, inv)
    os.makedirs(args.out, exist_ok=True)
    p = os.path.join(args.out, "forensics.json")
    write_json_durable(p, fo)
    bad = [k for k, v in fo["items"].items() if not v.get("ok")]
    Log.info("forensics -> %s (unavailable: %s)" % (p, ", ".join(bad) or "none"))
    if args.print:
        print(json.dumps(fo, indent=1, default=str))
    return 0


def _labels(args):
    labels = {}
    for item in args.label or []:
        if "=" in item:
            name, d = item.split("=", 1)
            labels[d] = name
    return labels


def cmd_report(args):
    dirs = list(args.dirs)
    labels = _labels(args)
    dirs += [d for d in labels if d not in dirs]
    if not dirs and not (getattr(args, "before", None) and getattr(args, "after", None)):
        Log.info("no result directories given")
        return 2
    rep, md = build_report(dirs, labels, args.out, args.window_ms, args.reference, getattr(args, "before", None), getattr(args, "after", None))
    Log.info("report -> %s/report.md, report.json (%d findings)" % (args.out, len(rep["findings"])))
    if args.print:
        print(md)
    else:
        for f in rep["findings"]:
            print("%-9s %s %s" % (f["severity"].upper(), f["tag"], f["title"]))
    return 0


def cmd_all(args):
    rc = cmd_inventory(args)
    rc |= cmd_forensics(args)
    args.dirs = [args.out]
    args.label = ["%s=%s" % (socket.gethostname(), args.out)]
    args.reference = None
    args.window_ms = 500
    rep, md = build_report([args.out], _labels(args), os.path.join(args.out, "report"), 500, None)
    Log.info("report -> %s/report/report.md (%d findings)" % (args.out, len(rep["findings"])))
    for f in rep["findings"]:
        print("%-9s %s %s" % (f["severity"].upper(), f["tag"], f["title"]))
    return rc


def cmd_mods(args):
    kr = ModsKeyring.from_binary(args.mods_bin)
    Log.info("keyring: %s" % "; ".join(kr.notes))
    rc = 0
    for fn in args.files:
        if os.path.isdir(fn):
            print("%s: directory, skipped (use forensics --mods-logs DIR for run directories)" % fn)
            continue
        with open(fn, "rb") as f:
            data = f.read()
        res = mods_decode(data, kr)
        hdr = res.get("header", {})
        if not res["ok"]:
            print("%s: MODS %s present, not decoded: %s" % (fn, "type %s build %s" % (hdr.get("type"), hdr.get("version")), res.get("reason")))
            rc = 1
            continue
        pt = res["plaintext"]
        outp = None
        if args.outdir:
            os.makedirs(args.outdir, exist_ok=True)
            base = os.path.basename(fn)
            ext = {".spe": ".js", ".jsone": ".json", ".yme": ".yml", ".jse": ".js", ".log": ".txt", ".mle": ".bin"}.get(os.path.splitext(base)[1], ".bin")
            outp = os.path.join(args.outdir, base + ext)
            with open(outp, "wb") as f:
                f.write(pt)
        print("%s: decoded (%d bytes, key %s, build %s)%s" % (fn, len(pt), res.get("key_source"), res.get("version") or "", (" -> " + outp) if outp else ""))
        if fn.endswith(".log"):
            s = mods_log_summary(pt.decode("utf-8", "replace"))
            print(json.dumps({k: s[k] for k in ("version", "errors", "boot_status", "boot_status_decode", "last_test", "complete", "tail") if k in s}, indent=1))
        elif fn.endswith(".mle"):
            ents = mle_entries(pt)
            print(json.dumps({"entries": len(ents), "rc_records": [e for e in ents if e["rc"] is not None][:5], "last_text": [e["text"] for e in ents if e.get("text")][-6:]}, indent=1, default=str))
    return rc


def cmd_version(args):
    print("%s %s (%s build)%s" % (PROG, VERSION, BUILD, "  INTERNAL - contains NVIDIA MODS decryption keys; do not distribute" if BUILD == "internal" else ""))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog=PROG, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version="%s %s (%s build)" % (PROG, VERSION, BUILD))
    sub = ap.add_subparsers(dest="cmd")

    def common(p, out_default="./sparkdiag-out"):
        p.add_argument("--out", default=out_default, help="result directory (default %s)" % out_default)
        p.add_argument("--print", action="store_true", help="also print the JSON/Markdown to stdout")

    def mods_opts(p):
        p.add_argument("--mods-bin", default=DEFAULT_MODS_BIN, help="MODS binary to derive the log keys from (default %s)" % DEFAULT_MODS_BIN)
        p.add_argument("--mods-logs", action="append", default=[], help="extra directory to search for fieldiag logs-* run dirs (repeatable)")
        p.add_argument("--no-mods-decode", action="store_true")
        p.add_argument("--mods-max-runs", type=int, default=30)
        p.add_argument("--flightrec-dir", default="/var/log/fieldiag-flightrec")

    p = sub.add_parser("inventory", help="read-only system/firmware/driver inventory")
    common(p)
    p.add_argument("--bdf", help="GPU PCI address (auto-detected)")
    p.add_argument("--boots", type=int, default=12, help="boots to check for unclean shutdown")
    p.add_argument("--mods-bin", default=DEFAULT_MODS_BIN)
    p.add_argument("--image", default=DEFAULT_IMAGE)
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("forensics", help="read-only previous-boot / GPU latch / MODS log analysis")
    common(p)
    p.add_argument("--bdf")
    p.add_argument("--boots", type=int, default=12)
    p.add_argument("--prev-boots", type=int, default=3, help="previous boots to grep in detail")
    p.add_argument("--bar0", action="store_true", help="read the documented read-only BAR0 register plan (root, lockdown none)")
    mods_opts(p)
    p.set_defaults(func=cmd_forensics)

    p = sub.add_parser("telemetry", help="read-only unified sampler (NVML + ACPI zones + fans + SPBM), crash-survivable")
    common(p)
    p.add_argument("--rate-ms", type=float, default=20)
    p.add_argument("--seconds", type=float, default=0, help="duration (0 = until Ctrl-C)")
    p.add_argument("--spbm", choices=["auto", "devmem", "acpi_call", "off"], default="auto")
    p.add_argument("--udp", help="mirror every record to HOST:PORT by UDP")
    p.add_argument("--counters-s", type=float, default=1.0, help="clocks-event counter sampling period (0 = off)")
    p.add_argument("--sync-every", type=int, default=1, help="os.sync() every N samples")
    p.add_argument("--print-every", type=float, default=2.0, help="print a status line every N s (0 = quiet)")
    p.add_argument("--tag", default="tel")
    p.set_defaults(func=cmd_telemetry)

    p = sub.add_parser("stress", help="DESTRUCTIVE characterisation experiments (thermal, sweep, killstep, ramp, partial)")
    common(p, "/var/log/sparkdiag")
    p.add_argument(CONSENT_FLAG, dest="consent", action="store_true", help="required: the fault under test powers the node off without warning")
    p.add_argument("--experiments", default="thermal,sweep", help="comma list of thermal,sweep,killstep,ramp,partial")
    p.add_argument("--caps", default="1200,1500,1800,2100", help="clock caps for thermal/sweep (3003 = uncapped)")
    p.add_argument("--cap", default="2400", help="cap for killstep/ramp/partial")
    p.add_argument("--kill-caps", default=None, help="comma list of caps for killstep (overrides --cap)")
    p.add_argument("--seconds", type=float, default=10)
    p.add_argument("--sustain-s", type=float, default=30)
    p.add_argument("--cool-below", type=float, default=50, help="wait for zone0 below this before each step")
    p.add_argument("--cool-timeout", type=float, default=180)
    p.add_argument("--abort-c", type=float, default=95, help="thermal abort guard (any zone or GPU)")
    p.add_argument("--hard-stop-s", type=float, default=1.0, help="hard-kill the GPU job if still above the limit this long after an abort")
    p.add_argument("--fan", choices=["keep", "max", "auto"], default="keep", help="fan floor via the dgx_ec_fan_control driver if present")
    p.add_argument("--restore-cap", default="1200", help="clock cap restored at the end (MHz, or 'none' for -rgc)")
    p.add_argument("--image", default=DEFAULT_IMAGE)
    p.add_argument("--mode", choices=["auto", "direct", "docker"], default="auto")
    p.add_argument("--rate-ms", type=float, default=20)
    p.add_argument("--spbm", choices=["auto", "devmem", "acpi_call", "off"], default="auto")
    p.add_argument("--udp")
    p.add_argument("--counters-s", type=float, default=1.0)
    p.add_argument("--no-gpu-telemetry", action="store_true", help="GPU script records edges only (host sampler does telemetry)")
    p.add_argument("--skip-steps", default="", help="comma list of step ids (or prefixes) to skip")
    p.add_argument("--dry-run", action="store_true", help="print the plan and exit (nothing touched)")
    p.set_defaults(func=cmd_stress)

    p = sub.add_parser("resume", help="after a power loss: which stress step was running, last telemetry; --continue to proceed")
    common(p, "/var/log/sparkdiag")
    p.add_argument("--continue", dest="cont", action="store_true", help="continue the remaining plan (marks the dead step)")
    p.add_argument(CONSENT_FLAG, dest="consent", action="store_true")
    p.set_defaults(func=cmd_resume)

    for name, hlp in (("report", "ingest result directories -> report.md + report.json"), ("compare", "same as report; two or more nodes")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("dirs", nargs="*", help="result directories (label = directory basename)")
        p.add_argument("--label", action="append", help="NAME=DIR (repeatable)")
        p.add_argument("--reference", help="reference (healthy) node label for ratios")
        p.add_argument("--before", help="before/after intervention mode: result directory of the SAME unit before the change (e.g. repaste)")
        p.add_argument("--after", help="result directory of the same unit after the change; pairs runs by cap and pattern")
        p.add_argument("--window-ms", type=int, default=500)
        common(p, "./sparkdiag-report")
        p.set_defaults(func=cmd_report)

    p = sub.add_parser("all", help="inventory + forensics + report (the safe subcommands)")
    common(p)
    p.add_argument("--bdf")
    p.add_argument("--boots", type=int, default=12)
    p.add_argument("--prev-boots", type=int, default=3)
    p.add_argument("--bar0", action="store_true")
    p.add_argument("--image", default=DEFAULT_IMAGE)
    mods_opts(p)
    p.set_defaults(func=cmd_all)

    p = sub.add_parser("mods", help="decode / summarise MODS logs or spec files")
    p.add_argument("files", nargs="+")
    p.add_argument("--mods-bin", default=DEFAULT_MODS_BIN)
    p.add_argument("-o", "--outdir")
    p.set_defaults(func=cmd_mods)

    p = sub.add_parser("version")
    p.set_defaults(func=cmd_version)

    args = ap.parse_args(argv)
    Log.verbose = args.verbose
    if not args.cmd:
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
