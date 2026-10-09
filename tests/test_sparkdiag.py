#!/usr/bin/env python3
"""Offline unit tests for sparkdiag (no GPU, no ssh, nothing touched on hardware).

Run:  SPARKDIAG_FIXTURES=/path/to/investigation-data python3 -m unittest discover -s tests -v

Fixtures are the real recorded investigation data under $SPARKDIAG_FIXTURES (repro/runs, the MODS evidence
run directory, the fieldiag binary, the decoded references, the baseline captures).  Tests that need a fixture
skip with a message when it is absent, so the suite also runs on a node without the investigation tree.
"""
import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RCA = os.environ.get("SPARKDIAG_FIXTURES", "")  # investigation data root; fixture tests skip when unset/missing
RUNS = os.path.join(RCA, "repro", "runs")
EVIDENCE = os.path.join(RCA, "mods-re", "evidence")
OLD_RUNS = os.path.join(RCA, "spark1", "opt", "nvidia", "dgx-spark-fieldiag", "logs", "pre-2.0.4")
FLIGHTREC = os.path.join(RCA, "spark1", "var", "log", "fieldiag-flightrec")
MODS_BIN = os.path.join(RCA, "fieldiag-deb", "x", "dgx", "tests", "mods.580", "fieldiag")
DECODED_LOG = os.path.join(RCA, "mods-re", "decoded", "fieldiag.log.txt")
DECODED_CHECK_CONFIG = os.path.join(RCA, "mods-re", "decoded", "specs", "check_config.js")
BASELINE0 = os.path.join(RCA, "spark0", "baseline-0123.txt")
SCRATCH = os.environ.get("SPARKDIAG_TEST_TMP") or os.path.join(ROOT, "tests", ".tmp")
# The known MODS keys live only in the local (unpublished) build.py; key-related checks skip without it.
def _local_key_table():
    bp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build.py")
    if not os.path.exists(bp):
        return {}
    ns = {}
    src = open(bp).read()
    start = src.index("KEY_TABLE = {")
    exec(src[start:src.index("\n}\n", start) + 3], ns)
    return ns.get("KEY_TABLE", {})


_KT = _local_key_table().get("629.580.34", {})
LOG_KEY_HEX = _KT.get("log")
DATA_KEY_HEX = _KT.get("data")


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def jload(path):
    with open(path) as f:
        return json.load(f)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_internal():
    subprocess.run([sys.executable, os.path.join(ROOT, "build.py")], check=True, capture_output=True)
    return os.path.join(ROOT, "sparkdiag-internal.py")


sd = load(os.path.join(ROOT, "sparkdiag.py"), "sparkdiag_shareable")
os.makedirs(SCRATCH, exist_ok=True)


def tmpdir(prefix):
    return tempfile.mkdtemp(prefix=prefix, dir=SCRATCH)


def need(path):
    if not os.path.exists(path):
        raise unittest.SkipTest("fixture missing: %s" % path)
    return path


_KEYRING = {}


def keyring():
    if "kr" not in _KEYRING:
        need(MODS_BIN)
        _KEYRING["kr"] = sd.ModsKeyring.from_binary(MODS_BIN)
    return _KEYRING["kr"]


class TestBuilds(unittest.TestCase):
    def setUp(self):
        if not LOG_KEY_HEX or not DATA_KEY_HEX:
            self.skipTest("local build.py key table not present (public checkout)")

    def test_shareable_has_no_keys(self):
        src = slurp(os.path.join(ROOT, "sparkdiag.py"))
        self.assertNotIn(LOG_KEY_HEX, src)
        self.assertNotIn(DATA_KEY_HEX, src)
        self.assertEqual(sd.BUILD, "shareable")
        self.assertEqual(sd.MODS_KNOWN_KEYS, {})

    def test_internal_build_generated_from_source(self):
        path = build_internal()
        src = slurp(path)
        self.assertIn(LOG_KEY_HEX, src)
        self.assertIn(DATA_KEY_HEX, src)
        self.assertIn("INTERNAL BUILD", src[:400])
        subprocess.run([sys.executable, "-m", "py_compile", path], check=True)
        internal = load(path, "sparkdiag_internal")
        self.assertEqual(internal.BUILD, "internal")
        self.assertEqual(internal.MODS_KNOWN_KEYS["629.580.34"]["log"], LOG_KEY_HEX)
        out = subprocess.run([sys.executable, path, "version"], capture_output=True, text=True, check=True).stdout
        self.assertIn("INTERNAL", out)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "sparkdiag.py"), "version"], capture_output=True, text=True, check=True).stdout
        self.assertNotIn("INTERNAL", out)
        # everything except the two markers is identical
        a = slurp(os.path.join(ROOT, "sparkdiag.py")).replace('BUILD = "shareable"', "").replace("MODS_KNOWN_KEYS = {}", "")
        b = src.replace('BUILD = "internal"', "")
        for line in a.splitlines():
            if line.strip() and "MODS_KNOWN_KEYS" not in line and "sparkdiag --" not in line:
                self.assertIn(line, b)


class TestAES(unittest.TestCase):
    def test_fips197_vector(self):
        a = sd.AES128(bytes(range(16)))
        self.assertEqual(a.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_ctr_matches_accelerator_if_present(self):
        key, iv = bytes(range(16)), bytes(range(16, 32))
        data = bytes(range(256)) * 3 + b"tail"
        pure = sd.AES128(key).ctr(iv, data)
        self.assertEqual(len(pure), len(data))
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest("cryptography not installed")
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        self.assertEqual(pure, enc.update(data) + enc.finalize())
        # counter wrap across the 128-bit boundary
        iv2 = b"\xff" * 16
        enc = Cipher(algorithms.AES(key), modes.CTR(iv2)).encryptor()
        self.assertEqual(sd.AES128(key).ctr(iv2, data), enc.update(data) + enc.finalize())


class TestMods(unittest.TestCase):
    def test_keys_derived_from_binary_decode_log_and_mle(self):
        kr = keyring()
        self.assertIn("629.580.34", kr.binary_versions)
        self.assertTrue(any("landmark" in n for n in kr.notes))
        data = slurp(need(os.path.join(EVIDENCE, "logs-20261009-010700", "GpuStress", "fieldiag.log")), "rb")
        res = sd.mods_decode(data, kr)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertEqual(res["version"], "629.580.34")
        self.assertEqual(res["plaintext"], slurp(need(DECODED_LOG), "rb"))
        s = sd.mods_log_summary(res["plaintext"].decode())
        self.assertEqual(s["boot_status"], "0x00000008")
        self.assertEqual(s["errors"][0]["code"], 900167)
        self.assertEqual(s["errors"][0]["rc"], 167)
        self.assertTrue(s["complete"])
        self.assertFalse(s["boot_status_decode"]["gfw_boot_complete"])
        mle = slurp(os.path.join(EVIDENCE, "logs-20261009-010700", "GpuStress", "fieldiag.mle"), "rb")
        res = sd.mods_decode(mle, kr)
        self.assertTrue(res["ok"])
        ents = sd.mle_entries(res["plaintext"])
        self.assertEqual(len(ents), 52)
        rcs = [e for e in ents if e["rc"] is not None]
        self.assertEqual(rcs[0]["rc"], 167)
        self.assertAlmostEqual(ents[1]["t"], 1791508033.096, places=2)

    def test_spec_file_decode_matches_reference(self):
        kr = keyring()
        data = slurp(need(os.path.join(os.path.dirname(MODS_BIN), "check_config.spe")), "rb")
        res = sd.mods_decode(data, kr)
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertTrue(res["size_match"])
        self.assertEqual(res["plaintext"], slurp(need(DECODED_CHECK_CONFIG), "rb"))

    def test_other_build_fails_gracefully(self):
        kr = keyring()
        p = need(os.path.join(OLD_RUNS, "logs-20261009-005635", "GpuStress", "fieldiag.log"))
        res = sd.mods_decode(slurp(p, "rb"), kr)
        self.assertFalse(res["ok"])
        self.assertIn("629.580.36", res["reason"])
        self.assertIn("629.580.34", res["reason"])

    def test_no_binary_shareable_vs_internal(self):
        p = need(os.path.join(EVIDENCE, "logs-20261009-010700", "GpuStress", "fieldiag.log"))
        data = slurp(p, "rb")
        kr = sd.ModsKeyring.from_binary("/nonexistent/fieldiag")
        res = sd.mods_decode(data, kr)
        self.assertFalse(res["ok"])
        self.assertIn("no candidate keys", res["reason"])
        internal = load(build_internal(), "sparkdiag_internal2")
        kr2 = internal.ModsKeyring.from_binary("/nonexistent/fieldiag")
        res2 = internal.mods_decode(data, kr2)
        self.assertTrue(res2["ok"])
        self.assertTrue(res2["key_source"].startswith("embedded-629.580.34"))
        self.assertEqual(res2["plaintext"], slurp(need(DECODED_LOG), "rb"))

    def test_header_parse_and_classify(self):
        self.assertEqual(sd.mods_classify(b"\xf1\x1a\x81" + b"\0" * 100), 6)
        self.assertEqual(sd.mods_classify(b"\xf1\x1a\x80" + b"\0" * 100), 5)
        self.assertEqual(sd.mods_classify(b"plain"), 0)
        self.assertFalse(sd.mods_decode(b"", keyring() if os.path.exists(MODS_BIN) else sd.ModsKeyring())["ok"])

    def test_rundir_analysis(self):
        kr = keyring()
        r = sd.analyze_mods_rundir(need(os.path.join(EVIDENCE, "logs-20261009-010700")), kr)
        self.assertEqual(r["final_result"], "FAIL")
        self.assertEqual(r["error_code"], 900167)
        self.assertEqual(r["boot_status"], "0x00000008")
        self.assertRegex(r["serial"] or "", r"^[A-Z0-9]{8,}$")  # the unit serial from the run header
        self.assertFalse(r["truncated"])
        r2 = sd.analyze_mods_rundir(need(os.path.join(OLD_RUNS, "logs-20261009-001052")), kr)
        self.assertTrue(r2["truncated"])
        self.assertEqual(r2["unfinished_tests"], ["GpuStress"])
        self.assertTrue(all(f["decoded"] is False for f in r2["mods_files"]))
        self.assertIn("MODS log present, not decoded", r2["mods_files"][0]["status"])


class TestRecords(unittest.TestCase):
    def summ(self, rel, node):
        rec = sd.parse_record_file(need(os.path.join(RUNS, rel)))
        return sd.summarize_run(rec, node)

    def test_sustain60_1200_reproduces_findings(self):
        s0 = self.summ("spark0/20261009-012813-s0-sustain60-1200.log", "spark0")
        s1 = self.summ("spark1/20261009-012814-s1-sustain60-1200.log", "spark1")
        self.assertEqual((s0["cap"], s0["pattern"], s0["kind"]), (1200, "sustain", "gpuload"))
        self.assertTrue(s0["ended"] and s1["ended"])
        self.assertAlmostEqual(s0["p_mean"], 28.1, delta=0.5)
        self.assertAlmostEqual(s1["p_mean"], 31.0, delta=0.5)
        self.assertAlmostEqual(s0["z0_rise_5s"], 2.7, delta=0.6)
        self.assertAlmostEqual(s1["z0_rise_5s"], 15.7, delta=0.6)
        self.assertAlmostEqual(s0["z0_peak"], 51.8, delta=0.5)
        self.assertAlmostEqual(s1["z0_peak"], 63.8, delta=0.5)
        self.assertNotIn("pulses", s0)

    def test_sustain30_1800_c_per_w(self):
        s0 = self.summ("spark0/20261009-013849-s0-sustain30-1800.log", "spark0")
        s1 = self.summ("spark1/20261009-013850-s1-sustain30-1800.log", "spark1")
        self.assertAlmostEqual(s0["c_per_w_30s"], 0.30, delta=0.04)
        self.assertAlmostEqual(s1["c_per_w_30s"], 0.83, delta=0.04)
        self.assertGreater(s1["c_per_w_30s"] / s0["c_per_w_30s"], 2.4)
        self.assertAlmostEqual(s1["z0_peak"], 85.0, delta=0.3)

    def test_pulses_1800(self):
        s0 = self.summ("spark0/20261009-013253-s0-pulse-1800.log", "spark0")
        s1 = self.summ("spark1/20261009-013253-s1-pulse-1800.log", "spark1")
        self.assertTrue(s0["pattern"].startswith("pulse"))
        r0 = [p["rise"] for p in s0["pulses"][:3]]
        r1 = [p["rise"] for p in s1["pulses"][:3]]
        self.assertTrue(all(7.5 <= r <= 12 for r in r0), r0)
        self.assertTrue(all(30 <= r <= 37 for r in r1), r1)
        self.assertAlmostEqual(s1["z0_peak"], 76.3, delta=0.3)

    def test_trip_2100_plateau(self):
        s = self.summ("sweep/spark1/20261009-014420-s1-trip-2100.log", "spark1")
        self.assertIsNotNone(s["plateau"])
        self.assertGreaterEqual(s["plateau"]["z0_min"], 94.0)
        self.assertLessEqual(s["plateau"]["z0_max"], 97.5)
        self.assertGreater(s["plateau"]["seconds"], 10)
        self.assertLess(s["plateau"]["sm_min"], s["plateau"]["sm_max"])
        self.assertFalse(s["died"])

    def test_2400_cont_died(self):
        rec = sd.parse_record_file(need(os.path.join(RUNS, "sweep/spark1/20261009-021210-spark1-sw-2400-cont.log")))
        s = sd.summarize_run(rec, "spark1")
        self.assertEqual(rec["kind"], "khzload")
        self.assertFalse(rec["ended"])
        self.assertTrue(s["died"])
        self.assertEqual((s["cap"], s["pattern"]), (2400, "cont"))
        self.assertLess(s["death"]["t_after_load_s"], 0.15)
        self.assertAlmostEqual(s["death"]["z0_last_c"], 38.4, delta=0.2)
        self.assertEqual(s["death"]["sm_last"], 2392)
        self.assertEqual(s["ramp_ms"], 0)
        self.assertEqual(s["sm_frac"], 1.0)

    def test_tag_info(self):
        self.assertEqual(sd.tag_info("s1-sustain60-1200")["cap"], 1200)
        self.assertEqual(sd.tag_info("s1-sustain60-1200")["node"], "spark1")
        self.assertEqual(sd.tag_info("spark1-sw-2100-100-20", {"on_us": 100, "off_us": 20})["pattern"], "100-20")
        self.assertEqual(sd.tag_info("s1-trip-2100", {"pattern": "square", "on_ms": 20000, "off_ms": 1000, "seconds": 20})["pattern"], "pulse20s/1s")
        self.assertEqual(sd.tag_info("x-2400-cont", {"on_us": 100, "off_us": 0, "ramp_ms": 200, "sm_frac": 0.5})["pattern"], "cont+ramp200ms+sm50%")
        self.assertEqual(sd.tag_info("03-sweep-1500-1ms", {"on_us": 1000, "off_us": 1000})["cap"], 1500)

    def test_torn_last_line_tolerated(self):
        d = tmpdir("torn")
        p = os.path.join(d, "x.log")
        with open(p, "w") as f:
            f.write('START {"tag":"t-1200","on_us":100,"off_us":0,"seconds":10,"t":1.0,"m":1.0}\n')
            f.write('LAUNCHED {"t":1.1,"m":1.1}\n')
            f.write('TEL {"p_inst_mw":20000,"sm_mhz":1000,"gpu_c":40,"thermal_zone0":40000,"t":1.2,"m":1.2}\n')
            f.write('TEL {"p_inst_mw":30000,"sm_')
        rec = sd.parse_record_file(p)
        self.assertEqual(len(rec["tel"]), 1)
        self.assertFalse(rec["ended"])


class TestSpbm(unittest.TestCase):
    def test_step_window_and_pm_state(self):
        sp = sd.parse_spbm_log(need(os.path.join(RUNS, "sweep/spark1/spbm-20261009-020739.log")))
        self.assertGreater(len(sp["rows"]), 13000)
        self.assertIn("gpu", sp["keys"])       # legacy gpu_out -> gpu
        self.assertEqual(sp["interval_ms"], 20)
        rec = sd.parse_record_file(need(os.path.join(RUNS, "sweep/spark1/20261009-021210-spark1-sw-2400-cont.log")))
        st = sd.spbm_step_analysis(sp, rec["load_start_t"])
        self.assertTrue(st["log_ends_in_window"])
        self.assertLessEqual(st["ms_onset_to_last"], 120)
        self.assertGreaterEqual(st["ms_onset_to_last"], 60)
        self.assertAlmostEqual(st["last"]["dc_in_w"], 125.1, delta=0.2)
        self.assertAlmostEqual(st["last"]["gpu_w"], 95.1, delta=0.2)
        self.assertAlmostEqual(st["last"]["soc_pkg_w"], 106.3, delta=0.2)
        self.assertAlmostEqual(st["last"]["tj_c"], 38.5, delta=0.2)
        self.assertFalse(st["pm_state_last_5s"]["any_changed"])
        self.assertEqual(st["pm_state_last_5s"]["pl1_ec"]["values"], [140000])
        self.assertEqual(st["pm_state_last_5s"]["spl1_ec"]["values"], [231000])
        self.assertEqual(st["pm_state_last_5s"]["prochot"]["values"], [1])

    def test_tj_register_cadence(self):
        sp = sd.parse_spbm_log(need(os.path.join(RUNS, "sweep/spark1/spbm-20261009-020739.log")))
        cad = sd.spbm_tj_cadence(sp)
        self.assertGreater(cad["n"], 1000)
        self.assertTrue(50 <= cad["median_ms"] <= 70, cad)
        self.assertTrue(130 <= cad["p90_ms"] <= 220, cad)
        self.assertTrue(30 <= cad["p10_ms"] <= 50, cad)
        rec = sd.parse_record_file(need(os.path.join(RUNS, "sweep/spark1/20261009-021210-spark1-sw-2400-cont.log")))
        st = sd.spbm_step_analysis(sp, rec["load_start_t"])
        self.assertEqual(st["tj_updates_onset_to_last"], 2)
        self.assertTrue(st["cut_within_2_tj_updates"])

    def test_2100_cont_max_power(self):
        sp = sd.parse_spbm_log(need(os.path.join(RUNS, "sweep/spark1/spbm-20261009-020739.log")))
        rec = sd.parse_record_file(need(os.path.join(RUNS, "sweep/spark1/20261009-020951-spark1-sw-2100-cont.log")))
        st = sd.spbm_run_stats(sp, rec["t_first"], rec["t_last"])
        self.assertAlmostEqual(st["dc_in_max_w"], 142.4, delta=0.2)
        self.assertAlmostEqual(st["gpu_max_w"], 90.9, delta=0.3)
        self.assertFalse(st["pm_state"]["any_changed"])

    def test_units(self):
        self.assertAlmostEqual(sd.spbm_c({"tj": 3239}, "tj"), 50.75, places=1)
        self.assertEqual(sd.spbm_w({"dc_in": 125124}, "dc_in"), 125.1)
        self.assertEqual(sd.SPBM_BY_NAME["tj"][1], 0x818)
        self.assertEqual(sd.SPBM_BY_NAME["dc_in"][1], 0x31C)
        self.assertEqual(sd.ACPI_TZ_TO_SPBM["TSOC"], "tj")
        for lo, hi, _ in sd.NEVER_TOUCH_PHYS:
            self.assertTrue(hi <= sd.SPBM_BASE or lo >= sd.SPBM_BASE + sd.SPBM_SIZE)


class TestStepLogsAndFlightrec(unittest.TestCase):
    def test_sweep_log_running_step(self):
        m = sd.parse_step_log(need(os.path.join(RUNS, "sweep/spark1/sweep-spark1-20261009-020239.log")))
        self.assertEqual(len(m["steps"]), 21)
        self.assertFalse(m["ended"])
        self.assertEqual((m["running_at_end"]["cap"], m["running_at_end"]["pattern"]), ("2400", "cont"))

    def test_flightrec(self):
        fr = sd.parse_flightrec(need(os.path.join(FLIGHTREC, "flightrec-20261009-010711-46053.log")))
        self.assertEqual(fr["tests"], ["GpuStress"])
        self.assertAlmostEqual(fr["z0_max_c"], 79.9, delta=0.2)
        self.assertTrue(any("mods" in l for l in fr["kmsg"]))


class TestParsers(unittest.TestCase):
    def test_nvidia_smi_q(self):
        txt = slurp(need(BASELINE0)).split("===ESRT")[0]
        q = sd.parse_nvidia_smi_q(txt)
        self.assertEqual(q["Driver Version"], "580.159.03")
        gpu = next(v for k, v in q.items() if k.startswith("GPU "))
        self.assertEqual(gpu["VBIOS Version"], "9A.0B.2D.00.00")
        self.assertEqual(gpu["GSP Firmware Version"], "580.159.03")
        self.assertEqual(sd._get(gpu, "PCI", "Device Id"), "0x2E1210DE")
        ctr = sd.parse_counters_us(gpu["Clocks Event Reasons Counters"])
        self.assertEqual(ctr["SW Thermal Slowdown"], 166242)
        self.assertEqual(ctr["HW Power Braking"], 0)

    def test_list_boots_text(self):
        txt = slurp(need(BASELINE0)).split("===BOOTS")[1].split("===CMDLINE")[0]
        boots = sd.parse_list_boots_text(txt)
        self.assertEqual(len(boots), 25)
        self.assertEqual(boots[-1]["index"], 0)
        self.assertEqual(boots[0]["boot_id"], "52bfc4c32d084b259bbe253aebb051c4")
        self.assertIsNotNone(boots[0]["first"])

    def test_rminit_and_xid_decode(self):
        d = sd.decode_nvrm_line("NVRM: RmInitAdapter failed! (0x62:0x65:2028)")
        self.assertEqual(d["rminit"]["initStatus_name"], "RM_INIT_FIRMWARE_INIT_FAILED")
        self.assertEqual(d["rminit"]["rmStatus_name"], "NV_ERR_TIMEOUT")
        self.assertIn("osinit.c", d["rminit"]["line_hint"])
        d = sd.decode_nvrm_line("NVRM: Xid (PCI:000f:01:00): 119, pid=1234, name=nvidia-smi, Timeout after 6s of waiting for RPC response")
        self.assertEqual(d["xid"]["code"], 119)
        self.assertTrue(sd.decode_nvrm_line("NVRM: ksec2PrepareBootCommands_GB20B: SEC2 secure boot partition timed out.")["sec2_boot_timeout_gb20b"])

    def test_vsec_decode(self):
        d = sd.decode_vsec_debug_sec(0)
        self.assertFalse(d["sec_fault_latched"])
        d = sd.decode_vsec_debug_sec((1 << 8) | (1 << 9) | (5 << 16))
        self.assertEqual(d["fault_bits"], ["GPMVDD_VMON", "GPCVDD_VMON"])
        self.assertEqual(d["iff_pos"], 5)

    def test_cdi_uvm_major(self):
        y = "cdiVersion: 0.5.0\ndevices:\n- name: all\n  containerEdits:\n    deviceNodes:\n    - path: /dev/nvidia0\n      type: c\n      major: 195\n      minor: 0\n    - path: /dev/nvidia-uvm\n      type: c\n      major: 510\n      minor: 0\n"
        self.assertEqual(sd.cdi_uvm_major(y), (510, "yaml"))
        j = json.dumps({"devices": [{"name": "all", "containerEdits": {"deviceNodes": [{"path": "/dev/nvidia-uvm", "major": 509}]}}]})
        self.assertEqual(sd.cdi_uvm_major(j), (509, "json"))
        self.assertEqual(sd.cdi_uvm_major("nothing: here")[0], None)

    def test_bar0_plan_excludes_side_effect_registers(self):
        for off, _, _ in sd.BAR0_PLAN:
            for lo, hi, _ in sd.BAR0_EXCLUDED:
                self.assertFalse(lo <= off < hi)
        self.assertIn(0x5E0, [o for o, _, _ in sd.BAR0_PLAN])
        self.assertEqual([o for o, _, _ in sd.BAR0_PLAN][:4], [0x0, 0xA00, 0x5E4, 0x5E0])

    def test_shutdown_regex(self):
        self.assertTrue(sd._SHUTDOWN_RE.search("Oct 09 systemd-journald[1]: Journal stopped"))
        self.assertTrue(sd._SHUTDOWN_RE.search("systemd[1]: Reached target Power-Off."))
        self.assertFalse(sd._SHUTDOWN_RE.search("vllm[1234]: prefill 1234 tokens"))


class TestAnalysisAndReport(unittest.TestCase):
    def test_two_node_report_reproduces_findings(self):
        need(os.path.join(RUNS, "spark0"))
        need(os.path.join(RUNS, "sweep", "spark1"))
        out = tmpdir("rep")
        rep, md = sd.build_report([os.path.join(RUNS, "spark0"), os.path.join(RUNS, "sweep", "spark1")], None, out, 500, "spark0")
        ids = [f["id"] for f in rep["findings"]]
        self.assertIn("heat-path", ids)
        self.assertIn("load-step-poweroff", ids)
        self.assertIn("clock-band", ids)
        self.assertIn("thermal-plateau", ids)
        hp = next(f for f in rep["findings"] if f["id"] == "heat-path")
        self.assertEqual(hp["nodes"], ["spark1", "spark0"])
        self.assertTrue(any("[O]" in e for e in hp["evidence"]) and any("[C]" in e for e in hp["evidence"]) and any("[H]" in e for e in hp["evidence"]))
        et = next(f for f in rep["findings"] if f["id"] == "load-step-poweroff")
        self.assertIn("2400", et["title"])
        self.assertIn("38.5", et["title"])
        self.assertIn("thermal not excluded", et["title"])
        self.assertTrue(any("did not change before the cut" in e for e in et["evidence"]))
        self.assertTrue(any("142.4" in e for e in et["evidence"]))
        self.assertTrue(any("THERMAL NOT EXCLUDED" in e for e in et["evidence"]))
        self.assertTrue(any("cadence" in e and "median" in e for e in et["evidence"]))
        joined = " ".join(et["evidence"]) + et["title"]
        self.assertNotIn("not thermal", joined.lower())
        self.assertNotIn("electrical, not", joined.lower())
        cb = next(f for f in rep["findings"] if f["id"] == "clock-band")
        self.assertIn("survived <= 2100 MHz, died at >= 2400 MHz", cb["title"])
        self.assertIn("V/F-dependent power density", cb["title"])
        self.assertTrue(any("not by itself proof of an electrical fault" in e for e in cb["evidence"]))
        hp = next(f for f in rep["findings"] if f["id"] == "heat-path")
        self.assertIn("primary diagnostic", hp["title"])
        self.assertTrue(any("95.1" in e for e in cb["evidence"]))
        self.assertEqual(rep["clock_band"]["spark1"]["band"], (2100, 2400))
        self.assertEqual(len(rep["deaths"]), 1)
        self.assertEqual(rep["deaths"][0]["cap"], 2400)
        self.assertTrue(os.path.exists(os.path.join(out, "report.md")))
        self.assertTrue(os.path.exists(os.path.join(out, "report.json")))
        self.assertIn("## Last 500 ms before power loss", md)
        self.assertIn("125.1", md)
        self.assertIn("## Reproduction recipe", md)
        self.assertIn("--kill-caps 2200,2300", md)
        self.assertIn("spark1-sw-2400-cont", md)
        jload(os.path.join(out, "report.json"))

    def test_compare_nodes_ratio(self):
        runs = []
        for rel, node in (("spark0/20261009-012813-s0-sustain60-1200.log", "spark0"), ("spark1/20261009-012814-s1-sustain60-1200.log", "spark1")):
            runs.append(sd.summarize_run(sd.parse_record_file(need(os.path.join(RUNS, rel))), node))
        rows = sd.compare_nodes(runs, "spark0")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["power_equal"])
        self.assertGreater(rows[0]["z0_rise_5s_ratio"], 4)

    def test_forensics_offline_gfw_stall(self):
        need(EVIDENCE)
        out = tmpdir("fo")
        args = type("A", (), {})()
        args.bdf = None
        args.boots = 2
        args.prev_boots = 1
        args.bar0 = False
        args.mods_bin = MODS_BIN
        args.mods_logs = [EVIDENCE, OLD_RUNS]
        args.no_mods_decode = False
        args.mods_max_runs = 30
        args.flightrec_dir = FLIGHTREC
        args.out = out
        fo = sd.collect_forensics(args, None)
        sd.write_json_durable(os.path.join(out, "forensics.json"), fo)
        runs = fo["items"]["mods"]["data"]["runs"]
        self.assertTrue(any(r.get("boot_status") == "0x00000008" for r in runs))
        rep, md = sd.build_report([out], None, None, 500, None)
        ids = [f["id"] for f in rep["findings"]]
        self.assertIn("gfw-boot-stall", ids)
        if os.path.isdir(OLD_RUNS):
            self.assertIn("fieldiag-truncated", ids)
            self.assertIn("mods-not-decoded", ids)
        self.assertIn("0x00000008", md)

    def _synthetic_khz_run(self, path, tag, cap, p_w, z0_base, z0_peak, seconds=10, on_us=100.0, off_us=0.0):
        """A khzload-format record that ended normally (used for fabricated fixtures)."""
        t0, m0 = 1791600000.0, 1000.0
        period = (on_us + off_us) / 1e6
        with open(path, "w") as f:
            f.write('START {"tag":"%s","warps":8,"ramp_ms":0.0,"sm_frac":1.0,"on_us":%s,"off_us":%s,"seconds":%d,"sms":48,"blocks":96,"period_us":%s,"freq_khz":1.0,"duty":1.0,"t":%.4f,"m":%.4f}\n' % (tag, on_us, off_us, seconds, (on_us + off_us), t0, m0))
            f.write('LAUNCHED {"t":%.4f,"m":%.4f}\n' % (t0 + 0.01, m0 + 0.01))
            n = int((seconds + 2.0) / 0.02)
            for i in range(n):
                dt = i * 0.02
                load = 1.5 <= dt <= 1.5 + seconds and (off_us == 0 or ((dt - 1.5) % period) < on_us / 1e6)
                if off_us == 0:
                    z = z0_base + (z0_peak - z0_base) * min(1.0, max(0.0, (dt - 1.5) / seconds)) if dt >= 1.5 else z0_base
                else:
                    ph = ((dt - 1.5) % period) if dt >= 1.5 else 0.0
                    z = z0_base + (z0_peak - z0_base) * (min(1.0, ph / (on_us / 1e6)) if load else max(0.0, 1.0 - (ph - on_us / 1e6) / (off_us / 1e6)))
                f.write('TEL {"p_inst_mw":%d,"p_avg_mw":%d,"sm_mhz":%d,"gpu_c":%d,"thermal_zone0":%d,"thermal_zone1":40000,"thermal_zone3":41000,"thermal_zone5":%d,"fan1":9000,"fan2":13500,"t":%.4f,"m":%.4f}\n' % (
                    (p_w if load else 12) * 1000, (p_w if load else 12) * 1000, cap - 8, 40 + (20 if load else 0), int(z * 1000), int(z * 1000) - 500, t0 + dt, m0 + dt))
            f.write('DONE {"aborted":false,"t":%.4f,"m":%.4f}\n' % (t0 + n * 0.02, m0 + n * 0.02))
            f.write('END {"t":%.4f,"m":%.4f}\n' % (t0 + n * 0.02 + 0.06, m0 + n * 0.02 + 0.06))

    def test_before_after_intervention_mode(self):
        need(os.path.join(RUNS, "spark0"))
        need(os.path.join(RUNS, "sweep", "spark1"))
        after = tmpdir("after")
        # the 'after' unit heats like the reference (reuse spark0's thermal records) and survives the killing step
        for n in ("20261009-012813-s0-sustain60-1200.log", "20261009-013253-s0-pulse-1800.log", "20261009-013849-s0-sustain30-1800.log"):
            shutil.copy(os.path.join(RUNS, "spark0", n), os.path.join(after, n))
        self._synthetic_khz_run(os.path.join(after, "20261009-033000-after-killstep-2400-cont.log"), "after-killstep-2400-cont", 2400, 107, 44.0, 75.0)
        out = tmpdir("ba")
        rep, md = sd.build_report([os.path.join(RUNS, "spark0")], {os.path.join(RUNS, "spark0"): "spark0", os.path.join(RUNS, "sweep", "spark1"): "spark1-before", after: "spark1-after"},
                                  out, 500, "spark0", before=os.path.join(RUNS, "sweep", "spark1"), after=after)
        self.assertEqual(rep["intervention"], {"before": "spark1-before", "after": "spark1-after"})
        iv = next(f for f in rep["findings"] if f["id"] == "intervention-effect")
        self.assertEqual(rep["findings"][0]["id"], "intervention-effect")
        self.assertIn("removed the power-off at cap 2400", iv["title"])
        self.assertIn("normalised the hotspot heating", iv["title"])
        self.assertTrue(any("cap 2400: before = power lost" in e and "after = survived 1/1" in e for e in iv["evidence"]))
        self.assertTrue(any("reference" in e for e in iv["evidence"]))
        self.assertTrue(any("is thermal" in e for e in iv["evidence"]))
        self.assertIn("intervention removed the power-off", md)
        # CLI form
        r = subprocess.run([sys.executable, os.path.join(ROOT, "sparkdiag.py"), "compare", "--before", os.path.join(RUNS, "sweep", "spark1"), "--after", after,
                            "--out", os.path.join(out, "cli")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("intervention-effect", open(os.path.join(out, "cli", "report.json")).read())

    def test_single_node_sparkdiag_tree_primary_diagnostic(self):
        """A sparkdiag-generated single-node result tree: the 30 s sustain step at 0.8 C/W must trigger heat-path-single
        and a 3 s/7 s khzload pulse record must get a per-pulse table."""
        d = tmpdir("single")
        rec = os.path.join(d, "stress", "rec")
        os.makedirs(rec)
        self._synthetic_khz_run(os.path.join(rec, "20261010-010000-01-thermal-1800-sustain.log"), "01-thermal-1800-sustain", 1800, 50, 40.0, 80.0, seconds=30)
        self._synthetic_khz_run(os.path.join(rec, "20261010-010100-02-thermal-1800-pulse3s7s.log"), "02-thermal-1800-pulse3s7s", 1800, 50, 40.0, 70.0, seconds=30, on_us=3e6, off_us=7e6)
        plan = [{"id": "01-thermal-1800-sustain", "status": "done", "cap": 1800, "pattern": "sustain", "experiment": "thermal"},
                {"id": "02-thermal-1800-pulse3s7s", "status": "done", "cap": 1800, "pattern": "pulse3s/7s", "experiment": "thermal"}]
        sd.write_json_durable(os.path.join(d, "stress", "state.json"), {"status": "finished", "plan": plan, "args": {}})
        rep, md = sd.build_report([d], None, None, 500, None)
        ids = [f["id"] for f in rep["findings"]]
        self.assertIn("heat-path-single", ids)
        runs = rep["runs"][os.path.basename(d)]
        sus = next(r for r in runs if r["tag"] == "01-thermal-1800-sustain")
        self.assertEqual(sus["pattern"], "sustain")
        self.assertAlmostEqual(sus["c_per_w_30s"], 0.8, delta=0.05)
        pul = next(r for r in runs if r["tag"] == "02-thermal-1800-pulse3s7s")
        self.assertEqual(pul["pattern"], "pulse3s/7s")
        self.assertEqual(len(pul["pulses"]), 3)
        self.assertTrue(all(p["rise"] > 20 for p in pul["pulses"]), pul["pulses"])
        self.assertIn("Per-pulse zone0 response", md)
        # the same plan labels pair with legacy gpuload pulse records in the comparison
        legacy = sd.summarize_run(sd.parse_record_file(need(os.path.join(RUNS, "spark0", "20261009-013253-s0-pulse-1800.log"))), "spark0")
        self.assertEqual(legacy["pattern"], pul["pattern"])

    def test_single_node_degraded_report(self):
        d = tmpdir("empty")
        rep, md = sd.build_report([d], None, None, 500, None)
        self.assertEqual(rep["findings"], [])
        self.assertIn("No fault was reproduced", md)


class TestCliDegradation(unittest.TestCase):
    """Runs the real CLI on this (non-GB10) machine: every missing piece must be named, exit codes right."""

    def run_cli(self, *a, script="sparkdiag.py", timeout=240):
        return subprocess.run([sys.executable, os.path.join(ROOT, script)] + list(a), capture_output=True, text=True, timeout=timeout)

    def test_inventory_and_forensics_degrade(self):
        out = tmpdir("cli")
        r = self.run_cli("inventory", "--out", out, "--boots", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        inv = jload(os.path.join(out, "inventory.json"))
        self.assertIn("items", inv)
        for name in ("dmi", "kernel", "nvidia", "pci", "thermal", "fan", "nvme", "fieldiag", "cdi", "boots"):
            self.assertIn(name, inv["items"])
            if not inv["items"][name]["ok"]:
                self.assertTrue(inv["items"][name].get("note"), name)
        r = self.run_cli("forensics", "--out", out, "--boots", "2", "--prev-boots", "1", "--mods-bin", "/nonexistent", "--flightrec-dir", "/nonexistent")
        self.assertEqual(r.returncode, 0, r.stderr)
        fo = jload(os.path.join(out, "forensics.json"))
        self.assertIn("bar0", fo["items"])
        self.assertFalse(fo["items"]["bar0"]["ok"])
        self.assertIn("not requested", fo["items"]["bar0"]["note"])
        r = self.run_cli("report", out, "--out", os.path.join(out, "rep"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "rep", "report.md")))

    def test_telemetry_short_run(self):
        out = tmpdir("tel")
        r = self.run_cli("telemetry", "--out", out, "--seconds", "1", "--rate-ms", "50", "--print-every", "0", "--counters-s", "0")
        self.assertEqual(r.returncode, 0, r.stderr)
        files = [f for f in os.listdir(out) if f.startswith("telemetry-")]
        self.assertEqual(len(files), 1)
        rec = sd.parse_record_file(os.path.join(out, files[0]))
        self.assertEqual(rec["kind"], "sparkdiag")
        self.assertTrue(rec["ended"])
        self.assertGreaterEqual(len(rec["tel"]), 10)
        self.assertIn("hot_c", rec["tel"][0])
        self.assertIn("spbm", rec["hdr"])

    def test_stress_requires_consent_and_dry_run(self):
        out = tmpdir("stress")
        r = self.run_cli("stress", "--out", out)
        self.assertEqual(r.returncode, 3)
        self.assertIn("--i-understand-this-can-power-off-the-node", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "stress")))
        r = self.run_cli("stress", "--out", out, "--dry-run", "--experiments", "killstep,ramp,partial,sweep", "--caps", "1200,2100", "--cap", "2400",
                         "--i-understand-this-can-power-off-the-node")
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)["plan"]
        ids = [s["id"] for s in plan]
        self.assertEqual(len([s for s in plan if s["experiment"] == "ramp"]), 4)
        self.assertEqual(sorted({s["ramp_ms"] for s in plan if s["experiment"] == "ramp"}), [0.0, 50.0, 200.0, 1000.0])
        self.assertEqual(sorted({s["sm_frac"] for s in plan if s["experiment"] == "partial"}), [0.25, 0.5, 0.75, 1.0])
        self.assertEqual(len([s for s in plan if s["experiment"] == "sweep"]), 10)
        self.assertTrue(any("killstep-2400" in i for i in ids))
        self.assertFalse(os.path.exists(os.path.join(out, "stress")))

    def test_all_runs_safe_subcommands(self):
        out = tmpdir("all")
        r = self.run_cli("all", "--out", out, "--boots", "2", "--prev-boots", "1", "--mods-bin", "/nonexistent", "--flightrec-dir", "/nonexistent")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "report", "report.md")))


class TestStressMachinery(unittest.TestCase):
    def test_gpu_load_source_abort_flag_is_host_mapped(self):
        src = sd.GPU_LOAD_SRC
        ast.parse(src)  # valid Python
        self.assertIn("hostAlloc(4, HOST_ALLOC_MAPPED)", src)
        self.assertIn("HOST_ALLOC_MAPPED = 2", src)
        self.assertIn("_mapped_device_ptr(flag_host)", src)
        self.assertIn("cudaDevAttrUnifiedAddressing", src)  # UVA fallback (CuPy 14 lacks hostGetDevicePointer)
        self.assertIn("volatile int *abort_flag", src)
        self.assertIn("ctypes.c_int.from_address(flag_host)", src)
        self.assertIn('rec("FLAGCHECK"', src)
        self.assertIn('rec("HARDSTOP"', src)
        self.assertIn("os._exit(3)", src)
        self.assertNotIn("abort_dev.fill", src)   # the broken CuPy-fill-on-another-stream path
        self.assertNotIn("cp.zeros(1, dtype=cp.int32)\nabort", src)
        self.assertIn("cp.uint64(flag_dev)", src)
        self.assertIn("--ramp-ms", src)
        self.assertIn("--sm-frac", src)

    def test_plan_skip_and_ids(self):
        args = type("A", (), {})()
        args.experiments = "thermal,killstep"
        args.caps = "1200"
        args.cap = "2400"
        args.kill_caps = "2200,2300"
        args.seconds = 10
        args.sustain_s = 30
        args.skip_steps = "01-"
        plan = sd.build_plan(args)
        self.assertEqual(plan[0]["status"], "skipped")
        self.assertEqual([s["cap"] for s in plan if s["experiment"] == "killstep"], [2200, 2300])
        self.assertEqual(plan[1]["pattern"], "pulse3s/7s")
        self.assertEqual(plan[0]["pattern"], "sustain")
        self.assertEqual(sd.pattern_name(100, 0, 10), "cont")
        self.assertEqual(sd.pattern_name(3e6, 7e6), "pulse3s/7s")
        self.assertEqual(sd.tag_info("s1-pulse-1800", {"pattern": "square", "on_ms": 3000, "off_ms": 7000, "seconds": 30})["pattern"], "pulse3s/7s")
        self.assertEqual(sd.tag_info("x", {"on_us": 100, "off_us": 0, "seconds": 30})["pattern"], "sustain")

    def test_resume_describes_running_step(self):
        d = tmpdir("resume")
        sroot = os.path.join(d, "stress")
        os.makedirs(sroot)
        tel = os.path.join(sroot, "telemetry-x.log")
        with open(tel, "w") as f:
            f.write('HDR {"tag":"stress","t":100.0,"m":1.0}\n')
            f.write('MARK {"text":"BEGIN step=02-killstep-2400-cont cap=2400","t":101.0,"m":2.0}\n')
            f.write('TEL {"p_inst_mw":90000,"sm_mhz":2392,"gpu_c":45,"thermal_zone0":40000,"spbm_dc_in":125100,"spbm_gpu":95100,"spbm_tj":3116,"spbm_prochot":1,"t":101.5,"m":2.5}\n')
        state = {"status": "running", "host": "spark1", "plan": [{"id": "01-killstep-2200-cont", "status": "done", "cap": 2200, "pattern": "cont", "ramp_ms": 0, "sm_frac": 1.0},
                                                                  {"id": "02-killstep-2400-cont", "status": "running", "cap": 2400, "pattern": "cont", "ramp_ms": 0, "sm_frac": 1.0}],
                 "telemetry_file": tel, "args": {"out": d, "experiments": "killstep"}}
        sd.write_json_durable(os.path.join(sroot, "state.json"), state)
        st, info = sd.describe_resume(d)
        self.assertEqual(info["running_step"]["id"], "02-killstep-2400-cont")
        self.assertFalse(info["telemetry_ended_cleanly"])
        self.assertAlmostEqual(info["last_spbm"]["tj_c"], 38.5, delta=0.1)
        self.assertEqual(info["last_spbm"]["dc_in_w"], 125.1)
        self.assertEqual(info["steps_done"], 1)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "sparkdiag.py"), "resume", "--out", d], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("was RUNNING when the records stop", r.stdout)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "sparkdiag.py"), "resume", "--out", d, "--continue"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)
        # the report ingests a sparkdiag stress tree and shows the session
        rep, md = sd.build_report([d], None, None, 500, None)
        self.assertIn("02-killstep-2400-cont=running", md)

    def test_sync_writer_and_durable_json(self):
        d = tmpdir("sync")
        w = sd.SyncWriter(os.path.join(d, "w.log"))
        w.rec("TEL", a=1)
        w.close()
        rec = sd.parse_record_file(os.path.join(d, "w.log"))
        self.assertEqual(rec["tel"][0]["a"], 1)
        sd.write_json_durable(os.path.join(d, "s.json"), {"x": 1})
        self.assertEqual(sd.load_json(os.path.join(d, "s.json"))["x"], 1)
        self.assertFalse(os.path.exists(os.path.join(d, "s.json.tmp")))


if __name__ == "__main__":
    unittest.main()
