from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import tempfile
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass
class SecurityAssociation:
    src: str
    dst: str
    spi: str
    reqid: int
    mode: str
    enc_algorithm: str
    enc_key: str
    auth_algorithm: str
    auth_key: str
    esn: bool = False
    esn_high: int = 0
    nat_t: bool = False
    sport: int | None = None
    dport: int | None = None


@dataclass
class DecryptResult:
    plaintext_path: Path
    esp_sa_path: Path
    report_path: Path
    matched_sas: list[SecurityAssociation]
    decrypted_counts: dict[str, int]
    samples: dict[str, dict[str, str]]
    final_packet_count: int


def normalize_hex(value: str) -> str:
    value = value.strip().lower()
    return value if value.startswith("0x") else "0x" + value


def map_encryption(line: str) -> str:
    lower = line.lower()
    if "cbc(aes)" in lower:
        return "AES-CBC [RFC3602]"
    if "rfc3686(ctr(aes))" in lower or "ctr(aes)" in lower:
        return "AES-CTR [RFC3686]"
    raise ValueError(f"Unsupported encryption algorithm: {line}")


def map_authentication(name: str, trunc_bits: int) -> str:
    mappings = {
        ("sha512", 256): "HMAC-SHA-512-256 [RFC4868]",
        ("sha384", 192): "HMAC-SHA-384-192 [RFC4868]",
        ("sha256", 128): "HMAC-SHA-256-128 [RFC4868]",
        ("sha1", 96): "HMAC-SHA-1-96 [RFC2404]",
        ("sha", 96): "HMAC-SHA-1-96 [RFC2404]",
        ("md5", 96): "HMAC-MD5-96 [RFC2403]",
    }
    key = (name.lower(), int(trunc_bits))
    if key not in mappings:
        raise ValueError(f"Unsupported authentication algorithm: hmac({name})/{trunc_bits}")
    return mappings[key]


def parse_xfrm(text: str) -> list[SecurityAssociation]:
    raw_sas: list[dict] = []
    current: dict | None = None

    for raw in text.splitlines():
        line = raw.strip()

        m = re.fullmatch(r"src\s+(\S+)\s+dst\s+(\S+)", line)
        if m:
            if current and current.get("spi"):
                raw_sas.append(current)
            current = {
                "src": m.group(1),
                "dst": m.group(2),
                "esn": False,
                "esn_high": 0,
                "nat_t": False,
            }
            continue

        if current is None:
            continue

        m = re.search(
            r"proto\s+esp\s+spi\s+(0x[0-9a-fA-F]+)\s+reqid\s+(\d+)\s+mode\s+(\S+)",
            line,
        )
        if m:
            current["spi"] = normalize_hex(m.group(1))
            current["reqid"] = int(m.group(2))
            current["mode"] = m.group(3)
            continue

        m = re.search(
            r"auth-trunc\s+hmac\(([^)]+)\)\s+(0x[0-9a-fA-F]+)\s+(\d+)",
            line,
        )
        if m:
            current["auth_key"] = normalize_hex(m.group(2))
            current["auth_algorithm"] = map_authentication(m.group(1), int(m.group(3)))
            continue

        if line.startswith("enc "):
            m = re.search(r"(0x[0-9a-fA-F]+)$", line)
            if m:
                current["enc_key"] = normalize_hex(m.group(1))
                current["enc_algorithm"] = map_encryption(line)
            continue

        m = re.search(
            r"encap\s+type\s+espinudp\s+sport\s+(\d+)\s+dport\s+(\d+)",
            line,
        )
        if m:
            current["nat_t"] = True
            current["sport"] = int(m.group(1))
            current["dport"] = int(m.group(2))
            continue

        if line.startswith("replay-window") and re.search(r"\besn\b", line):
            current["esn"] = True

        m = re.search(r"seq-hi\s+(0x[0-9a-fA-F]+)", line)
        if m:
            current["esn_high"] = int(m.group(1), 16)

    if current and current.get("spi"):
        raw_sas.append(current)

    required = {
        "src", "dst", "spi", "reqid", "mode",
        "enc_algorithm", "enc_key", "auth_algorithm", "auth_key"
    }
    usable: list[SecurityAssociation] = []
    for sa in raw_sas:
        if required.issubset(sa):
            usable.append(SecurityAssociation(**sa))
    return usable


def _bundle_root() -> Path:
    """
    PyInstaller one-file extracts bundled resources into sys._MEIPASS.
    In source mode, resources are resolved relative to this module.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS).resolve()
    return Path(__file__).resolve().parent


def _private_wireshark_dir() -> Path:
    return _bundle_root() / "wireshark"


def _tool_candidates(name: str) -> list[Path]:
    exe = name if name.lower().endswith(".exe") else (
        f"{name}.exe" if os.name == "nt" else name
    )

    candidates = [
        _private_wireshark_dir() / exe,
    ]

    found = shutil.which(name)
    if found:
        candidates.append(Path(found))

    if os.name == "nt":
        candidates += [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / exe,
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / exe,
        ]

    return candidates


def find_tool(name: str) -> str:
    for path in _tool_candidates(name):
        if path.exists():
            return str(path)
    raise FileNotFoundError(
        f"Could not find {name}. This build is missing its bundled Wireshark runtime."
    )


def _runtime_env(base: dict | None = None) -> dict:
    """
    Ensure bundled TShark/editcap can locate their Wireshark data, plugins,
    and DLLs after PyInstaller extracts the one-file application.
    """
    env = dict(base or os.environ)
    ws = _private_wireshark_dir()

    if ws.exists():
        env["WIRESHARK_DATA_DIR"] = str(ws)
        plugins = ws / "plugins"
        if plugins.exists():
            env["WIRESHARK_PLUGIN_DIR"] = str(plugins)

        current_path = env.get("PATH", "")
        env["PATH"] = str(ws) + (os.pathsep + current_path if current_path else "")

    return env


def run(cmd: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        env=_runtime_env(env),
    )


def get_capture_spis(pcap: Path, tshark: str) -> set[str]:
    result = run([
        tshark, "-r", str(pcap), "-Y", "esp",
        "-T", "fields", "-e", "esp.spi"
    ])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark could not inspect the capture.")

    spis: set[str] = set()
    for line in result.stdout.splitlines():
        for value in line.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                spis.add(f"0x{int(value, 0):08x}")
            except ValueError:
                pass
    return spis


def esp_sa_row(sa: SecurityAssociation) -> list[str]:
    return [
        "IPv4",
        sa.src,
        sa.dst,
        sa.spi,
        sa.enc_algorithm,
        sa.enc_key,
        sa.auth_algorithm,
        sa.auth_key,
        "64-bit" if sa.esn else "32-bit",
        f"0x{sa.esn_high:08x}",
    ]


def write_esp_sa_file(sas: Iterable[SecurityAssociation], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for sa in sas:
            writer.writerow(esp_sa_row(sa))


def capture_basename(path: Path) -> str:
    lower = path.name.lower()
    for extension in (".pcapng", ".pcap", ".cap"):
        if lower.endswith(extension):
            return path.name[:-len(extension)]
    return path.stem


def output_paths(pcap: Path) -> tuple[Path, Path, Path]:
    base = capture_basename(pcap)
    return (
        pcap.parent / f"{base}-plaintext.pcapng",
        pcap.parent / f"{base}-esp_sa",
        pcap.parent / f"{base}-decryption-report.txt",
    )


def create_wireshark_environment(
    sas: list[SecurityAssociation], tempdir: Path
) -> dict:
    config_dir = tempdir / "wireshark"
    config_dir.mkdir(parents=True, exist_ok=True)
    write_esp_sa_file(sas, config_dir / "esp_sa")
    env = os.environ.copy()
    env["WIRESHARK_CONFIG_DIR"] = str(config_dir)
    return env


def verify_decryption(
    pcap: Path,
    sas: list[SecurityAssociation],
    tshark: str,
    env: dict,
) -> tuple[dict[str, int], dict[str, dict[str, str]]]:
    counts: dict[str, int] = {}
    samples: dict[str, dict[str, str]] = {}

    for sa in sas:
        result = run([
            tshark,
            "-o", "esp.enable_encryption_decode:TRUE",
            "-o", "esp.enable_authentication_check:FALSE",
            "-r", str(pcap),
            "-Y", f"esp.spi == {sa.spi}",
            "-T", "fields",
            "-E", "separator=|",
            "-E", "occurrence=a",
            "-E", "aggregator=,",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
        ], env=env)

        if result.returncode != 0:
            counts[sa.spi] = 0
            continue

        count = 0
        sample = None
        for line in result.stdout.splitlines():
            fields = line.split("|")
            while len(fields) < 3:
                fields.append("")
            srcs = [x.strip() for x in fields[1].split(",") if x.strip()]
            dsts = [x.strip() for x in fields[2].split(",") if x.strip()]
            if len(srcs) >= 2 and len(dsts) >= 2:
                count += 1
                if sample is None:
                    sample = {
                        "frame": fields[0].strip(),
                        "outer_src": srcs[0],
                        "outer_dst": dsts[0],
                        "inner_src": srcs[-1],
                        "inner_dst": dsts[-1],
                    }

        counts[sa.spi] = count
        if sample:
            samples[sa.spi] = sample

    return counts, samples


def count_packets(path: Path, tshark: str) -> int:
    result = run([tshark, "-r", str(path), "-T", "fields", "-e", "frame.number"])
    if result.returncode != 0:
        return 0
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def write_report(
    report_path: Path,
    original_pcap: Path,
    plaintext_pcap: Path,
    sas: list[SecurityAssociation],
    counts: dict[str, int],
    samples: dict[str, dict[str, str]],
    final_packet_count: int,
) -> None:
    with report_path.open("w", encoding="utf-8") as handle:
        handle.write("IPsec ESP Decryption Report\n")
        handle.write("===========================\n\n")
        handle.write(f"Original capture:\n  {original_pcap}\n\n")
        handle.write(f"Plaintext capture:\n  {plaintext_pcap}\n\n")
        handle.write(f"Final plaintext packet count: {final_packet_count}\n\n")
        handle.write("Security Associations\n")
        handle.write("=====================\n\n")

        for sa in sas:
            handle.write(f"SPI: {sa.spi}\n")
            handle.write(f"Direction: {sa.src} -> {sa.dst}\n")
            handle.write(f"ReqID: {sa.reqid}\n")
            handle.write(f"Mode: {sa.mode}\n")
            handle.write(f"Encryption: {sa.enc_algorithm}\n")
            handle.write(f"Authentication: {sa.auth_algorithm}\n")
            handle.write(f"ESP packets successfully decrypted: {counts.get(sa.spi, 0)}\n")
            sample = samples.get(sa.spi)
            if sample:
                handle.write(
                    f"Example outer packet: {sample['outer_src']} -> {sample['outer_dst']}\n"
                )
                handle.write(
                    f"Example inner packet: {sample['inner_src']} -> {sample['inner_dst']}\n"
                )
            handle.write("\n")


def decrypt_capture(
    xfrm_text: str,
    pcap: Path,
    *,
    remove_duplicates: bool = True,
    progress: Callable[[int, str], None] | None = None,
) -> DecryptResult:
    progress = progress or (lambda percent, message: None)

    progress(5, "Parsing XFRM state…")
    sas = parse_xfrm(xfrm_text)
    if not sas:
        raise RuntimeError("No usable ESP SAs were found in the pasted XFRM state.")

    tshark = find_tool("tshark")
    editcap = find_tool("editcap")

    progress(15, "Inspecting ESP SPIs in capture…")
    capture_spis = get_capture_spis(pcap, tshark)
    matched = [sa for sa in sas if sa.spi in capture_spis]
    if not matched:
        raise RuntimeError(
            "No XFRM Security Association matches an ESP SPI in this capture. "
            "The capture may belong to a different CHILD_SA or rekey."
        )

    plaintext, esp_sa_path, report_path = output_paths(pcap)
    write_esp_sa_file(matched, esp_sa_path)

    with tempfile.TemporaryDirectory(prefix="ipsec-decrypt-") as td:
        tempdir = Path(td)
        env = create_wireshark_environment(matched, tempdir)

        progress(30, "Verifying ESP decryption…")
        counts, samples = verify_decryption(pcap, matched, tshark, env)
        if sum(counts.values()) == 0:
            raise RuntimeError(
                "SPIs matched, but TShark did not expose any decrypted inner IP packets."
            )

        raw_export = tempdir / "raw-ip-export.pcapng"
        filtered_export = tempdir / "plaintext-filtered.pcapng"

        progress(55, "Exporting decrypted inner IP traffic…")
        result = run([
            tshark,
            "-o", "esp.enable_encryption_decode:TRUE",
            "-o", "esp.enable_authentication_check:FALSE",
            "-r", str(pcap),
            "-U", "IP",
            "-w", str(raw_export),
        ], env=env)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "TShark Raw IP export failed.")

        progress(72, "Removing outer ESP and IKE packets…")
        result = run([
            tshark,
            "-r", str(raw_export),
            "-Y", "not esp and not isakmp",
            "-w", str(filtered_export),
        ])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Plaintext filtering failed.")

        if plaintext.exists():
            plaintext.unlink()

        if remove_duplicates:
            progress(84, "Removing duplicate exported packets…")
            result = run([editcap, "-d", str(filtered_export), str(plaintext)])
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Duplicate cleanup failed.")
        else:
            shutil.copy2(filtered_export, plaintext)

    progress(93, "Validating plaintext capture…")
    final_packet_count = count_packets(plaintext, tshark)
    if final_packet_count == 0:
        raise RuntimeError("The generated plaintext capture contains zero packets.")

    write_report(
        report_path, pcap, plaintext, matched, counts, samples, final_packet_count
    )
    progress(100, "Decryption confirmed.")

    return DecryptResult(
        plaintext_path=plaintext,
        esp_sa_path=esp_sa_path,
        report_path=report_path,
        matched_sas=matched,
        decrypted_counts=counts,
        samples=samples,
        final_packet_count=final_packet_count,
    )
