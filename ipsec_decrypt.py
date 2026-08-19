#!/usr/bin/env python3

import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


BANNER = """
IPsec PCAP Decrypt Helper
=========================
"""


# ============================================================
# Generic helpers
# ============================================================

def run(cmd, env=None):
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        env=env,
    )


def normalize_hex(value):
    value = value.strip().lower()

    if not value.startswith("0x"):
        value = "0x" + value

    return value


def safe_unlink(path):
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def require_tools():
    missing = []

    for tool in ["tshark", "editcap"]:
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        print("ERROR: Missing required tool(s):")
        for tool in missing:
            print(f"  {tool}")

        print()
        print("Install Wireshark CLI tools and try again.")
        sys.exit(1)


# ============================================================
# Algorithm mapping
# ============================================================

def map_encryption(line):
    lower = line.lower()

    if "cbc(aes)" in lower:
        return "AES-CBC [RFC3602]"

    if "rfc3686(ctr(aes))" in lower or "ctr(aes)" in lower:
        return "AES-CTR [RFC3686]"

    raise ValueError(
        f"Unsupported encryption algorithm:\n{line}"
    )


def map_authentication(name, trunc_bits):
    name = name.lower()
    trunc_bits = int(trunc_bits)

    mappings = {
        ("sha512", 256):
            "HMAC-SHA-512-256 [RFC4868]",

        ("sha384", 192):
            "HMAC-SHA-384-192 [RFC4868]",

        ("sha256", 128):
            "HMAC-SHA-256-128 [RFC4868]",

        ("sha1", 96):
            "HMAC-SHA-1-96 [RFC2404]",

        ("sha", 96):
            "HMAC-SHA-1-96 [RFC2404]",

        ("md5", 96):
            "HMAC-MD5-96 [RFC2403]",
    }

    result = mappings.get((name, trunc_bits))

    if result is None:
        raise ValueError(
            f"Unsupported authentication algorithm: "
            f"hmac({name})/{trunc_bits}"
        )

    return result


# ============================================================
# STEP 1 - Paste XFRM
# ============================================================

def paste_xfrm():
    print("[1/4] Paste the XFRM STATE")
    print()
    print("On the IPsec router run:")
    print()
    print("    ip xfrm state")
    print()
    print("Paste the entire output below.")
    print()
    print("When finished, type:")
    print()
    print("    END")
    print()
    print("on a line by itself.")
    print()

    lines = []

    while True:
        try:
            line = input("> ")
        except EOFError:
            break

        if line.strip().upper() == "END":
            break

        lines.append(line)

    return "\n".join(lines)


# ============================================================
# Parse XFRM state
# ============================================================

def parse_xfrm(text):
    sas = []
    current = None

    for raw in text.splitlines():
        line = raw.strip()

        # Beginning of an XFRM state
        match = re.fullmatch(
            r"src\s+(\S+)\s+dst\s+(\S+)",
            line
        )

        if match:
            if current and current.get("spi"):
                sas.append(current)

            current = {
                "src": match.group(1),
                "dst": match.group(2),
                "esn": False,
                "esn_high": 0,
            }

            continue

        if current is None:
            continue

        # SPI / ReqID / Mode
        match = re.search(
            r"proto\s+esp\s+"
            r"spi\s+(0x[0-9a-fA-F]+)\s+"
            r"reqid\s+(\d+)\s+"
            r"mode\s+(\S+)",
            line,
        )

        if match:
            current["spi"] = normalize_hex(
                match.group(1)
            )

            current["reqid"] = int(
                match.group(2)
            )

            current["mode"] = match.group(3)

            continue

        # Authentication
        match = re.search(
            r"auth-trunc\s+"
            r"hmac\(([^)]+)\)\s+"
            r"(0x[0-9a-fA-F]+)\s+"
            r"(\d+)",
            line,
        )

        if match:
            current["auth_key"] = normalize_hex(
                match.group(2)
            )

            current["auth_algorithm"] = (
                map_authentication(
                    match.group(1),
                    match.group(3),
                )
            )

            continue

        # Encryption
        if line.startswith("enc "):
            match = re.search(
                r"(0x[0-9a-fA-F]+)$",
                line
            )

            if match:
                current["enc_key"] = normalize_hex(
                    match.group(1)
                )

                current["enc_algorithm"] = (
                    map_encryption(line)
                )

            continue

        # NAT-T
        match = re.search(
            r"encap\s+type\s+espinudp\s+"
            r"sport\s+(\d+)\s+"
            r"dport\s+(\d+)",
            line,
        )

        if match:
            current["nat_t"] = True
            current["sport"] = int(
                match.group(1)
            )
            current["dport"] = int(
                match.group(2)
            )

            continue

        # Extended Sequence Numbers
        if (
            line.startswith("replay-window")
            and re.search(r"\besn\b", line)
        ):
            current["esn"] = True

        match = re.search(
            r"seq-hi\s+(0x[0-9a-fA-F]+)",
            line,
        )

        if match:
            current["esn_high"] = int(
                match.group(1),
                16,
            )

    if current and current.get("spi"):
        sas.append(current)

    usable = []

    required = [
        "src",
        "dst",
        "spi",
        "enc_algorithm",
        "enc_key",
        "auth_algorithm",
        "auth_key",
    ]

    for sa in sas:
        if all(sa.get(field) for field in required):
            usable.append(sa)

    return usable


def display_sas(sas):
    print()
    print(f"Found {len(sas)} usable ESP SA(s):")
    print()

    for sa in sas:
        print(
            f"  {sa['spi']:<12} "
            f"{sa['src']} -> {sa['dst']} "
            f"reqid={sa.get('reqid', '?')}"
        )

    print()


# ============================================================
# STEP 2 - Capture selection
# ============================================================

def ask_pcap():
    print("[2/4] Enter capture filename")
    print()

    while True:
        value = input("PCAP> ").strip()
        value = value.strip("'\"")

        path = Path(value).expanduser()

        if path.exists():
            print()
            return path.resolve()

        print()
        print(f"File not found: {path}")
        print()


# ============================================================
# Find ESP SPIs in original capture
# ============================================================

def get_capture_spis(pcap):
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "esp",
        "-T",
        "fields",
        "-e",
        "esp.spi",
    ]

    result = run(cmd)

    if result.returncode != 0:
        print(result.stderr)
        sys.exit(
            "ERROR: TShark could not inspect the capture."
        )

    spis = set()

    for line in result.stdout.splitlines():
        for value in line.split(","):
            value = value.strip()

            if not value:
                continue

            try:
                number = int(value, 0)
                spis.add(f"0x{number:08x}")
            except ValueError:
                continue

    return spis


def match_sas(sas, capture_spis):
    matched = []

    print("[3/4] Matching and decrypting...")
    print()

    if not capture_spis:
        print("No ESP SPIs were detected in the capture.")
        return []

    for spi in sorted(capture_spis):
        sa = next(
            (
                entry
                for entry in sas
                if entry["spi"] == spi
            ),
            None,
        )

        if sa:
            matched.append(sa)

            print(
                f"  {spi:<12} MATCH  "
                f"{sa['src']} -> {sa['dst']}"
            )
        else:
            print(
                f"  {spi:<12} NO MATCHING KEY"
            )

    print()

    return matched


# ============================================================
# ESP SA file generation
# ============================================================

def esp_sa_row(sa):
    sn = (
        "64-bit"
        if sa.get("esn")
        else "32-bit"
    )

    esn_high = (
        f"0x{sa.get('esn_high', 0):08x}"
    )

    return [
        "IPv4",
        sa["src"],
        sa["dst"],
        sa["spi"],
        sa["enc_algorithm"],
        sa["enc_key"],
        sa["auth_algorithm"],
        sa["auth_key"],
        sn,
        esn_high,
    ]


def write_esp_sa_file(sas, path):
    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.writer(
            handle,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )

        for sa in sas:
            writer.writerow(
                esp_sa_row(sa)
            )


# ============================================================
# Output names
# ============================================================

def capture_basename(path):
    name = path.name

    for extension in [
        ".pcapng",
        ".pcap",
        ".cap",
    ]:
        if name.lower().endswith(extension):
            return name[:-len(extension)]

    return path.stem


def output_paths(pcap):
    base = capture_basename(pcap)
    directory = pcap.parent

    plaintext = (
        directory
        / f"{base}-plaintext.pcapng"
    )

    esp_sa = (
        directory
        / f"{base}-esp_sa"
    )

    report = (
        directory
        / f"{base}-decryption-report.txt"
    )

    return plaintext, esp_sa, report


# ============================================================
# Build temporary Wireshark environment
# ============================================================

def create_wireshark_environment(sas, tempdir):
    config_dir = (
        Path(tempdir)
        / "wireshark"
    )

    config_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    esp_sa_file = (
        config_dir
        / "esp_sa"
    )

    write_esp_sa_file(
        sas,
        esp_sa_file,
    )

    env = os.environ.copy()

    env["WIRESHARK_CONFIG_DIR"] = str(
        config_dir
    )

    return env


# ============================================================
# Verify decryption per SPI
# ============================================================

def verify_decryption(pcap, sas, env):
    counts = {}
    samples = {}

    for sa in sas:
        spi = sa["spi"]

        cmd = [
            "tshark",

            "-o",
            "esp.enable_encryption_decode:TRUE",

            "-o",
            "esp.enable_authentication_check:FALSE",

            "-r",
            str(pcap),

            "-Y",
            f"esp.spi == {spi}",

            "-T",
            "fields",

            "-E",
            "separator=|",

            "-E",
            "occurrence=a",

            "-E",
            "aggregator=,",

            "-e",
            "frame.number",

            "-e",
            "ip.src",

            "-e",
            "ip.dst",
        ]

        result = run(
            cmd,
            env=env,
        )

        if result.returncode != 0:
            counts[spi] = 0
            continue

        count = 0
        sample = None

        for line in result.stdout.splitlines():
            fields = line.split("|")

            while len(fields) < 3:
                fields.append("")

            frame = fields[0].strip()

            srcs = [
                x.strip()
                for x in fields[1].split(",")
                if x.strip()
            ]

            dsts = [
                x.strip()
                for x in fields[2].split(",")
                if x.strip()
            ]

            # Tunnel mode should expose:
            #
            # outer IP
            # inner IP
            #
            if (
                len(srcs) >= 2
                and len(dsts) >= 2
            ):
                count += 1

                if sample is None:
                    sample = {
                        "frame": frame,
                        "outer_src": srcs[0],
                        "outer_dst": dsts[0],
                        "inner_src": srcs[-1],
                        "inner_dst": dsts[-1],
                    }

        counts[spi] = count

        if sample:
            samples[spi] = sample

    return counts, samples


# ============================================================
# Export actual decrypted IP PDUs
# ============================================================

def export_plaintext(pcap, sas, final_output):
    print("Exporting decrypted inner IP traffic...")

    with tempfile.TemporaryDirectory(
        prefix="ipsec-decrypt-"
    ) as tempdir:

        tempdir = Path(tempdir)

        raw_export = (
            tempdir
            / "raw-ip-export.pcapng"
        )

        filtered_export = (
            tempdir
            / "plaintext-filtered.pcapng"
        )

        env = create_wireshark_environment(
            sas,
            tempdir,
        )

        # ----------------------------------------------------
        # PROVE that ESP decryption actually works
        # ----------------------------------------------------

        counts, samples = verify_decryption(
            pcap,
            sas,
            env,
        )

        print()

        total_decrypted = 0

        for sa in sas:
            spi = sa["spi"]
            count = counts.get(spi, 0)

            total_decrypted += count

            if count:
                print(
                    f"  {spi:<12} SUCCESS - "
                    f"{count} ESP packet(s) decrypted"
                )

                sample = samples.get(spi)

                if sample:
                    print(
                        f"               Example inner: "
                        f"{sample['inner_src']} -> "
                        f"{sample['inner_dst']}"
                    )

            else:
                print(
                    f"  {spi:<12} "
                    f"NO PLAINTEXT DETECTED"
                )

        print()

        if total_decrypted == 0:
            raise RuntimeError(
                "The SPIs matched, but TShark did not "
                "successfully expose any inner IP traffic."
            )

        # ----------------------------------------------------
        # Export ALL dissected IP PDUs
        #
        # This produces Raw-IP packets, including:
        #   outer ESP/IKE IP packets
        #   decrypted inner IP packets
        # ----------------------------------------------------

        export_cmd = [
            "tshark",

            "-o",
            "esp.enable_encryption_decode:TRUE",

            "-o",
            "esp.enable_authentication_check:FALSE",

            "-r",
            str(pcap),

            "-U",
            "IP",

            "-w",
            str(raw_export),
        ]

        result = run(
            export_cmd,
            env=env,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "TShark IP PDU export failed:\n"
                + result.stderr
            )

        if not raw_export.exists():
            raise RuntimeError(
                "TShark did not create the Raw-IP export."
            )

        # ----------------------------------------------------
        # Remove outer ESP and IKE packets.
        #
        # What remains is the decrypted inner IP traffic.
        # ----------------------------------------------------

        filter_cmd = [
            "tshark",

            "-r",
            str(raw_export),

            "-Y",
            "not esp and not isakmp",

            "-w",
            str(filtered_export),
        ]

        result = run(filter_cmd)

        if result.returncode != 0:
            raise RuntimeError(
                "Plaintext filtering failed:\n"
                + result.stderr
            )

        # ----------------------------------------------------
        # Remove duplicate exported IP PDUs.
        #
        # -d compares the current packet against the
        # previous four packets.
        # ----------------------------------------------------

        safe_unlink(final_output)

        dedupe_cmd = [
            "editcap",
            "-d",
            str(filtered_export),
            str(final_output),
        ]

        result = run(dedupe_cmd)

        if result.returncode != 0:
            raise RuntimeError(
                "Duplicate cleanup failed:\n"
                + result.stderr
            )

        return counts, samples


# ============================================================
# Validate final plaintext capture
# ============================================================

def inspect_final_capture(path):
    cmd = [
        "tshark",
        "-r",
        str(path),
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]

    result = run(cmd)

    if result.returncode != 0:
        return 0

    packet_count = len(
        [
            line
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    )

    return packet_count


def check_for_esp(path):
    cmd = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        "esp or isakmp",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]

    result = run(cmd)

    if result.returncode != 0:
        return None

    return len(
        [
            line
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    )


# ============================================================
# Report generation
# ============================================================

def write_report(
    report_path,
    original_pcap,
    plaintext_pcap,
    sas,
    counts,
    samples,
    final_packet_count,
):
    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as handle:

        handle.write(
            "IPsec ESP Decryption Report\n"
        )

        handle.write(
            "===========================\n\n"
        )

        handle.write(
            f"Original capture:\n"
            f"  {original_pcap}\n\n"
        )

        handle.write(
            f"Plaintext capture:\n"
            f"  {plaintext_pcap}\n\n"
        )

        handle.write(
            f"Final plaintext packet count: "
            f"{final_packet_count}\n\n"
        )

        handle.write(
            "Security Associations\n"
        )

        handle.write(
            "=====================\n\n"
        )

        for sa in sas:
            spi = sa["spi"]

            handle.write(
                f"SPI: {spi}\n"
            )

            handle.write(
                f"Direction: "
                f"{sa['src']} -> "
                f"{sa['dst']}\n"
            )

            handle.write(
                f"ReqID: "
                f"{sa.get('reqid', '?')}\n"
            )

            handle.write(
                f"Mode: "
                f"{sa.get('mode', '?')}\n"
            )

            handle.write(
                f"Encryption: "
                f"{sa['enc_algorithm']}\n"
            )

            handle.write(
                f"Authentication: "
                f"{sa['auth_algorithm']}\n"
            )

            handle.write(
                f"ESP packets successfully decrypted: "
                f"{counts.get(spi, 0)}\n"
            )

            sample = samples.get(spi)

            if sample:
                handle.write(
                    f"Example outer packet: "
                    f"{sample['outer_src']} -> "
                    f"{sample['outer_dst']}\n"
                )

                handle.write(
                    f"Example inner packet: "
                    f"{sample['inner_src']} -> "
                    f"{sample['inner_dst']}\n"
                )

            handle.write("\n")


# ============================================================
# Main
# ============================================================

def main():
    print(BANNER)

    require_tools()

    # --------------------------------------------------------
    # STEP 1
    # --------------------------------------------------------

    xfrm_text = paste_xfrm()

    if not xfrm_text.strip():
        sys.exit(
            "\nERROR: No XFRM state was provided."
        )

    try:
        sas = parse_xfrm(
            xfrm_text
        )

    except ValueError as error:
        sys.exit(
            f"\nXFRM parse error: {error}"
        )

    if not sas:
        sys.exit(
            "\nNo usable ESP SAs were found.\n\n"
            "Make sure you pasted the output of:\n\n"
            "    ip xfrm state\n"
        )

    display_sas(sas)

    # --------------------------------------------------------
    # STEP 2
    # --------------------------------------------------------

    pcap = ask_pcap()

    # --------------------------------------------------------
    # STEP 3
    # --------------------------------------------------------

    capture_spis = get_capture_spis(
        pcap
    )

    matched = match_sas(
        sas,
        capture_spis,
    )

    if not matched:
        sys.exit(
            "No matching ESP SAs were found.\n\n"
            "The capture may belong to a different "
            "IPsec CHILD_SA/rekey."
        )

    plaintext, esp_sa_file, report_file = (
        output_paths(pcap)
    )

    # Save the matching SA table permanently
    write_esp_sa_file(
        matched,
        esp_sa_file,
    )

    # --------------------------------------------------------
    # Decrypt / export
    # --------------------------------------------------------

    try:
        counts, samples = export_plaintext(
            pcap,
            matched,
            plaintext,
        )

    except RuntimeError as error:
        print()
        print("DECRYPTION FAILED")
        print("=================")
        print()
        print(error)
        sys.exit(1)

    # --------------------------------------------------------
    # Validate final result
    # --------------------------------------------------------

    final_packet_count = inspect_final_capture(
        plaintext
    )

    bad_packets = check_for_esp(
        plaintext
    )

    if final_packet_count == 0:
        sys.exit(
            "\nERROR: Final plaintext capture "
            "contains zero packets."
        )

    if bad_packets is None:
        print(
            "WARNING: Could not verify final "
            "ESP/IKE packet count."
        )

    elif bad_packets:
        print(
            f"WARNING: Final capture still contains "
            f"{bad_packets} ESP/IKE packet(s)."
        )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    write_report(
        report_file,
        pcap,
        plaintext,
        matched,
        counts,
        samples,
        final_packet_count,
    )

    # --------------------------------------------------------
    # STEP 4
    # --------------------------------------------------------

    print()
    print("[4/4] COMPLETE")
    print("==============")
    print()

    print(
        f"Original encrypted capture:\n"
        f"  {pcap}"
    )

    print()

    print(
        f"Plaintext capture:\n"
        f"  {plaintext}"
    )

    print()

    print(
        f"ESP SA table:\n"
        f"  {esp_sa_file}"
    )

    print()

    print(
        f"Decryption report:\n"
        f"  {report_file}"
    )

    print()

    print(
        f"Final plaintext packets: "
        f"{final_packet_count}"
    )

    if bad_packets == 0:
        print(
            "ESP/IKE packets remaining: 0"
        )

    print()
    print(
        "SUCCESS: plaintext PCAP is ready."
    )
    print()


if __name__ == "__main__":
    main()
