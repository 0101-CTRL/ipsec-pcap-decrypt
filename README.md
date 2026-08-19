# IPsec PCAP Decrypt Helper

A small Python utility for turning an IPsec ESP packet capture into a plaintext inner-IP capture using Linux XFRM state and TShark.

The tool is designed for lab and troubleshooting workflows where you have:

- an encrypted `.pcap` / `.pcapng`
- the corresponding output of `ip xfrm state`
- TShark and editcap installed

It parses the active ESP Security Associations, matches them to SPIs present in the capture, verifies decryption, exports decrypted inner IP packets, removes outer ESP/IKE traffic, removes obvious duplicate exports, and saves a clean plaintext capture.

## What it does

The workflow is:

```text
PCAP + ip xfrm state
        ↓
Parse ESP SAs
        ↓
Match SPIs in capture
        ↓
Load ESP keys into TShark
        ↓
Decrypt ESP
        ↓
Export Raw IP PDUs
        ↓
Remove outer ESP / IKE
        ↓
Deduplicate
        ↓
plaintext.pcapng
