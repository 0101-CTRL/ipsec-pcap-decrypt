# IPsec PCAP Decryptor — Single EXE Windows Build

This edition builds a **single `IPsecDecryptor.exe`** intended for end users.

## End-user experience

The user receives exactly:

```text
IPsecDecryptor.exe
```

They double-click it and use the GUI. They do **not** need to install:

- Python
- PySide6
- TShark
- editcap
- Wireshark

The application bundles the Python runtime, Qt/PySide6, and a private Wireshark/TShark runtime.

## How it works

PyInstaller `--onefile` embeds the application and its dependencies into one executable. At launch, PyInstaller extracts its bundled support files to a temporary runtime directory. The application locates the private `tshark.exe` and `editcap.exe` there and uses them invisibly.

## Recommended build: GitHub Actions

Push this project to GitHub, then:

1. Open **Actions**
2. Select **Build Single Windows EXE**
3. Click **Run workflow**
4. Wait for the build to finish
5. Download the artifact **IPsecDecryptor-Windows-x64**
6. Inside is `IPsecDecryptor.exe`

That EXE is the file to test on a clean Windows machine.

## Local maintainer build

Python and Wireshark are required only on the computer *building* the EXE.

```powershell
.\build.ps1
```

Result:

```text
dist\IPsecDecryptor.exe
```

## Security

XFRM output includes active ESP keys. Captures, plaintext output, `*-esp_sa`, and decryption reports are sensitive and should not be committed.

## Wireshark licensing

The EXE redistributes an unmodified Wireshark/TShark runtime. Wireshark is GPLv2 software. Before public redistribution, preserve applicable license/source obligations and review Wireshark's redistribution guidance.
