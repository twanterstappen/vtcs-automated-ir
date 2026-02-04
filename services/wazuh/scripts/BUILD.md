# Building Instructions

The `remove-threat` executable files (`.exe` for Windows and `ELF` for Linux) are compiled using PyInstaller 6.17.

## Build Command

```bash
pyinstaller --onefile --name remove-threat remove-threat.py
```

This creates a single standalone executable from the Python script without requiring Python to be installed on the target system.
