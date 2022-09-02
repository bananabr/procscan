# PROCSCAN
Procscan is a quick and dirty python script used to look for potentially dangerous api call patterns in a [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) PML file.

## Installation
```
git clone https://github.com/bananabr/procscan.git
cd procscan
python3 -m pip install -r requirements.txt
```
## Usage

```
usage: procscan.py [-h] [--log LOG_FILE] [--verbose] --pml PML_FILE --ac ACCESSCHK_FILE

Scan a procmon PML file for potentially dangerous patterns.

options:
  -h, --help           show this help message and exit
  --log LOG_FILE       log file path
  --verbose, -v        increase verbosity
  --pml PML_FILE       procscan PML file
  --ac ACCESSCHK_FILE  "accesschk.exe -swu low_priv_username C:\" output file
```

## Todo

- [ ] (Registry symbolic link patterns)
- [x] (Filesystem symbolic link patterns)
- [x] (DLL hijack)
- [x] (Writable DLL loaded by privileged process)
- [x] (Writable PE loaded by privileged process)