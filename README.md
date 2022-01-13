# PROCSCAN
Procscan is a quick and dirty python script used to look for potentially dangerous api call patterns in a [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) PML file.

## Installation
```
python3 -m pip install -r requirements.txt
```
## Usage

```
usage: procscan.py [-h] [--log LOG] [--verbose] --pml PML --ac AC

optional arguments:
  -h, --help     show this help message and exit
  --log LOG      log file path
  --verbose, -v  increase verbosity
  --pml PML      procscan PML file
  --ac AC        accesschk output file
```

## Todo

- [ ] (Registry symbolic link patterns)
- [x] (Filesystem symbolic link patterns)
- [x] (DLL hijack)
- [x] (Writable DLL loaded by privileged process)
- [x] (Writable PE loaded by privileged process)