# from joblib.parallel import delayed
from procmon_parser import ProcmonLogsReader
import logging
# from joblib import Parallel, delayed, parallel_backend
# from pqdm.threads import pqdm
import argparse

parser = argparse.ArgumentParser(description='Scan a procmon PML file for potentially dangerous patterns.')
parser.add_argument('--log', default='./procscan.log',
                    help='log file path')
parser.add_argument('--verbose', '-v', action='count', default=0,
                    help='increase verbosity')
parser.add_argument('--pml', required=True,
                    help='procscan PML file')
parser.add_argument('--ac', required=True,
                    help='accesschk output file')

args = parser.parse_args()

if args.verbose > 1:
    logging.basicConfig(level=logging.DEBUG, filename=args.log)
elif args.verbose == 1:
    logging.basicConfig(level=logging.INFO, filename=args.log)
else:
    logging.basicConfig(level=logging.WARN, filename=args.log)

f = open(args.pml, "rb")
af = open(args.ac, "r")

print(f"Processing {args.ac} records")

WRITABLE_PATHS = {}

while True:
    try:
        i = af.readline().strip()
        if not i:
            break
        if not i.startswith("RW "):
            continue
        WRITABLE_PATHS[i[3:]] = True
    except UnicodeDecodeError:
        continue
af.close()

#logging.debug(WRITABLE_PATHS)

print(f"Loading {args.pml} records")
pml_reader = ProcmonLogsReader(f)
print(f"Processing {len(pml_reader)} records")  # number of logs

dll_hijack_candidates = {}

def processEvent(event):
    logging.debug(event)
    if event.path:
        logging.debug(event.path.split('\\')[:-1])
        logging.debug(WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False))
    # DLL hijacking
    if event.operation == "CreateFile" \
            and (event.result == 0xc0000034
                 or event.result == 0xc000003a) \
        and event.path.endswith(".dll") \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} tries to read a nonexistent DLL at {event.path}")
        filename = (event.path.split('\\')[-1]).lower()
        if dll_hijack_candidates.get(event.process.process_name, False):
            dll_hijack_candidates[event.process.process_name].append(filename)
        else:
            dll_hijack_candidates[event.process.process_name] = [filename]
    # DLL hijacking confirmation
    if event.operation == "Load_Image" \
            and event.path.endswith(".dll"):
        logging.debug(dll_hijack_candidates)
        if dll_hijack_candidates.get(event.process.process_name, False):
            filename = (event.path.split('\\')[-1]).lower()
            if filename in dll_hijack_candidates[event.process.process_name]:
                if event.process.user == "NT AUTHORITY\\SYSTEM":
                    logging.critical(
                        f"{event.process.process_name} running as {event.process.user} eventually loads {filename} from {event.path}!")
                else:
                    logging.error(
                        f"{event.process.process_name} running as {event.process.user} eventually loads {filename} from {event.path}!")
    # Arbitrary file write
    if event.operation == "WriteFile" \
        and event.process.user == "NT AUTHORITY\\SYSTEM" \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} writes to {event.path}")
    # Arbitrary file delete
    if  event.operation.startswith("SetDispositionInformation") \
        and event.process.user == "NT AUTHORITY\\SYSTEM" \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} calls SetDispositionInformation* for {event.path}")
    # Arbitrary file move
    if  event.operation.startswith("SetRenameInformation") \
        and event.process.user == "NT AUTHORITY\\SYSTEM" \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} calls SetRenameInformation* for {event.path}")
    # Arbitrary file permission grant
    if  event.operation == "SetSecurityFile" \
        and event.process.user == "NT AUTHORITY\\SYSTEM" \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
        and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} calls SetSecurityFile for {event.path}")

# with parallel_backend('threading', n_jobs=os.cpu_count()):
#     Parallel()(delayed(processEvent)(e) for e in pml_reader)

#pqdm(pml_reader, processEvent, n_jobs=os.cpu_count())
for event in pml_reader:
    processEvent(event)