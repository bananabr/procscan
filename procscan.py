from procmon_parser import ProcmonLogsReader
import logging
import argparse


def is_authority(username):
    if username == "NT AUTHORITY\\LOCAL SERVICE" \
            or username == "NT AUTHORITY\\NETWORK SERVICE" \
            or username == "NT AUTHORITY\\SYSTEM":
        return True
    return False

def print_banner():
    print("""

      ___           ___           ___           ___           ___           ___           ___           ___     
     /\  \         /\  \         /\  \         /\  \         /\  \         /\  \         /\  \         /\__\    
    /::\  \       /::\  \       /::\  \       /::\  \       /::\  \       /::\  \       /::\  \       /::|  |   
   /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/\ \  \     /:/\:\  \     /:/\:\  \     /:|:|  |   
  /::\~\:\  \   /::\~\:\  \   /:/  \:\  \   /:/  \:\  \   _\:\~\ \  \   /:/  \:\  \   /::\~\:\  \   /:/|:|  |__ 
 /:/\:\ \:\__\ /:/\:\ \:\__\ /:/__/ \:\__\ /:/__/ \:\__\ /\ \:\ \ \__\ /:/__/ \:\__\ /:/\:\ \:\__\ /:/ |:| /\__\\
 \/__\:\/:/  / \/_|::\/:/  / \:\  \ /:/  / \:\  \  \/__/ \:\ \:\ \/__/ \:\  \  \/__/ \/__\:\/:/  / \/__|:|/:/  /
      \::/  /     |:|::/  /   \:\  /:/  /   \:\  \        \:\ \:\__\    \:\  \            \::/  /      |:/:/  / 
       \/__/      |:|\/__/     \:\/:/  /     \:\  \        \:\/:/  /     \:\  \           /:/  /       |::/  /  
                  |:|  |        \::/  /       \:\__\        \::/  /       \:\__\         /:/  /        /:/  /   
                   \|__|         \/__/         \/__/         \/__/         \/__/         \/__/         \/__/    
""")

parser = argparse.ArgumentParser(
    description='Scan a procmon PML file for potentially dangerous patterns.')
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

logging.debug(f"{v}\n" for v in WRITABLE_PATHS.values())

print_banner()
print(f"Loading {args.pml} records")
pml_reader = ProcmonLogsReader(f)
print(f"Processing {len(pml_reader)} records")  # number of logs

dll_hijack_candidates = {}


def processEvent(event):
    logging.debug(event)
    # Writable executable
    if event.operation == "Load_Image" \
            and event.path.endswith(".exe") \
            and WRITABLE_PATHS.get(event.path, False):
        if is_authority(event.process.user):
            logging.critical(
                f"{event.process.process_name} running as {event.process.user} loaded a writable PE located at {event.path}!")
    # DLL hijacking
    if event.operation == "CreateFile" \
            and (event.result == 0xc0000034
                 or event.result == 0xc000003a) \
        and event.path.endswith(".dll") \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} tried to read a nonexistent DLL at {event.path}")
        filename = (event.path.split('\\')[-1]).lower()
        if dll_hijack_candidates.get(event.process.process_name, False):
            dll_hijack_candidates[event.process.process_name].append(filename)
        else:
            dll_hijack_candidates[event.process.process_name] = [filename]
    # DLL hijacking confirmation
    if event.operation == "Load_Image" \
            and event.path.endswith(".dll"):
        # Writable DLL loaded by privileged process
        if WRITABLE_PATHS.get(event.path, False):
            if is_authority(event.process.user):
                logging.critical(
                    f"{event.process.process_name} running as {event.process.user} loaded a writable DLL located at {event.path}!")
        # DLL hijacking confirmation
        logging.debug(dll_hijack_candidates)
        if dll_hijack_candidates.get(event.process.process_name, False):
            filename = (event.path.split('\\')[-1]).lower()
            if filename in dll_hijack_candidates[event.process.process_name]:
                if is_authority(event.process.user):
                    logging.critical(
                        f"{event.process.process_name} running as {event.process.user} eventually loaded {filename} from {event.path}!")
                else:
                    logging.error(
                        f"{event.process.process_name} running as {event.process.user} eventually loaded {filename} from {event.path}!")
    # Arbitrary file write
    if event.operation == "WriteFile" \
            and is_authority(event.process.user) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} wrote to {event.path}")
    # Arbitrary file delete
    if event.operation.startswith("SetDispositionInformation") \
            and is_authority(event.process.user) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} called SetDispositionInformation* for {event.path}")
    # Arbitrary file move
    if event.operation.startswith("SetRenameInformation") \
            and is_authority(event.process.user) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} called SetRenameInformation* for {event.path}")
    # Arbitrary file permission grant
    if event.operation == "SetSecurityFile" \
            and is_authority(event.process.user) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-2]), False) \
            and WRITABLE_PATHS.get("\\".join(event.path.split('\\')[:-1]), False):
        logging.warn(
            f"{event.process.process_name} running as {event.process.user} called SetSecurityFile for {event.path}")


for event in pml_reader:
    processEvent(event)
