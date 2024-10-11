# Memory Dumper by hollow979

A Windows-based tool that scans and dumps memory allocations from a target process, before and after injection, into a binary file.

## Features

- Scans all memory allocations of a target process.
- Tracks memory changes after injection by comparing pre- and post-injection memory allocations.
- Dumps new memory allocations to a binary file for further analysis.

## Usage

1. **Run the program** with administrative privileges to access system-level process memory.
2. **Enter the target process name** when prompted.
3. The tool will scan all memory regions of the target process and log their base addresses and sizes.
4. **Inject into the target process** using your preferred injection method.
5. Press the **Delete** key to initiate the second scan.
6. The tool will compare the memory regions and identify new allocations made after the injection.
7. The new allocations are dumped to a binary file in a folder with the same name as the target process.

### Sample Workflow

```bash
[INFO] Enter the target process name: target_process.exe
[SCANNER] Allocation Base: 0x7FF612340000 Region Size: 0x20000
...
[SCANNER FINISHED] Allocation count before injection: 20
[INFO] Inject and press delete to scan for and dump the new allocations!
...
[SCANNER] New allocation found! Base: 0x7FF613450000, Size: 0x5000
[SUCCESS] The dump can be found in the same folder as the dumper itself.
