#!/usr/bin/env python3
"""
Albi Firmware File Identifier/Cutter

A Python tool for analyzing and extracting components from Albi firmware files.
Converted from Perl script by jindroush, published under MPL license.
Part of https://github.com/jindroush/albituzka

This tool analyzes update.chp/updateA.chp firmware files and can extract:
- Firmware modules and binaries
- MP3 audio files
- Text strings
- OID-to-firmware code mappings
- Button assignment tables

Usage:
    python fw_cutter.py [input_file] [options]

Options:
    --save          Save firmware internal files (texts, OID mappings)
    --save-bin      Save firmware subparts (modules, MP3s)
    --output DIR    Output directory for extracted files (default: current directory)

Examples:
    python fw_cutter.py updateA.chp
    python fw_cutter.py update.chp --save --save-bin
    python fw_cutter.py firmware.chp --save --output ./extracted
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from typing import Dict
from bnl_utils import oid_table


class FirmwareCutter:
    """Albi firmware file analyzer and extractor."""

    def __init__(self, input_file: str = "updateA.chp", output_dir: str = ".",
                 save_files: bool = False, save_bins: bool = False):
        self.input_file = Path(input_file)
        self.output_dir = Path(output_dir)
        self.save_files = save_files
        self.save_bins = save_bins

        # Firmware data
        self.buf = b''
        self.length = 0
        self.md5_hash = ""

        # Binary sections
        self.sections = {}

        # OID converter table
        self.oid_tbl_int2raw = oid_table

        # Known firmware codes
        self.codes = {
            "0010": "book_id",
            "0020": "set_volume_0",
            "0040": "mp3",
            "0042": "mp3 pause",
            "0043": "mp3 play",
            "0044": "mp3 stop",
            "0045": "mp3 prev",
            "0046": "mp3 next",
            "0030": "vol+",
            "0031": "vol-",
            "0050": "compare",
            "0060": "sound_rec",
            "0062": "sound_play",
            "0080": "stop",
            "0090": "mode_05",
            "0091": "mode_04",
            "0092": "mode_03",
            "0093": "mode_02",
            "0094": "mode_01",
            "0095": "mode_06",
            "0096": "mode_07",
            "0097": "mode_08",
            "0098": "mode_09",
            "0099": "mode_10",
            "009A": "mode_11",
            "009B": "mode_12",
        }

    def _load_file(self) -> None:
        """Load firmware file into memory."""
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file '{self.input_file}' not found")

        self.length = self.input_file.stat().st_size

        with open(self.input_file, 'rb') as f:
            self.buf = f.read()

        # Calculate MD5 hash
        self.md5_hash = hashlib.md5(self.buf).hexdigest()

        print(f"input: {self.input_file}")
        print(f"md5: {self.md5_hash}")

    def _read_dword(self, offset: int) -> int:
        """Read 32-bit little-endian integer from buffer."""
        return struct.unpack('<I', self.buf[offset:offset + 4])[0]

    def _read_word(self, offset: int) -> int:
        """Read 16-bit little-endian integer from buffer."""
        return struct.unpack('<H', self.buf[offset:offset + 2])[0]

    def _read_byte(self, offset: int) -> int:
        """Read single byte from buffer."""
        return self.buf[offset]

    def _read_utf16_string(self, offset: int, length: int) -> str:
        """Read UTF-16LE string from buffer."""
        try:
            data = self.buf[offset:offset + length]
            return data.decode('utf-16le').rstrip('\x00')
        except UnicodeDecodeError:
            return f"<decode error at 0x{offset:X}>"

    def _analyze_sections(self) -> None:
        """Analyze firmware sections from header."""
        # Get section information from offset 0xA0
        dwords = struct.unpack('<6I', self.buf[0xA0:0xA0 + 24])

        b2b, b2e, b3b, b3e = dwords[:4]

        # Implicit first section
        b1b = 0x400000
        b1e = b2b

        # Calculate file offsets (address - 0x400000) * 2
        self.sections = {
            '1': {
                'mem_start': b1b, 'mem_end': b1e,
                'file_start': (b1b - 0x400000) * 2, 'file_end': (b1e - 0x400000) * 2,
                'size': (b1e - b1b) * 2
            },
            '2': {
                'mem_start': b2b, 'mem_end': b2e,
                'file_start': (b2b - 0x400000) * 2, 'file_end': (b2e - 0x400000) * 2,
                'size': (b2e - b2b) * 2
            },
            '3': {
                'mem_start': b3b, 'mem_end': b3e,
                'file_start': (b3b - 0x400000) * 2, 'file_end': (b3e - 0x400000) * 2,
                'size': (b3e - b3b) * 2
            }
        }

        for name, section in self.sections.items():
            print(f"{name}.bin [{section['mem_start']:06x}-{section['mem_end']:06x}/"
                  f"{section['file_start']:06x}-{section['file_end']:06x}] = {section['size']} bytes")

        expected_length = (b3e - b1b) * 2
        status = "Ok!" if expected_length == self.length else "mismatch!"
        print(f"Computed length: {expected_length:08X} / real: {self.length:08X} = {status}")

        # Version information
        verptr = dwords[5]
        if verptr:
            ver_offset = (verptr - b1b) * 2
            if ver_offset < len(self.buf):
                version_str = self._read_utf16_string(ver_offset, 0x32)
                print(f"ver: {version_str}")

    def _checksum_pram(self, ptr: int, words: int) -> int:
        """Calculate checksum for PRAM section."""
        ptr = (ptr - 0x400000) * 2
        checksum = 0

        for _ in range(words):
            if ptr + 1 < len(self.buf):
                checksum += self._read_word(ptr)
                ptr += 2
            else:
                break

        return checksum & 0xFFFF

    def _extract_1bin(self) -> None:
        """Extract and analyze first binary section."""
        section = self.sections['1']

        if self.save_bins:
            self._save_binary_section('1bin.bin', section)

        # Read chip type from offset 0x100
        if len(self.buf) > 0x106:
            chip_bytes = self.buf[0x100:0x107]
            chip = bytes(reversed(chip_bytes)).decode('ascii', errors='ignore')
            print(f"chip: {chip}")

        # Read module count
        if len(self.buf) > 0x109:
            mod_count = self._read_word(0x108)
            print(f"modules count: {mod_count}")

            # Process each module
            for i in range(min(mod_count, 50)):  # Safety limit
                offset = 0x10A + i * 16
                if offset + 16 > len(self.buf):
                    break

                module_data = struct.unpack('<HHIII', self.buf[offset:offset + 16])
                prj_id, pram_len, pram_fw_addr, pram_addr, checksum = module_data

                chk = self._checksum_pram(pram_fw_addr, pram_len)
                file_offset = (pram_fw_addr - 0x400000) * 2

                checksum_status = "ok" if chk == checksum else "mismatch"
                print(f"{i:2d}) PrjId:{prj_id:04X}  PRAM:{pram_addr:06x} len:{pram_len:04x} "
                      f"from:{pram_fw_addr:06x} [{file_offset:08X}]  checksum:{checksum_status}")

                if self.save_bins and file_offset < len(self.buf):
                    module_filename = f"1bin_module{i:02d}.bin"
                    end_offset = min(file_offset + pram_len * 2, len(self.buf))
                    self._save_data(module_filename, self.buf[file_offset:end_offset])

        # Extract text strings (Albi firmware specific)
        self._extract_texts()

    def _extract_texts(self) -> None:
        """Extract text strings from firmware."""
        # Check for text table pointer at 0x634
        if len(self.buf) <= 0x637:
            return

        dw634 = self._read_dword(0x634)
        text_offset = (dw634 - 0x400000) * 2

        if text_offset != 0x638:
            return

        texts = []
        text_offsets = 0x638

        for i in range(5000):  # Safety limit
            offset = text_offsets + i * 4
            if offset + 8 > len(self.buf):
                break

            dw1, dw2 = struct.unpack('<II', self.buf[offset:offset + 8])

            if dw2 == 0:
                break

            # Extract text string
            text_start = 0x638 + dw1
            text_length = dw2 - dw1

            if text_start + text_length <= len(self.buf):
                text_str = self._read_utf16_string(text_start, text_length)
                texts.append((i, dw1, dw2, text_length, text_str))

        if self.save_files and texts:
            output_file = self.output_dir / "1bin_extracted_texts.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                for i, dw1, dw2, length, text in texts:
                    f.write(f"{i:4d}/{i * 4:06x} [{dw1:06x}-{dw2:06x}] = {length:02x}  '{text}'\n")
            print(f"Saved {len(texts)} texts to {output_file}")

        print(f"1bin found {len(texts)} texts")

    def _extract_2bin(self) -> None:
        """Extract and analyze second binary section (MP3 files)."""
        section = self.sections['2']

        if self.save_bins:
            self._save_binary_section('2bin.bin', section)

        # Parse MP3 file table
        mp3_files = []
        ptr = section['file_start']
        first_file_ptr = None

        while ptr < section['file_end']:
            if ptr + 8 > len(self.buf):
                break

            file_start, file_length = struct.unpack('<II', self.buf[ptr:ptr + 8])
            file_start += section['file_start']
            file_length += section['file_start']

            if first_file_ptr is None:
                first_file_ptr = file_start

            ptr += 4

            if ptr >= first_file_ptr:
                break

            mp3_files.append((file_start, file_length - file_start))

        # Extract MP3 files
        for i, (start, length) in enumerate(mp3_files):
            if start >= section['file_end']:
                break

            filename = f"2bin-{i:03d}.mp3"

            if self.save_files:
                print(
                    f"{filename} [{i:04X}] {i}) {start:08X} ({start - section['file_start']:08X}) [{start + length:08X}]")
                end_pos = min(start + length, len(self.buf))
                self._save_data(filename, self.buf[start:end_pos])

        print(f"2bin: found {len(mp3_files)} mp3s")

    def _extract_3bin(self) -> None:
        """Extract and analyze third binary section (OID mappings, etc.)."""
        section = self.sections['3']

        if self.save_bins:
            self._save_binary_section('3bin.bin', section)

        base_offset = section['file_start']

        print(f"one time pad [{base_offset:06x}-{base_offset + 0x10000:06x}]")
        print(f"oid2fw codes [{base_offset + 0x10000:06x}-{base_offset + 0x30000:06x}]")

        # Analyze button assignment table
        self._analyze_button_table(base_offset)

        # Analyze dword table
        self._analyze_dword_table(base_offset)

        # Extract MP3 files from part 1
        self._extract_3bin_mp3s_part1(base_offset)

        # Extract MP3 files from part 3
        self._extract_3bin_mp3s_part3(base_offset)

        # Extract string table
        self._extract_3bin_strings(base_offset)

        # Extract OID to firmware code mapping
        if self.save_files:
            self._extract_oid2fw_codes(base_offset)

    def _analyze_button_table(self, base_offset: int) -> None:
        """Analyze button assignment table."""
        but_tbl_offset = base_offset + 0x30000
        print(f"button assignment table 3bin/30000: [{but_tbl_offset:06X}]")

        # Print header
        print("  bt len    ", end="")
        for j in range(16):
            print(f"{j:02x} ", end="")
        print()

        button_codes = set()

        for i in range(8):
            if but_tbl_offset + i * 32 + 32 > len(self.buf):
                break

            print(f"  {i:02x} short: ", end="")
            for j in range(16):
                offset = but_tbl_offset + i * 32 + j
                if offset < len(self.buf):
                    bcode = self._read_byte(offset)
                    print(f"{bcode:02x} ", end="")
                    button_codes.add(bcode)

            print(f"\n  {i:02x} long : ", end="")
            for j in range(16):
                offset = but_tbl_offset + i * 32 + 16 + j
                if offset < len(self.buf):
                    bcode = self._read_byte(offset)
                    print(f"{bcode:02x} ", end="")
                    button_codes.add(bcode)
            print()

        # Print button code meanings
        print("  button codes: ", end="")
        for bcode in sorted(button_codes):
            if bcode == 0xFF:
                continue
            bcode_str = f"{bcode:04X}"
            if bcode_str in self.codes:
                print(f"{bcode:02X}:{self.codes[bcode_str]} ", end="")
            else:
                print(f"[{bcode:02X}:*UNK*] ", end="")
        print()

    def _analyze_dword_table(self, base_offset: int) -> None:
        """Analyze dword table at offset 0x30340."""
        dword_offset = base_offset + 0x30340
        print(f"dword tbl 3bin/30340 [{dword_offset:06x}]")

        if dword_offset + 16 <= len(self.buf):
            dwords = struct.unpack('<4I', self.buf[dword_offset:dword_offset + 16])
            for i, dw in enumerate(dwords):
                print(f"  dw{i}: [{dw:06x}/{dw + base_offset:06x}]")

    def _extract_3bin_mp3s_part1(self, base_offset: int) -> None:
        """Extract MP3 files from 3bin part 1."""
        part1_offset = base_offset + 0x30400
        print(f"3bin/part 1 (1st mp3s) follows [{part1_offset:06x}]")

        count = 0
        for ptr in range(0x30400, 0x30500, 8):
            offset = base_offset + ptr
            if offset + 8 > len(self.buf):
                break

            file_start, file_length = struct.unpack('<II', self.buf[offset:offset + 8])

            if file_start in [0x0, 0xFFFFFFFF] or file_length == 0:
                count += 1
                continue

            if self.save_files:
                filename = f"3bin_1-{count:03d}.mp3"
                abs_start = file_start + base_offset
                abs_end = min(abs_start + file_length, len(self.buf))

                print(f"{filename} [{count:04X}] {count}) {abs_start:06x} [{abs_end:06x}]")
                self._save_data(filename, self.buf[abs_start:abs_end])

            count += 1

    def _extract_3bin_mp3s_part3(self, base_offset: int) -> None:
        """Extract MP3 files from 3bin part 3."""
        # Get part 3 offset from dword table
        dword_offset = base_offset + 0x30340
        if dword_offset + 8 > len(self.buf):
            return

        dwords = struct.unpack('<2I', self.buf[dword_offset + 4:dword_offset + 12])
        part3_offset = base_offset + dwords[0]  # dw[1]

        print(f"3bin/part 3 (2nd mp3s) follows [{part3_offset:06x}]")

        count = 0
        for i in range(0x500 // 8):  # Safety limit
            offset = part3_offset + i * 8
            if offset + 8 > len(self.buf):
                break

            file_start, file_length = struct.unpack('<II', self.buf[offset:offset + 8])

            if file_start in [0x0, 0xFFFFFFFF] or file_length == 0:
                count += 1
                continue

            if self.save_files:
                filename = f"3bin_3-{count:03d}.mp3"
                abs_start = file_start + base_offset
                abs_end = min(abs_start + file_length, len(self.buf))

                print(f"{filename} [{count:04X}] {count}) {abs_start:08X} [{abs_end:06x}]")
                self._save_data(filename, self.buf[abs_start:abs_end])

            count += 1

    def _extract_3bin_strings(self, base_offset: int) -> None:
        """Extract string table from 3bin part 4."""
        # Get string table offset from dword table
        dword_offset = base_offset + 0x30340
        if dword_offset + 12 > len(self.buf):
            return

        dwords = struct.unpack('<3I', self.buf[dword_offset + 8:dword_offset + 20])
        string_offset = base_offset + dwords[0]  # dw[2]

        print(f"3bin/part 4 (string tbl) follows [{string_offset:06x}]")

        count = 0
        for i in range(0x100 // 8):  # Safety limit
            offset = string_offset + i * 8
            if offset + 8 > len(self.buf):
                break

            str_start, str_length = struct.unpack('<II', self.buf[offset:offset + 8])

            if str_start in [0x0, 0xFFFFFFFF] or str_length == 0:
                count += 1
                continue

            abs_start = str_start + base_offset
            if abs_start + str_length * 2 <= len(self.buf):
                text = self._read_utf16_string(abs_start, str_length * 2)
                print(f"[{count:02X}] {count}) {str_start:08X} [{str_start + str_length:08X}] {text}")

            count += 1

    def _extract_oid2fw_codes(self, base_offset: int) -> None:
        """Extract OID to firmware code mapping."""
        # Decrypt the OID table using one-time pad
        oid_data = bytearray()

        for i in range(0x20000):
            if base_offset + 0x10000 + i >= len(self.buf):
                break

            encrypted_byte = self._read_byte(base_offset + 0x10000 + i)
            key_byte = self._read_byte(base_offset + (i // 2))

            if (encrypted_byte != 0 and encrypted_byte != 0xFF and
                    encrypted_byte != key_byte and encrypted_byte != (key_byte ^ 0xFF)):
                decrypted_byte = encrypted_byte ^ key_byte
            else:
                decrypted_byte = encrypted_byte

            oid_data.append(decrypted_byte)

        # Convert to 16-bit words
        if len(oid_data) >= 2:
            words = struct.unpack(f'<{len(oid_data) // 2}H', oid_data[:len(oid_data) // 2 * 2])

            output_file = self.output_dir / "3bin_oid2fw_codes.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                last_output = None

                for i, word in enumerate(words):
                    if word == 0:
                        continue

                    if last_output is not None and last_output + 1 != i:
                        f.write("\n")
                    last_output = i

                    # Determine code meaning
                    code_meaning = ""
                    word_str = f"{word:04X}"

                    if word_str in self.codes:
                        code_meaning = self.codes[word_str]
                    elif 0x1000 <= word <= 0x1FFF:
                        code_meaning = f"quiz_{word - 0x1000}"
                    elif 0x0020 <= word <= 0x002F:
                        code_meaning = f"set_volume_{word - 0x0020}"

                    raw_code = self.oid_tbl_int2raw[i] if i < len(self.oid_tbl_int2raw) else 0

                    f.write(f"RAW OID 0x{raw_code:04X} ({raw_code:5d}) = "
                            f"INT OID 0x{i:04X} ({i:5d}) = 0x{word:04X} ({word:5d}) {code_meaning}\n")

            print(f"Saved OID to firmware code mapping to {output_file}")

    def _save_binary_section(self, filename: str, section: Dict) -> None:
        """Save a binary section to file."""
        start = section['file_start']
        end = min(section['file_end'], len(self.buf))
        self._save_data(filename, self.buf[start:end])

    def _save_data(self, filename: str, data: bytes) -> None:
        """Save data to file in output directory."""
        output_path = self.output_dir / filename
        with open(output_path, 'wb') as f:
            f.write(data)

    def analyze(self) -> None:
        """Main analysis function."""
        print("Albi Firmware Cutter")
        print("=" * 50)

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load and analyze file
        self._load_file()
        self._analyze_sections()

        print("\nExtracting sections...")
        self._extract_1bin()
        self._extract_2bin()
        self._extract_3bin()

        print("\nAnalysis completed!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Albi Firmware File Identifier/Cutter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s updateA.chp
  %(prog)s update.chp --save --save-bin
  %(prog)s firmware.chp --save --output ./extracted

This tool analyzes update.chp/updateA.chp firmware files and can extract:
- Firmware modules and binaries
- MP3 audio files
- Text strings
- OID-to-firmware code mappings
- Button assignment tables
        """
    )

    parser.add_argument(
        'input_file',
        nargs='?',
        default='updateA.chp',
        help='Input firmware file (default: updateA.chp)'
    )

    parser.add_argument(
        '--save',
        action='store_true',
        help='Save firmware internal files (texts, OID mappings)'
    )

    parser.add_argument(
        '--save-bin',
        action='store_true',
        help='Save firmware subparts (modules, MP3s)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='.',
        help='Output directory for extracted files (default: current directory)'
    )

    args = parser.parse_args()

    try:
        # Create firmware cutter
        cutter = FirmwareCutter(
            input_file=args.input_file,
            output_dir=args.output,
            save_files=args.save,
            save_bins=args.save_bin
        )

        # Run analysis
        cutter.analyze()

        # Print summary
        if args.save or args.save_bin:
            output_path = Path(args.output)
            extracted_files = list(output_path.glob("*"))
            if extracted_files:
                print(f"\nExtracted {len(extracted_files)} files to: {output_path.absolute()}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
# Basic analysis (no file extraction)
python fw_cutter.py updateA.chp

# Extract all files to current directory
python fw_cutter.py update.chp --save --save-bin

# Extract to specific directory
python fw_cutter.py firmware.chp --save --output ./extracted

# Extract only internal files (texts, mappings)
python fw_cutter.py updateA.chp --save

# Extract only binary components (modules, MP3s)
python fw_cutter.py update.chp --save-bin --output ./binaries
"""