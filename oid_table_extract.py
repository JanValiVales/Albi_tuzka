#!/usr/bin/env python3
"""
OID Table Extractor

A Python tool for extracting raw->internal OIDs from OidProducer.exe.
Converted from Perl script by jindroush, published under MPL license.
Part of https://github.com/jindroush/albituzka

This tool extracts the OID conversion table from OidProducer.exe and generates
Python code for the OID converter initialization function.

Usage:
    python oid_table_extract.py [options]

Options:
    --input FILE        Input executable file (default: OidProducer10.20.exe)
    --output FILE       Output Python code file (default: oid_converter.py)
    --table-offset HEX  Table offset in hex (default: 0x8F9DE0)
    --verify-md5        Verify MD5 hash of input file

Examples:
    python oid_table_extract.py
    python oid_table_extract.py --input OidProducer.exe --output converter.py
    python oid_table_extract.py --table-offset 0x900000 --verify-md5
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path
from typing import List, Union


class OIDTableExtractor:
    """Extractor for OID conversion tables from OidProducer.exe."""

    # Known MD5 hash for the tested version
    KNOWN_MD5 = "78af7c4610995f7b98f35e3261e3dd19"

    def __init__(self, input_file: str = "OidProducer10.20.exe",
                 output_file: str = "oid_converter.py",
                 table_offset: int = 0x8F9DE0):
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.table_offset = table_offset

    def _calculate_md5(self) -> str:
        """Calculate MD5 hash of the input file.

        Returns:
            MD5 hash as hexadecimal string
        """
        hash_md5 = hashlib.md5()
        with open(self.input_file, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _verify_file(self, verify_md5: bool = False) -> None:
        """Verify the input file exists and optionally check MD5.

        Args:
            verify_md5: Whether to verify MD5 hash
        """
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file '{self.input_file}' not found")

        file_size = self.input_file.stat().st_size
        print(f"Input file: {self.input_file}")
        print(f"File size: {file_size} bytes (0x{file_size:X})")

        if verify_md5:
            actual_md5 = self._calculate_md5()
            print(f"MD5 hash: {actual_md5}")

            if actual_md5.lower() != self.KNOWN_MD5.lower():
                print(f"Warning: MD5 hash doesn't match known good version!")
                print(f"Expected: {self.KNOWN_MD5}")
                print(f"Actual:   {actual_md5}")
                print(f"Table offset might need adjustment.")
            else:
                print("MD5 hash matches known good version.")

        # Check if table offset is within file
        if self.table_offset + (65536 * 4) > file_size:
            raise ValueError(f"Table offset 0x{self.table_offset:X} extends beyond file size")

    def _read_table(self) -> List[int]:
        """Read the OID table from the executable.

        Returns:
            List of 65536 32-bit integers
        """
        print(f"Reading table from offset 0x{self.table_offset:X}")

        with open(self.input_file, 'rb') as f:
            f.seek(self.table_offset)
            # Read 64k 32-bit integers (256KB total)
            table_data = f.read(65536 * 4)

        if len(table_data) != 65536 * 4:
            raise ValueError(f"Failed to read complete table. Got {len(table_data)} bytes, expected {65536 * 4}")

        # Unpack as little-endian 32-bit integers
        dwords = struct.unpack('<65536I', table_data)

        if len(dwords) != 65536:
            raise ValueError(f"Table unpacking failed. Got {len(dwords)} values, expected 65536")

        print(f"Successfully read {len(dwords)} table entries")
        return list(dwords)

    def _create_dense_table(self, raw_table: List[int]) -> List[Union[int, str]]:
        """Create a 'dense' table by finding consecutive ranges.

        Args:
            raw_table: List of 65536 raw OID values

        Returns:
            List of integers and range strings (e.g., "4..7")
        """
        dense_table = []
        first = None

        for i in range(65536):
            if first is None:
                first = raw_table[i]
                continue

            prev = raw_table[i - 1]
            current = raw_table[i]

            if prev + 1 == current:
                # Consecutive values, continue range
                continue
            else:
                # End of range, add to dense table
                if first == prev:
                    # Single value
                    dense_table.append(first)
                elif first + 1 == prev:
                    # Two consecutive values
                    dense_table.append(first)
                    dense_table.append(prev)
                else:
                    # Range of values
                    dense_table.append(f"{first}..{prev}")

                first = current

        # Handle the last range
        if first is not None:
            last = raw_table[65535]
            if first == last:
                dense_table.append(first)
            elif first + 1 == last:
                dense_table.append(first)
                dense_table.append(last)
            else:
                dense_table.append(f"{first}..{last}")

        return dense_table

    def _generate_python_code(self, dense_table: List[Union[int, str]]) -> str:
        """Generate Python code for the OID converter initialization.

        Args:
            dense_table: Dense representation of the OID table

        Returns:
            Python code as string
        """
        lines = []
        lines.append("def oid_converter_init():")
        lines.append("    \"\"\"Initialize OID converter table.")
        lines.append("    ")
        lines.append("    Index to the array is INTERNAL pen code (index to OID table).")
        lines.append("    Value in the array is RAW, printed code.")
        lines.append("    \"\"\"")
        lines.append("    global oid_tbl_int2raw")
        lines.append("    oid_tbl_int2raw = (")

        # Format the dense table into Python code
        current_line = "        "
        line_length_limit = 90

        for i, item in enumerate(dense_table):
            item_str = str(item)

            # Add comma except for first item
            if i > 0:
                item_str = ", " + item_str

            # Check if adding this item would exceed line length
            if len(current_line + item_str) > line_length_limit and current_line.strip():
                # Finish current line and start new one
                lines.append(current_line + ",")
                current_line = "        " + item_str.lstrip(", ")
            else:
                current_line += item_str

        # Add the last line
        if current_line.strip():
            lines.append(current_line)

        lines.append("    )")
        lines.append("")

        # Add usage example
        lines.append("")
        lines.append("# Example usage:")
        lines.append("# oid_converter_init()")
        lines.append("# raw_code = oid_tbl_int2raw[internal_code]")
        lines.append("")

        return "\n".join(lines)

    def _write_output(self, python_code: str) -> None:
        """Write the generated Python code to output file.

        Args:
            python_code: Python code to write
        """
        with open(self.output_file, 'w', encoding='utf-8') as f:
            # Add file header
            f.write('#!/usr/bin/env python3\n')
            f.write('"""\n')
            f.write('OID Converter Table\n')
            f.write('\n')
            f.write('Generated by oid_table_extract.py\n')
            f.write('Extracted from OidProducer.exe\n')
            f.write('"""\n')
            f.write('\n')
            f.write('# Global variable to hold the conversion table\n')
            f.write('oid_tbl_int2raw = []\n')
            f.write('\n')
            f.write('\n')
            f.write(python_code)

        print(f"Generated Python code written to: {self.output_file}")

    def extract(self, verify_md5: bool = False) -> None:
        """Main extraction function.

        Args:
            verify_md5: Whether to verify MD5 hash of input file
        """
        print("OID Table Extractor")
        print("=" * 50)

        # Verify input file
        self._verify_file(verify_md5)

        # Read the raw table
        raw_table = self._read_table()

        # Create dense representation
        print("Creating dense table representation...")
        dense_table = self._create_dense_table(raw_table)
        print(f"Dense table has {len(dense_table)} entries (compressed from 65536)")

        # Generate Python code
        print("Generating Python code...")
        python_code = self._generate_python_code(dense_table)

        # Write output
        self._write_output(python_code)

        print("Extraction completed successfully!")

        # Show some statistics
        total_values = sum(
            1 if isinstance(item, int) else
            int(item.split('..')[1]) - int(item.split('..')[0]) + 1
            for item in dense_table
        )
        print(f"Total OID values in table: {total_values}")


def parse_hex_int(value: str) -> int:
    """Parse hexadecimal integer from string.

    Args:
        value: Hex string (with or without 0x prefix)

    Returns:
        Integer value
    """
    if value.startswith('0x') or value.startswith('0X'):
        return int(value, 16)
    else:
        return int(value, 16)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="OID Table Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --input OidProducer.exe --output converter.py
  %(prog)s --table-offset 0x900000 --verify-md5

This tool extracts the OID conversion table from OidProducer.exe and generates
Python code for the oid_converter_init() function.

Known working version:
  File: OidProducer10.20.exe
  MD5:  78af7c4610995f7b98f35e3261e3dd19
  Table offset: 0x8F9DE0

For other versions, the table offset may need to be adjusted.
        """
    )

    parser.add_argument(
        '--input',
        type=str,
        default='OidProducer10.20.exe',
        help='Input executable file (default: OidProducer10.20.exe)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='oid_converter.py',
        help='Output Python code file (default: oid_converter.py)'
    )

    parser.add_argument(
        '--table-offset',
        type=str,
        default='0x8F9DE0',
        help='Table offset in hex (default: 0x8F9DE0)'
    )

    parser.add_argument(
        '--verify-md5',
        action='store_true',
        help='Verify MD5 hash of input file against known good version'
    )

    args = parser.parse_args()

    try:
        # Parse table offset
        table_offset = parse_hex_int(args.table_offset)

        # Create extractor
        extractor = OIDTableExtractor(
            input_file=args.input,
            output_file=args.output,
            table_offset=table_offset
        )

        # Run extraction
        extractor.extract(verify_md5=args.verify_md5)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
# Basic usage with default settings
python oid_table_extract.py

# Specify different input/output files
python oid_table_extract.py --input OidProducer.exe --output my_converter.py

# Use different table offset for different version
python oid_table_extract.py --table-offset 0x900000

# Verify MD5 hash against known good version
python oid_table_extract.py --verify-md5

# Full custom extraction
python oid_table_extract.py --input MyOidProducer.exe --output custom_oid.py --table-offset 0x8F0000 --verify-md5
"""