#!/usr/bin/env python3
"""
OID 2.0 PNG Bitmap Generator

A Python tool for generating OID 2.0 PNG bitmaps for given internal OID(s).
Converted from Perl script by jindroush, published under MPL license.
Part of https://github.com/jindroush/albituzka

This code was originally written by ernie76 & nomeata from tip-toi-reveng project
https://github.com/entropia/tip-toi-reveng/blob/master/perl-tools/TTT-generatePDF.pl

Changes from original:
- Uses PIL/Pillow instead of GD for better PNG support with resolution tags
- Creates PNG files instead of PDF (better for composition)
- Internally runs on 600dpi, can rescale to 1200dpi
- Uses different checksumming method suitable for Albi pen (same as Ting checksum)
- The generated code is larger - TipToi uses 1mm, Albi 1.35mm
- Uses OID2 raw2internal table

Usage:
    # Generate single OID
    python oid_png_generator.py <oid> [options]

    # Generate multiple OIDs from YAML file
    python oid_png_generator.py @input_file.yaml [options]

Options:
    --output FILE       Output filename (default: oid_N.png for single OID)
    --size SIZE         Size of resulting bitmap in millimeters (default: 20mm)
    --size-x SIZE       Width in millimeters
    --size-y SIZE       Height in millimeters
    --dpi DPI           Density of resulting image: 600 or 1200 (default: 1200)

Examples:
    python oid_png_generator.py 1234
    python oid_png_generator.py 0x04D2 --size 25 --dpi 600
    python oid_png_generator.py @generate_oids.yaml --size 15
    python oid_png_generator.py 100 --output my_oid.png --size-x 30 --size-y 20

Requirements:
    PyYAML>=6.0
    mutagen>=1.45.0
    Pillow>=8.0.0

"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any
import yaml
from bnl_utils import oid_table

try:
    from PIL import Image, ImageDraw

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Error: PIL/Pillow not available. Install with: pip install Pillow")
    sys.exit(1)


class OIDGenerator:
    """OID 2.0 PNG bitmap generator."""

    def __init__(self, dpi: int = 1200, size_x: float = 20.0, size_y: float = 20.0):
        self.dpi = dpi
        self.size_x = size_x  # millimeters
        self.size_y = size_y  # millimeters

        # Initialize OID converter
        self.oid_tbl_int2raw = oid_table

        # Validate DPI
        if self.dpi not in [600, 1200]:
            raise ValueError("DPI must be 600 or 1200")

    def _split_oid_to_array(self, value: int) -> List[int]:
        """Split 16-bit OID value into an array of 9 2-bit values.

        [0] is the checksum, [1]..[8] the bits from MSB to LSB
        analog to the printed OID code, where [0] is top-left
        and [8] bottom-right

        Args:
            value: 16-bit OID raw value

        Returns:
            List of 9 2-bit values (0-3)
        """
        # Calculate checksum using Albi/Ting method
        checksum = (((value >> 2) ^ (value >> 8) ^ (value >> 12) ^ (value >> 14)) & 0x01) << 1
        checksum |= ((value ^ (value >> 4) ^ (value >> 6) ^ (value >> 10)) & 0x01)

        oid_array = [0] * 9
        oid_array[0] = checksum

        # Extract 2-bit values from MSB to LSB
        for i in range(1, 9):
            oid_array[i] = (value & 0xC000) >> 14
            value = value << 2

        return oid_array

    def _create_oid_tile(self, raw_code: int, resolution: int) -> Image.Image:
        """Generate 32x32 pixel raster for a given OID in 600dpi, scale eventually up.

        All magic numbers inside are hardcoded for 1.35mm, 600dpi, OID2 code.

        Args:
            raw_code: Raw OID code to generate
            resolution: Target resolution (600 or 1200)

        Returns:
            PIL Image object with the OID pattern
        """
        oid_array = self._split_oid_to_array(raw_code)

        # Create 32x32 image with transparent background
        oid_tile = Image.new('RGBA', (32, 32), (255, 255, 255, 0))
        draw = ImageDraw.Draw(oid_tile)

        black = (0, 0, 0, 255)

        # Set the frame pixels surrounding the data pixels
        frame_pixels = [(0, 0), (8, 0), (16, 0), (24, 0), (0, 8), (1, 16), (0, 24)]
        for x, y in frame_pixels:
            oid_tile.putpixel((x, y), black)

        # Set the 9 data pixels
        # Like documented here: http://upload.querysave.de/code.html
        for i in range(9):
            row = i // 3 + 1
            col = i % 3 + 1

            delta_x = 1 - (2 * (((oid_array[i] & 0x02) >> 1) ^ (oid_array[i] & 0x01)))
            delta_y = 1 - (2 * ((oid_array[i] & 0x02) >> 1))

            x = col * 8 + delta_x
            y = row * 8 + delta_y
            oid_tile.putpixel((x, y), black)

        # Scale if needed (internally on 600dpi, rescale using high-quality resampling)
        scale = resolution / 600
        if scale != 1.0:
            new_size = (int(32 * scale), int(32 * scale))
            oid_tile = oid_tile.resize(new_size, Image.Resampling.NEAREST)

        return oid_tile

    def _create_oid_raster(self, filename: str, raw_code: int, width: int, height: int, resolution: int) -> None:
        """Create a rastered area, which is tiled with an OID raster.

        Args:
            filename: Output filename
            raw_code: Raw OID code to generate
            width: Image width in pixels
            height: Image height in pixels
            resolution: DPI resolution
        """
        # Create main image with transparent background
        image = Image.new('RGBA', (width, height), (255, 255, 255, 0))

        # Get the OID tile
        tile = self._create_oid_tile(raw_code, resolution)
        tile_width, tile_height = tile.size

        # Tile the pattern across the entire image
        for y in range(0, height, tile_height):
            for x in range(0, width, tile_width):
                # Calculate the area to paste
                paste_width = min(tile_width, width - x)
                paste_height = min(tile_height, height - y)

                if paste_width == tile_width and paste_height == tile_height:
                    # Full tile
                    image.paste(tile, (x, y), tile)
                else:
                    # Partial tile at edges
                    cropped_tile = tile.crop((0, 0, paste_width, paste_height))
                    image.paste(cropped_tile, (x, y), cropped_tile)

        # Set DPI information
        dpi_tuple = (resolution, resolution)

        # Save with DPI information
        image.save(filename, dpi=dpi_tuple)

    def generate_single_oid(self, code: int, output_filename: str) -> None:
        """Generate PNG for a single OID code.

        Args:
            code: Internal OID code
            output_filename: Output PNG filename
        """
        if code < 0 or code >= len(self.oid_tbl_int2raw):
            raise ValueError(f"Code {code} is out of range (0-{len(self.oid_tbl_int2raw) - 1})")

        raw_code = self.oid_tbl_int2raw[code]
        if raw_code is None:
            raise ValueError(f"Can't find raw code for internal code {code}")

        # Convert mm to pixels
        pixels_x = int((self.size_x / 25.4) * self.dpi)
        pixels_y = int((self.size_y / 25.4) * self.dpi)

        self._create_oid_raster(output_filename, raw_code, pixels_x, pixels_y, self.dpi)
        print(f"Written {output_filename} ({pixels_x} x {pixels_y})")

    def generate_multiple_oids(self, oid_list: List[Dict[str, Any]]) -> None:
        """Generate PNGs for multiple OID codes from YAML list.

        Args:
            oid_list: List of dictionaries with 'oid' and 'fname' keys
        """
        for entry in oid_list:
            if not isinstance(entry, dict) or 'oid' not in entry or 'fname' not in entry:
                print(f"Warning: Skipping invalid entry: {entry}")
                continue

            try:
                code = entry['oid']
                filename = entry['fname']
                self.generate_single_oid(code, filename)
            except Exception as e:
                print(f"Error generating OID {entry.get('oid', 'unknown')}: {e}")


def load_yaml_file(filename: str) -> List[Dict[str, Any]]:
    """Load OID list from YAML file.

    Args:
        filename: YAML filename to load

    Returns:
        List of OID entries
    """
    filepath = Path(filename)
    if not filepath.exists():
        raise FileNotFoundError(f"Input file '{filename}' not found")

    with open(filepath, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    if not isinstance(data, list):
        raise ValueError(f"YAML file '{filename}' should contain a list of OID entries")

    if not data:
        raise ValueError(f"No entries found in input file '{filename}'")

    return data


def parse_oid_value(oid_str: str) -> int:
    """Parse OID value from string (supports decimal and hex).

    Args:
        oid_str: OID string (e.g., "1234" or "0x04D2")

    Returns:
        Integer OID value
    """
    if oid_str.startswith('0x') or oid_str.startswith('0X'):
        return int(oid_str, 16)
    else:
        return int(oid_str)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="OID 2.0 PNG Bitmap Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 1234
  %(prog)s 0x04D2 --size 25 --dpi 600
  %(prog)s @generate_oids.yaml --size 15
  %(prog)s 100 --output my_oid.png --size-x 30 --size-y 20

Input file format (YAML):
  - oid: 1234
    fname: oid_test.png
  - oid: 5678
    fname: oid_another.png

Note: Requires PIL/Pillow. Install with: pip install Pillow
        """
    )

    parser.add_argument(
        'input',
        help='OID code (decimal/hex) or @filename.yaml for multiple OIDs'
    )

    parser.add_argument(
        '--output', '-O',
        type=str,
        help='Output filename (default: oid_N.png for single OID)'
    )

    parser.add_argument(
        '--size',
        type=float,
        default=20.0,
        help='Size of resulting bitmap in millimeters (default: 20mm)'
    )

    parser.add_argument(
        '--size-x',
        type=float,
        help='Width in millimeters (overrides --size)'
    )

    parser.add_argument(
        '--size-y',
        type=float,
        help='Height in millimeters (overrides --size)'
    )

    parser.add_argument(
        '--dpi',
        type=int,
        choices=[600, 1200],
        default=1200,
        help='Density of resulting image (default: 1200)'
    )

    args = parser.parse_args()

    # Determine size
    size_x = args.size_x if args.size_x is not None else args.size
    size_y = args.size_y if args.size_y is not None else args.size

    if size_x <= 0 or size_y <= 0:
        print("Error: Size must be positive")
        sys.exit(1)

    try:
        # Create generator
        generator = OIDGenerator(dpi=args.dpi, size_x=size_x, size_y=size_y)

        if args.input.startswith('@'):
            # Multiple OIDs from file
            if args.output:
                print("Warning: --output ignored when using input file")

            yaml_filename = args.input[1:]  # Remove '@' prefix
            oid_list = load_yaml_file(yaml_filename)
            generator.generate_multiple_oids(oid_list)

        else:
            # Single OID
            try:
                code = parse_oid_value(args.input)
            except ValueError:
                print(f"Error: Invalid OID value '{args.input}'")
                sys.exit(1)

            if code < 0 or code > 65535:
                print(f"Error: OID code {code} is out of range (0-65535)")
                sys.exit(1)

            output_filename = args.output if args.output else f"oid_{code}.png"
            generator.generate_single_oid(code, output_filename)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
# Generate single OID (decimal)
python oid_png_generator.py 1234

# Generate single OID (hexadecimal)
python oid_png_generator.py 0x04D2 --size 25 --dpi 600

# Generate from YAML file (created by bnl_creator.py)
python oid_png_generator.py @generate_oids.yaml --size 15

# Custom output filename and dimensions
python oid_png_generator.py 100 --output my_oid.png --size-x 30 --size-y 20

# High resolution for printing
python oid_png_generator.py 5678 --dpi 1200 --size 10
"""
