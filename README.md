# Albituzka - Albi Pen Tools

A comprehensive Python toolkit for working with Albi smart pen firmware, content files, and OID generation. This project is a Python conversion of the original Perl tools by jindroush, published under the MPL license.

## Overview

The Albi pen is a smart reading device that uses OID (Optical Identification) technology to interact with specially printed books and materials. This toolkit provides tools for:

- **Firmware Analysis**: Extract and analyze Albi pen firmware files
- **Content Creation**: Create and modify BNL content files for custom books
- **OID Generation**: Generate printable OID codes for interactive elements
- **File Conversion**: Convert between different formats and extract media files

## Features

### 🔧 Firmware Tools
- **Firmware Cutter**: Analyze and extract components from firmware files (update.chp/updateA.chp)
- **OID Table Extractor**: Extract OID conversion tables from OidProducer.exe

### 📚 Content Tools  
- **BNL Disassembler**: Decrypt and analyze BNL content files
- **BNL Creator**: Create custom BNL files from YAML configuration
- **Media Extraction**: Extract and decrypt MP3 audio files

### 🖨️ OID Generation
- **PNG Generator**: Create printable OID codes as high-quality PNG images
- **Batch Processing**: Generate multiple OIDs from YAML configuration files

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Required Packages
- `PyYAML>=6.0` - YAML file processing
- `mutagen>=1.45.0` - MP3 metadata handling  
- `Pillow>=8.0.0` - Image generation and processing

## Quick Start

### Analyze Firmware
```bash
# Basic firmware analysis
python fw_cutter.py updateA.chp

# Extract all components
python fw_cutter.py update.chp --save --save-bin --output ./extracted
```

### Create OID Codes
```bash
# Generate single OID
python oid_png_generator.py 1234 --size 20 --dpi 1200

# Generate from YAML file
python oid_png_generator.py @oids.yaml --size 15
```

### Work with BNL Files
```bash
# Disassemble BNL file
python bnl_dis.py book.bnl --extract

# Create BNL from YAML
python bnl_creator.py --input book.yaml --output custom.bnl
```

## Tools Reference

### Firmware Cutter (`fw_cutter.py`)
Analyzes Albi firmware files and extracts components.

```bash
python fw_cutter.py [input_file] [options]

Options:
  --save          Save firmware internal files (texts, OID mappings)
  --save-bin      Save firmware subparts (modules, MP3s)  
  --output DIR    Output directory for extracted files
```

**Extracted Files:**
- Firmware modules and binaries
- MP3 audio files
- Text strings and translations
- OID-to-firmware code mappings
- Button assignment tables

### OID PNG Generator (`oid_png_generator.py`)
Creates printable OID codes as PNG images.

```bash
python oid_png_generator.py <oid> [options]
python oid_png_generator.py @input.yaml [options]

Options:
  --output FILE   Output filename
  --size SIZE     Size in millimeters (default: 20mm)
  --size-x SIZE   Width in millimeters
  --size-y SIZE   Height in millimeters
  --dpi DPI       Resolution: 600 or 1200 (default: 1200)
```

**Features:**
- High-quality PNG output with DPI metadata
- Batch generation from YAML files
- Albi-compatible OID 2.0 format
- Customizable size and resolution

### BNL Disassembler (`bnl_dis.py`)
Decrypts and analyzes BNL content files.

```bash
python bnl_dis.py input.bnl [options]

Options:
  --extract       Extract MP3 files
  --bitrate       Analyze MP3 bitrates
  --output DIR    Output directory
```

**Extracted Data:**
- Decrypted MP3 audio files
- YAML configuration for reconstruction
- OID mappings and quiz data
- Media file references

### BNL Creator (`bnl_creator.py`)
Creates BNL content files from YAML configuration.

```bash
python bnl_creator.py [options]

Options:
  --input FILE    Input YAML file (default: bnl.yaml)
  --output FILE   Output BNL file (default: bnl.bnl)
  --media DIR     Media files directory
```

**Features:**
- YAML-based configuration
- Automatic media file encryption
- Quiz and interaction support
- Multiple book modes

### OID Table Extractor (`oid_table_extract.py`)
Extracts OID conversion tables from OidProducer.exe.

```bash
python oid_table_extract.py [options]

Options:
  --input FILE        Input executable (default: OidProducer10.20.exe)
  --output FILE       Output Python file (default: oid_converter.py)
  --table-offset HEX  Table offset (default: 0x8F9DE0)
  --verify-md5        Verify file MD5 hash
```

## File Formats

### YAML Configuration
The tools use YAML files for configuration and data exchange:

```yaml
# OID generation list
- oid: 1234
  fname: oid_start.png
- oid: 5678  
  fname: oid_quiz1.png

# BNL book configuration
header:
  book_id: 0x0803
  encryption:
    header_key: 0x00000100
    prekey: [0x00, 0x00, ...]

oids:
  oid_x2710:  # OID 10000
    mode_0:
      - audio_file1.mp3
    mode_1:
      - audio_file2.mp3
```

### Supported File Types
- **Firmware**: `.chp` files (update.chp, updateA.chp)
- **Content**: `.bnl` files (encrypted book content)
- **Audio**: `.mp3` files (encrypted/decrypted)
- **Images**: `.png` files (OID codes)
- **Configuration**: `.yaml` files
- **Executables**: `OidProducer.exe` (for table extraction)

## Examples

### Creating a Custom Book

1. **Extract existing book for reference:**
```bash
python bnl_dis.py existing_book.bnl --extract --output ./reference
```

2. **Modify the generated YAML configuration:**
```bash
# Edit bnl.yaml with your content
# Add your MP3 files to the directory
```

3. **Create new BNL file:**
```bash
python bnl_creator.py --input bnl.yaml --output my_book.bnl
```

4. **Generate OID codes:**
```bash
python oid_png_generator.py @generate_oids.yaml --size 15 --dpi 1200
```

### Firmware Analysis Workflow

1. **Analyze firmware structure:**
```bash
python fw_cutter.py updateA.chp
```

2. **Extract all components:**
```bash
python fw_cutter.py updateA.chp --save --save-bin --output ./firmware_extracted
```

3. **Examine extracted files:**
- `1bin_extracted_texts.txt` - UI text strings
- `3bin_oid2fw_codes.txt` - OID mappings
- `*.mp3` - System sounds and audio

## Technical Details

### OID Technology
- **Format**: OID 2.0 compatible with Albi pens
- **Checksum**: Ting/Albi checksum algorithm
- **Size**: 1.35mm dots (larger than TipToi's 1mm)
- **Resolution**: 600/1200 DPI output

### Encryption
- **BNL Files**: Custom XOR-based encryption
- **MP3 Files**: Encrypted with derived keys
- **Key Derivation**: Complex algorithm from pre-keys

### File Structure
- **Firmware**: Multi-section binary with modules
- **BNL**: Header + OID table + media table + encrypted MP3s
- **OID Tables**: 64K lookup tables for code conversion

## Contributing

This project is a Python conversion of the original Perl tools. Contributions are welcome:

1. **Bug Reports**: Open issues for any problems found
2. **Feature Requests**: Suggest improvements or new tools
3. **Code Contributions**: Submit pull requests with enhancements
4. **Documentation**: Help improve documentation and examples

### Development Setup
```bash
git clone https://github.com/yourusername/albituzka-python
cd albituzka-python
pip install -r requirements.txt
python -m pytest tests/  # Run tests (if available)
```

## License

This project is published under the **Mozilla Public License (MPL)**, maintaining compatibility with the original Perl tools by jindroush.

## Credits

- **Original Author**: jindroush - Created the original Perl toolkit
- **Python Conversion**: Converted to Python with enhancements
- **OID Algorithm**: Based on work by ernie76 & nomeata from tip-toi-reveng project
- **Community**: Thanks to all contributors and testers

## Disclaimer

This toolkit is for educational and research purposes. Users are responsible for complying with applicable laws and regulations when working with firmware and content files.

## Support

- **Issues**: Report bugs and problems via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions and help
- **Documentation**: Check the tool-specific help with `--help` option

---

**Note**: This project is not affiliated with or endorsed by the manufacturers of Albi pens or related hardware.
