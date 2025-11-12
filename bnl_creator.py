#!/usr/bin/env python3
"""
BNL Creator Tool

A Python tool for creating BNL files from YAML configuration and MP3 media files.
Converted from Perl script by jindroush, published under MPL license.
Part of https://github.com/jindroush/albituzka

This tool consumes bnl.yaml file as produced by bnl_dis.py tool and creates BNL output file.

Usage:
    python bnl_creator.py [options]

Options:
    --input FILE        Input YAML filename (default: bnl.yaml)
    --output FILE       Output BNL filename (default: bnl.bnl)
    --media-dir DIR     Directory containing MP3 media files (default: current directory)
    --no-encryption     Generate weak encryption (for testing)

Examples:
    python bnl_creator.py
    python bnl_creator.py --input my_book.yaml --output my_book.bnl
    python bnl_creator.py --input book.yaml --media-dir ./media --output book.bnl
    python bnl_creator.py --input test.yaml --no-encryption
"""

import argparse
import struct
import sys
import random
from pathlib import Path
from typing import Dict, List, Optional
import yaml


class BNLCreator:
    """BNL file creator from YAML configuration."""

    def __init__(self, input_file: str = "bnl.yaml", output_file: str = "bnl.bnl",
                 media_dir: str = ".", encryption: bool = True):
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.media_dir = Path(media_dir)
        self.encryption = encryption

        # Global data structures
        self.bnl_data = {}
        self.block_header = bytearray(b'\xFF' * 0x200)
        self.block_oids = b''
        self.block_others = bytearray()
        self.block_media = bytearray()

        self.all_media = {}
        self.book_id = 0
        self.max_book_mode = -1
        self.media_cnt = 0
        self.header_key = 0
        self.prekey = []
        self.real_key = []
        self.prekey_dw = 0

        # OID translation tables
        self.oid_arr = [None] * 65536
        self.oid_noprint = {}
        self.oid_to_num_map = {}

    def _load_input(self) -> None:
        """Load and parse YAML input file."""
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file '{self.input_file}' not found")

        with open(self.input_file, 'r', encoding='utf-8') as f:
            yaml_content = f.read()

        lines = yaml_content.count('\n')
        print(f"Loaded {lines} lines from {self.input_file}")

        # Parse YAML documents
        documents = list(yaml.safe_load_all(yaml_content))

        if len(documents) < 3:
            raise ValueError("Input file is malformed, expecting 3 YAML documents")

        self.bnl_data = {
            'header': documents[0] or {},
            'quiz': documents[1] or {},
            'oids': documents[2] or {}
        }

        # Validate structure
        for section in ['header', 'quiz', 'oids']:
            if not isinstance(self.bnl_data[section], dict):
                raise ValueError(f"Input file is malformed, {section} section is not a dictionary")

        print("Parsed input data.")

    def _gen_rand_arr(self, length: int) -> List[int]:
        """Generate array of random bytes."""
        return [random.randint(0, 255) for _ in range(length)]

    def _setup_encryption(self) -> None:
        """Setup encryption keys."""
        if 'encryption' in self.bnl_data['header']:
            print("Encryption: from input file")
            encryption_data = self.bnl_data['header']['encryption']
            self.header_key = int(encryption_data['header_key'], 16)
            self.prekey_dw = int(encryption_data['prekey_dw'], 16)
            self.prekey = [int(x, 16) for x in encryption_data['prekey']]
        else:
            if self.encryption:
                print("Encryption: generated strong")
                self.header_key = struct.unpack('<I', bytes(self._gen_rand_arr(4)))[0]
                self.prekey_dw = struct.unpack('<I', bytes(self._gen_rand_arr(4)))[0]
                self.prekey_dw = (self.prekey_dw & 0xFFFFFF00) | ((0xF5 - (self.header_key >> 24)) & 0xFF)
                self.prekey = self._gen_rand_arr(16)
            else:
                print("Encryption: generated weak")
                self.header_key = 0x00000100
                self.prekey_dw = 0xF5
                self.prekey = [0] * 16

        if len(self.prekey) != 16:
            raise ValueError("Incorrect encryption key length")

        if (((self.header_key >> 24) + (self.prekey_dw & 0xFF)) & 0xFF) != 0xF5:
            raise ValueError("Incorrect encryption check")

        # Set header values
        struct.pack_into('<I', self.block_header, 0, self.header_key)
        struct.pack_into('<I', self.block_header, 4, 0x200 ^ self.header_key)
        struct.pack_into('<I', self.block_header, 0x140, self.prekey_dw)
        struct.pack_into('16B', self.block_header, 0x144, *self.prekey)

        self.real_key = self._keygen(self.prekey, (self.header_key >> 24) & 0xFF)

    def _keygen(self, pre_key: List[int], pk: int) -> List[int]:
        """Generate 512-byte decryption key from pre-key."""
        keygen_tbl = [
            [0, 1, 1, 2, 0, 1, 1, 2],
            [3, 3, 2, 1, 1, 2, 2, 1],
            [2, 2, 3, 1, 2, 2, 3, 1],
            [1, 0, 0, 0, 1, 0, 0, 0],
            [1, 2, 0, 1, 1, 2, 0, 1],
            [1, 2, 0, 2, 1, 2, 2, 2],
            [2, 1, 0, 0, 2, 1, 0, 0],
            [2, 3, 2, 2, 2, 3, 2, 2],
            [3, 0, 3, 1, 3, 0, 3, 1],
            [0, 0, 1, 1, 0, 3, 1, 1],
            [2, 2, 3, 0, 2, 2, 3, 1],
            [3, 1, 0, 0, 3, 1, 0, 0],
            [3, 3, 0, 2, 3, 3, 1, 2],
            [1, 2, 0, 0, 1, 2, 0, 0],
            [2, 1, 0, 3, 2, 1, 3, 3],
            [0, 0, 0, 0, 0, 0, 0, 0]
        ]

        key = [0] * 512

        # Every byte of input key
        for pk_ptr in range(len(pre_key)):
            # Is written on the same 0-3 offset in each of 8 blocks
            for block in range(8):
                # The position is modified by keygen_tbl
                idx = block * 16 * 4 + pk_ptr * 4 + keygen_tbl[pk_ptr][block]
                if idx < len(key):
                    key[idx] = (pre_key[pk_ptr] + pk) & 0xFF

        return key

    def _decrypt_mem(self, data: bytes, key: List[int]) -> bytes:
        """Encrypt/decrypt memory buffer using key (XOR is symmetric)."""
        key_length = len(key)
        result = bytearray(data)

        for i, byte_val in enumerate(result):
            key_idx = i % key_length
            if key[key_idx] != 0:
                if (byte_val != 0 and byte_val != 0xFF and
                        byte_val != key[key_idx] and byte_val != (key[key_idx] ^ 0xFF)):
                    result[i] = byte_val ^ key[key_idx]

        return bytes(result)

    def _process_oids(self) -> None:
        """Process OID definitions and create translation tables."""
        hr_oids = self.bnl_data['oids']

        min_oid = 0
        max_oid = 0

        for txt_oid in hr_oids.keys():
            if txt_oid.startswith('oid_'):
                oid_part = txt_oid[4:]  # Remove 'oid_' prefix

                # Handle extensions like oid_x1234_something
                if '_' in oid_part:
                    oid_part = oid_part.split('_')[0]

                if oid_part.startswith('x'):
                    num = int(oid_part[1:], 16)
                else:
                    num = int(oid_part)

                if self.oid_arr[num] is not None:
                    raise ValueError(f"Duplicate oid definition for '{txt_oid}' (previous def {self.oid_arr[num]})")

                self.oid_arr[num] = txt_oid
                self.oid_to_num_map[txt_oid] = num
                max_oid = max(max_oid, num)
            else:
                raise ValueError(f"Invalid oid format {txt_oid}")

        print(f"Oids range: 0x{min_oid:04X}-0x{max_oid:04X}")
        struct.pack_into('<HH', self.block_header, 0x18, min_oid, max_oid)

        return min_oid, max_oid

    def _parse_media_arrays(self, media_data: Optional[Dict]) -> None:
        """Parse media arrays to find max book mode and collect media files."""
        if not media_data or not isinstance(media_data, dict):
            return

        for mode_key in media_data.keys():
            if mode_key.startswith('mode_'):
                try:
                    mode = int(mode_key[5:])  # Remove 'mode_' prefix
                    self.max_book_mode = max(self.max_book_mode, mode)

                    for media_file in media_data[mode_key]:
                        self.all_media[media_file] = {'idx': 0}
                except ValueError:
                    raise ValueError(f"Expected keyword mode_X, got '{mode_key}', invalid input file")

    def _oid_to_num(self, oid_str: str) -> int:
        """Convert oid_XXXX string to decimal number."""
        if oid_str in self.oid_to_num_map:
            return self.oid_to_num_map[oid_str]

        if oid_str.startswith('oid_'):
            oid_part = oid_str[4:]
            if '_' in oid_part:
                oid_part = oid_part.split('_')[0]

            if oid_part.startswith('x'):
                return int(oid_part[1:], 16)
            else:
                return int(oid_part)

        raise ValueError(f"Invalid oid format '{oid_str}'")

    def _warn_on_oid(self, oid: str, context: str) -> None:
        """Warn if OID is referenced but not defined."""
        if oid not in self.bnl_data['oids']:
            print(f"warning: there is a reference to OID {oid} (from {context}) not present in oid table!")

    def _write_media_array(self, media_data: Optional[Dict]) -> int:
        """Write media array and return pointer."""
        if not media_data:
            return 0xFFFFFFFF

        ptr_return = len(self.block_others)

        for mode in range(self.max_book_mode):
            mode_key = f"mode_{mode}"

            if mode_key in media_data:
                media_list = media_data[mode_key]
                # Write count and media indices
                self.block_others.extend(struct.pack('<H', len(media_list)))
                indices = [self.all_media[media_file]['idx'] for media_file in media_list]
                self.block_others.extend(struct.pack(f'<{len(indices)}H', *indices))
            else:
                # Empty array
                self.block_others.extend(struct.pack('<H', 0))

        return ptr_return

    def _write_media_arrays_hdr(self, hdr_offset: int, media_data: Optional[Dict]) -> None:
        """Write media array and patch encrypted pointer to header."""
        ptr = self._write_media_array(media_data)

        if ptr != 0xFFFFFFFF:
            # Calculate absolute pointer
            abs_ptr = len(self.block_header) + len(self.block_oids) + ptr
            struct.pack_into('<I', self.block_header, hdr_offset, abs_ptr ^ self.header_key)

    def _write_oidtable(self, oid_list: Optional[List[str]], noprint: bool = False) -> int:
        """Write OID table and return pointer."""
        if not oid_list:
            return 0xFFFFFFFF

        ptr_return = len(self.block_others)

        # Write count and OID numbers
        self.block_others.extend(struct.pack('<H', len(oid_list)))
        oid_nums = [self._oid_to_num(oid) for oid in oid_list]
        self.block_others.extend(struct.pack(f'<{len(oid_nums)}H', *oid_nums))

        # Mark OIDs as non-printable if requested
        for oid in oid_list:
            self._warn_on_oid(oid, "oidtable")
            if noprint:
                oid_num = self._oid_to_num(oid)
                self.oid_noprint[oid_num] = True

        return ptr_return

    def _write_oidtable_hdr(self, hdr_offset: int, oid_list: Optional[List[str]]) -> None:
        """Write OID table and patch encrypted pointer to header."""
        ptr = self._write_oidtable(oid_list, noprint=True)

        if ptr != 0xFFFFFFFF:
            # Calculate absolute pointer
            abs_ptr = len(self.block_header) + len(self.block_oids) + ptr
            struct.pack_into('<I', self.block_header, hdr_offset, abs_ptr ^ self.header_key)

    def _pack_hex_oid_array(self, oid_list: List[str], noprint: bool = False) -> bytes:
        """Pack OID array into binary format."""
        result = struct.pack('<H', len(oid_list))
        oid_nums = [self._oid_to_num(oid) for oid in oid_list]
        result += struct.pack(f'<{len(oid_nums)}H', *oid_nums)

        for oid in oid_list:
            self._warn_on_oid(oid, "oid_array")
            if noprint:
                oid_num = self._oid_to_num(oid)
                self.oid_noprint[oid_num] = True

        return result

    def _write_quiz(self, quiz_list: List[Dict]) -> None:
        """Write quiz data."""
        if not quiz_list:
            print("warning: zero length of quiz tables!")
            return

        ptr_return = len(self.block_others)

        # Write pointer to quiz pointers table
        abs_ptr = len(self.block_header) + len(self.block_oids) + ptr_return
        struct.pack_into('<I', self.block_header, 0x11 * 4, abs_ptr ^ self.header_key)

        # Reserve space for quiz pointers
        quiz_ptrs_offset = len(self.block_others)
        quiz_cnt = len(quiz_list)
        quiz_ptrs = [0xFFFFFFFF] * quiz_cnt
        self.block_others.extend(struct.pack(f'<{quiz_cnt}I', *quiz_ptrs))

        # Write each quiz
        for cnt_quiz, quiz_data in enumerate(quiz_list):
            quiz_ptrs[cnt_quiz] = len(self.block_others)

            questions = quiz_data['questions']
            q_type = int(quiz_data['q_type'], 16)
            q_asked = int(quiz_data['q_asked'], 16)
            q_verify = int(quiz_data.get('q_verify', quiz_data.get('q_unk', '0x0000')), 16)
            q_oid = self._oid_to_num(quiz_data['q_oid'])

            if q_type not in [0, 4, 8]:
                print(f"warning: quiz_type {q_type} is not documented, could cause unknown behavior!")

            self._warn_on_oid(quiz_data['q_oid'], "q_oid")

            q_count = len(questions)

            if q_count < q_asked:
                print(f"warning: number of questions ({q_count}) < questions asked ({q_asked})!")

            if q_type == 0:
                quiz_results = self.bnl_data['quiz'].get('quiz_results', [])
                if q_asked + 1 != len(quiz_results):
                    print(f"warning: number of questions asked ({q_asked}) does not match "
                          f"number of results ({len(quiz_results)}) in quiz_results!")

            # Write quiz header
            quiz_header = struct.pack('<5H', q_type, q_count, q_asked, q_verify, q_oid)
            self.block_others.extend(quiz_header)

            # Prepare questions data
            questions_data = bytearray()
            questions_ptrs = []

            for question in questions:
                questions_ptrs.append(len(questions_data))

                if q_type in [4, 8]:
                    # Quiz types 4 and 8
                    q4_oid = self._oid_to_num(question[f'q{q_type}_oid'])
                    q4_unk1 = int(question[f'q{q_type}_unk1'], 16)
                    q4_unk2 = int(question[f'q{q_type}_unk2'], 16)
                    q4_unk3 = int(question[f'q{q_type}_unk3'], 16)

                    self._warn_on_oid(question[f'q{q_type}_oid'], f"q{q_type}_oid")

                    question_data = struct.pack('<4H', q4_oid, q4_unk1, q4_unk2, q4_unk3)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_good_reply_oids'])
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_unknown_oids'])
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_good_reply_snd1'], True)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_good_reply_snd2'], True)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_bad_reply_snd1'], True)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_bad_reply_snd2'], True)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_final_good'], True)
                    question_data += self._pack_hex_oid_array(question[f'q{q_type}_final_bad'], True)
                    questions_data.extend(question_data)

                elif q_type == 1:
                    # Question type 1
                    q1_question = self._oid_to_num(question['q1_question'])
                    q1_correct_reply = self._oid_to_num(question['q1_correct_reply'])

                    self._warn_on_oid(question['q1_question'], "q1_question")
                    self._warn_on_oid(question['q1_correct_reply'], "q1_correct_reply")

                    self.oid_noprint[q1_question] = True
                    self.oid_noprint[q1_correct_reply] = True

                    question_data = struct.pack('<2H', q1_question, q1_correct_reply)
                    question_data += self._pack_hex_oid_array(question['q1_good_reply_oids'])
                    questions_data.extend(question_data)

                elif q_type == 0:
                    # Question type 0
                    q0_unk = int(question['q1_unk'], 16)  # Note: uses q1_unk for q0
                    q0_oid = self._oid_to_num(question['q1_oid'])  # Note: uses q1_oid for q0

                    self._warn_on_oid(question['q1_oid'], "q0_oid")
                    self.oid_noprint[q0_oid] = True

                    question_data = struct.pack('<2H', q0_unk, q0_oid)
                    question_data += self._pack_hex_oid_array(question['q1_good_reply_oids'])
                    questions_data.extend(question_data)

                else:
                    raise ValueError(f"Unknown quiz type: {q_type}")

            # Calculate absolute pointers for questions
            base_ptr = len(self.block_header) + len(self.block_oids) + len(self.block_others) + len(questions_ptrs) * 4
            abs_questions_ptrs = [base_ptr + ptr for ptr in questions_ptrs]

            # Write question pointers and data
            self.block_others.extend(struct.pack(f'<{len(abs_questions_ptrs)}I', *abs_questions_ptrs))
            self.block_others.extend(questions_data)

        # Update quiz pointers with absolute addresses
        base_ptr = len(self.block_header) + len(self.block_oids)
        abs_quiz_ptrs = [base_ptr + ptr for ptr in quiz_ptrs]
        struct.pack_into(f'<{quiz_cnt}I', self.block_others, quiz_ptrs_offset, *abs_quiz_ptrs)

    def _write_media_table(self) -> None:
        """Write media table."""
        ptr_return = len(self.block_others)
        abs_ptr = len(self.block_header) + len(self.block_oids) + ptr_return
        struct.pack_into('<I', self.block_header, 0x2 * 4, abs_ptr ^ self.header_key)

        # Reserve space for media table
        self.media_table_offset = len(self.block_others)
        media_ptrs = [0xFFFFFFFF] * (self.media_cnt + 1)
        self.block_others.extend(struct.pack(f'<{len(media_ptrs)}I', *media_ptrs))

    def _write_all_media(self) -> None:
        """Write all media files."""
        # Create array sorted by index
        media_files = [None] * self.media_cnt
        for filename, data in self.all_media.items():
            media_files[data['idx']] = filename

        # Check for available files
        available_files = {}
        if self.media_dir.exists():
            for mp3_file in self.media_dir.glob("*.mp3"):
                available_files[str(mp3_file)] = False

        media_ptrs = []
        errors = 0

        # Process each media file
        for filename in media_files:
            if filename is None:
                continue

            # Calculate position with 0x200 alignment
            current_pos = (len(self.block_header) + len(self.block_oids) +
                           len(self.block_others) + len(self.block_media))

            padding_needed = current_pos % 0x200
            if padding_needed:
                padding = b'\x00' * (0x200 - padding_needed)
                self.block_media.extend(padding)
                current_pos += len(padding)

            media_ptrs.append(current_pos)

            # Read and encrypt media file
            media_path = self.media_dir / filename
            if not media_path.exists():
                print(f"Input file references sound file '{media_path}' which is not there/can't be opened")
                errors += 1
                continue

            try:
                with open(media_path, 'rb') as f:
                    file_data = f.read()

                if str(media_path) in available_files:
                    available_files[str(media_path)] = True
                else:
                    print(f"warning: file '{media_path}' referenced is not in media dir '{self.media_dir}'")

                # Encrypt the data
                encrypted_data = self._decrypt_mem(file_data, self.real_key)
                self.block_media.extend(encrypted_data)

            except Exception as e:
                print(f"Error reading file '{media_path}': {e}")
                errors += 1

        if errors:
            raise RuntimeError("There were errors loading mp3 files, stopping.")

        # Add final pointer
        final_pos = (len(self.block_header) + len(self.block_oids) +
                     len(self.block_others) + len(self.block_media))
        media_ptrs.append(final_pos)

        # Update media table
        if len(media_ptrs) != self.media_cnt + 1:
            raise AssertionError("Number of pointers doesn't match number of media files")

        struct.pack_into(f'<{len(media_ptrs)}I', self.block_others,
                         self.media_table_offset, *media_ptrs)

        # Warn about unused files
        for filepath, used in available_files.items():
            if not used:
                print(f"warning: there is unreferenced file in media dir: '{filepath}'")

    def _generate_print_oids(self, min_oid: int, max_oid: int) -> None:
        """Generate helper YAML file for OID PNG generator."""
        to_print = []

        # Always generate start icon
        self._generate_print_entry(to_print, self.book_id, "icon_start")

        # System icons
        sys_icons = {
            "volume_up": 0x07,
            "volume_down": 0x08,
            "stop": 0x06,
            "compare": 0x63
        }

        if 'sys_icons' in self.bnl_data['header']:
            for icon in self.bnl_data['header']['sys_icons']:
                if icon in sys_icons:
                    self._generate_print_entry(to_print, sys_icons[icon], f"icon_{icon}")
                else:
                    raise ValueError(f"Referencing unknown sys_icon '{icon}'")

        # Mode icons
        mode_icons = {
            "mode_1": 0x04, "mode_2": 0x05, "mode_3": 0x03, "mode_4": 0x02, "mode_5": 0x01,
            "mode_6": 0x0225, "mode_7": 0x0226, "mode_8": 0x0227, "mode_9": 0x0228,
            "mode_10": 0x0229, "mode_11": 0x022A, "mode_12": 0x022B
        }

        for mode in range(self.max_book_mode):
            mode_key = f"mode_{mode + 1}"
            if mode_key in mode_icons:
                self._generate_print_entry(to_print, mode_icons[mode_key], f"icon_{mode_key}")

        # Quiz OIDs
        for oid in range(100, 500):
            if self.oid_arr[oid] and oid not in self.oid_noprint:
                self._generate_print_entry(to_print, oid, f"icon_quiz_{oid - 99}")

        # User defined OIDs
        for oid in range(10000, max_oid + 1):
            if self.oid_arr[oid] and oid not in self.oid_noprint:
                oid_name = self.oid_arr[oid].replace('oid_', '')
                self._generate_print_entry(to_print, oid, oid_name)

        # Save to file
        if to_print:
            with open("generate_oids.yaml", 'w', encoding='utf-8') as f:
                yaml.dump(to_print, f, default_flow_style=False, allow_unicode=True)

    def _generate_print_entry(self, to_print: List, oid: int, name: str) -> None:
        """Add entry to print list."""
        entry = {
            'oid': oid,
            'fname': f"oid_{name}.png"
        }
        to_print.append(entry)

    def create(self) -> None:
        """Main creation function."""
        self._load_input()

        # Setup encryption
        self._setup_encryption()

        # Process OIDs
        min_oid, max_oid = self._process_oids()

        # Parse media arrays to find max book mode
        self.max_book_mode = -1

        # Parse OID media arrays
        for oid_data in self.bnl_data['oids'].values():
            self._parse_media_arrays(oid_data)

        # Parse header media arrays
        oid_tables = [
            "start_button_1st_read", "start_button_2nd_read", "unk_tbl_ptr5",
            "book_mode_read", "unk_tbl_ptr_18", "unk_tbl_ptr_19", "unk_tbl_ptr_1a",
            "unk_tbl_ptr_1b", "unk_tbl_ptr_1c", "unk_tbl_ptr_1d", "unk_tbl_ptr_1e",
            "unk_tbl_ptr_1f", "unk_tbl_ptr_20", "unk_tbl_ptr_21", "unk_tbl_ptr_22",
            "unk_tbl_ptr_23", "unk_tbl_ptr_24", "unk_tbl_ptr_25", "unk_tbl_ptr_26",
            "unk_tbl_ptr_33", "unk_tbl_ptr_34", "unk_tbl_ptr_35", "unk_tbl_ptr_36",
            "unk_tbl_ptr_37", "unk_tbl_ptr_38", "unk_tbl_ptr_39", "unk_tbl_ptr_40"
        ]

        for table_name in oid_tables:
            if table_name in self.bnl_data['header']:
                self._parse_media_arrays(self.bnl_data['header'][table_name])

        if self.max_book_mode == -1:
            raise ValueError("Max book mode left uninitialized after parsing. Input YAML file is incorrect.")

        self.max_book_mode += 1
        struct.pack_into('<I', self.block_header, 0x2C, self.max_book_mode)
        print(f"Book modes: {self.max_book_mode}")

        # Set book ID
        self.book_id = int(self.bnl_data['header']['book_id'], 16)
        if not (701 <= self.book_id <= 9999):
            raise ValueError(f"Book id {self.book_id} is out of range (701-9999)")

        struct.pack_into('<I', self.block_header, 0x5C, self.book_id)
        print(f"Book id: 0x{self.book_id:04X} ({self.book_id})")

        # Number media files
        self.media_cnt = 0
        for filename in sorted(self.all_media.keys()):
            self.all_media[filename]['idx'] = self.media_cnt
            self.media_cnt += 1

        struct.pack_into('<HH', self.block_header, 0x1C, self.media_cnt, 0)
        print(f"Media: references {self.media_cnt} files")

        # Create empty OID array
        oid_count = max_oid - min_oid + 1
        self.block_oids = b'\xFF' * (oid_count * 4)

        # Write header media arrays
        header_offsets = [
            (0x03, "start_button_1st_read"), (0x04, "start_button_2nd_read"),
            (0x05, "unk_tbl_ptr5"), (0x09, "book_mode_read"),
            (0x18, "unk_tbl_ptr_18"), (0x19, "unk_tbl_ptr_19"), (0x1a, "unk_tbl_ptr_1a"),
            (0x1b, "unk_tbl_ptr_1b"), (0x1c, "unk_tbl_ptr_1c"), (0x1d, "unk_tbl_ptr_1d"),
            (0x1e, "unk_tbl_ptr_1e"), (0x1f, "unk_tbl_ptr_1f"), (0x20, "unk_tbl_ptr_20"),
            (0x21, "unk_tbl_ptr_21"), (0x22, "unk_tbl_ptr_22"), (0x23, "unk_tbl_ptr_23"),
            (0x24, "unk_tbl_ptr_24"), (0x25, "unk_tbl_ptr_25"), (0x26, "unk_tbl_ptr_26"),
            (0x33, "unk_tbl_ptr_33"), (0x34, "unk_tbl_ptr_34"), (0x35, "unk_tbl_ptr_35"),
            (0x36, "unk_tbl_ptr_36"), (0x37, "unk_tbl_ptr_37"), (0x38, "unk_tbl_ptr_38"),
            (0x39, "unk_tbl_ptr_39"), (0x40, "unk_tbl_ptr_40")
        ]

        for offset, table_name in header_offsets:
            if table_name in self.bnl_data['header']:
                self._write_media_arrays_hdr(offset * 4, self.bnl_data['header'][table_name])

        # Write OID media arrays and patch OID array
        oid_array = bytearray(self.block_oids)
        for i in range(min_oid, max_oid + 1):
            if self.oid_arr[i] and self.oid_arr[i] in self.bnl_data['oids']:
                ptr = self._write_media_array(self.bnl_data['oids'][self.oid_arr[i]])
                if ptr != 0xFFFFFFFF:
                    abs_ptr = len(self.block_header) + len(self.block_oids) + ptr
                    struct.pack_into('<I', oid_array, i * 4, abs_ptr)

        self.block_oids = bytes(oid_array)

        # Write quizzes
        if 'quizes' in self.bnl_data['quiz']:
            self._write_quiz(self.bnl_data['quiz']['quizes'])

        # Write OID tables
        oid_table_offsets = [
            (0x12, 'quiz_pos1'), (0x13, 'quiz_pos2'), (0x14, 'quiz_neg1'), (0x15, 'quiz_neg2'),
            (0x16, 'unk_tbl_ptr_16'), (0x27, 'unk_tbl_ptr_27'), (0x28, 'unk_tbl_ptr_28'),
            (0x29, 'unk_tbl_ptr_29'), (0x2a, 'quiz_results')
        ]

        for offset, table_name in oid_table_offsets:
            if table_name in self.bnl_data['quiz']:
                self._write_oidtable_hdr(offset * 4, self.bnl_data['quiz'][table_name])
            elif table_name in self.bnl_data['header']:
                self._write_oidtable_hdr(offset * 4, self.bnl_data['header'][table_name])

        # Write media table
        self._write_media_table()

        # Write all media files
        self._write_all_media()

        # Write output file
        with open(self.output_file, 'wb') as f:
            f.write(self.block_header)
            f.write(self.block_oids)
            f.write(self.block_others)
            f.write(self.block_media)

        file_size = self.output_file.stat().st_size
        print(f"Created {self.output_file}, {file_size} bytes long.")

        # Generate OID print helper
        self._generate_print_oids(min_oid, max_oid)

        print("Done.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BNL Creator Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --input my_book.yaml --output my_book.bnl
  %(prog)s --input book.yaml --media-dir ./media --output book.bnl
  %(prog)s --input test.yaml --no-encryption

This tool consumes bnl.yaml file as produced by bnl_dis.py tool and creates BNL output file.
        """
    )

    parser.add_argument(
        '--input',
        type=str,
        default='bnl.yaml',
        help='Input YAML filename (default: bnl.yaml)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='bnl.bnl',
        help='Output BNL filename (default: bnl.bnl)'
    )

    parser.add_argument(
        '--media-dir',
        type=str,
        default='.',
        help='Directory containing MP3 media files (default: current directory)'
    )

    parser.add_argument(
        '--no-encryption',
        action='store_true',
        help='Generate weak encryption (for testing)'
    )

    args = parser.parse_args()

    # Validate input file
    if not Path(args.input).exists():
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)

    # Validate media directory
    media_path = Path(args.media_dir)
    if not media_path.exists():
        print(f"Error: Media directory '{args.media_dir}' not found")
        sys.exit(1)

    try:
        # Create BNL creator and run
        creator = BNLCreator(
            input_file=args.input,
            output_file=args.output,
            media_dir=args.media_dir,
            encryption=not args.no_encryption
        )

        creator.create()

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
# Basic usage (uses bnl.yaml in current directory)
python bnl_creator.py

# Specify input and output files
python bnl_creator.py --input my_book.yaml --output my_book.bnl

# Specify media directory
python bnl_creator.py --input book.yaml --media-dir ./media --output book.bnl

# Generate with weak encryption for testing
python bnl_creator.py --input test.yaml --no-encryption
"""