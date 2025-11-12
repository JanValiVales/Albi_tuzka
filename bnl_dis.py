#!/usr/bin/env python3
"""
BNL File Decryptor/Disassembler

A Python tool for decrypting and disassembling Albi BNL files, including some Arabic downloads.
Converted from Perl script by jindroush, published under MPL license.
Part of https://github.com/jindroush/albituzka

Usage:
    python bnl_dis.py input_file.bnl [options]

Options:
    --extract       Extract MP3 files to output directory
    --bitrate       Compute MP3 files bitrate
    --nosave        Don't output any files (analysis only)
    --output DIR    Output directory for extracted files (default: current directory)

Output files (when saving is enabled):
    *.mp3           Decrypted MP3 files (in output directory)
    rbuf.dat        Copy of input file with read data overwritten by # character (for coverage testing)
    bnl.yaml        BNL data structures in YAML format (consumed by bnl_creator.pl)

Examples:
    python bnl_dis.py book.bnl --extract
    python bnl_dis.py book.bnl --extract --output ./extracted_media
    python bnl_dis.py book.bnl --bitrate --nosave
    python bnl_dis.py book.bnl --extract --bitrate --output /path/to/output

Requirements:
    PyYAML>=6.0
    mutagen>=1.45.0

"""

import argparse
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
from bnl_utils import oid_table

try:
    from mutagen.mp3 import MP3

    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False
    print("Warning: mutagen not available. MP3 bitrate analysis disabled.")
    print("Install with: pip install mutagen")


class BNLDisassembler:
    """BNL file disassembler and decryptor."""

    def __init__(self, input_file: str, extract_mp3: bool = False,
                 extract_mp3_br: bool = False, save: bool = True, output_dir: str = "."):
        self.input_file = Path(input_file)
        self.extract_mp3 = extract_mp3
        self.extract_mp3_br = extract_mp3_br
        self.save = save
        self.output_dir = Path(output_dir)

        # Create output directory if it doesn't exist
        if self.extract_mp3 or self.extract_mp3_br:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize OID converter
        self.oid_tbl_int2raw = oid_table

        # Global data structures
        self.bnl_data = {}
        self.lo_rbuf = (1 << 32) - 1
        self.hi_rbuf = 0
        self.file_data = b''
        self.rbuf = bytearray()
        self.file_pos = 0

    def _read_file(self) -> None:
        """Read the entire file into memory."""
        with open(self.input_file, 'rb') as f:
            self.file_data = f.read()
        self.rbuf = bytearray(self.file_data)

    def _seek(self, pos: int) -> None:
        """Set file position."""
        self.file_pos = pos

    def _read(self, size: int) -> bytes:
        """Read data from current position."""
        data = self.file_data[self.file_pos:self.file_pos + size]
        self._mark_rbuf(size)
        self.file_pos += size
        return data

    def _mark_rbuf(self, length: int) -> None:
        """Mark read bytes in rbuf for coverage testing."""
        start_pos = self.file_pos
        end_pos = start_pos + length

        self.hi_rbuf = max(self.hi_rbuf, end_pos)
        self.lo_rbuf = min(self.lo_rbuf, start_pos)

        if self.lo_rbuf < 0:
            raise ValueError("Invalid rbuf position")

        # Mark read bytes with '#'
        for i in range(start_pos, end_pos):
            if i < len(self.rbuf):
                self.rbuf[i] = ord('#')

    def _get_ptr_value(self, val: int, dkey: int) -> int:
        """XOR pointer with dkey or return special values unchanged."""
        if val == 0 or val == 0xFFFFFFFF:
            return val
        return val ^ dkey

    def _oid2rawoid(self, inp_code: int) -> str:
        """Convert internal OID to raw OID."""
        if inp_code < len(self.oid_tbl_int2raw):
            return str(self.oid_tbl_int2raw[inp_code])
        return "no such code"

    def _keygen(self, pre_key: List[int]) -> List[int]:
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

        for pk_ptr in range(len(pre_key)):
            for block in range(8):
                idx = block * 16 * 4 + pk_ptr * 4 + keygen_tbl[pk_ptr][block]
                if idx < len(key):
                    key[idx] = pre_key[pk_ptr]

        return key

    def _decrypt_mem(self, data: bytes, key: List[int]) -> bytes:
        """Decrypt memory buffer using key."""
        key_length = len(key)
        decrypted = bytearray(data)

        for i, byte_val in enumerate(decrypted):
            key_idx = i % key_length
            if key[key_idx] != 0:
                if (byte_val != 0 and byte_val != 0xFF and
                        byte_val != key[key_idx] and byte_val != (key[key_idx] ^ 0xFF)):
                    decrypted[i] = byte_val ^ key[key_idx]

        return bytes(decrypted)

    def _get_mp3_info(self, filename: Path) -> Optional[Dict[str, Any]]:
        """Get MP3 file information using mutagen."""
        if not MUTAGEN_AVAILABLE:
            return None

        try:
            audio = MP3(str(filename))
            if audio.info:
                return {
                    'bitrate': int(audio.info.bitrate / 1000) if audio.info.bitrate else 0,
                    'length': audio.info.length,
                    'channels': getattr(audio.info, 'channels', 1),
                    'sample_rate': getattr(audio.info, 'sample_rate', 44100),
                }
        except Exception as e:
            print(f"Error reading MP3 info for {filename}: {e}")
        return None

    def _allmedia_tbl(self, ptr: int, bnl_section: Dict, bnl_key: str, book_modes: int) -> None:
        """Process all media table."""
        if ptr == 0xFFFFFFFF:
            return

        self._seek(ptr)
        lcnt = 0

        while lcnt < book_modes:
            cnt_data = self._read(2)
            cnt = struct.unpack('<H', cnt_data)[0]

            if cnt == 0:
                print(f"\tcnt: 0")
            else:
                vals_data = self._read(cnt * 2)
                vals = struct.unpack(f'<{cnt}H', vals_data)
                media_list = [f"media_{val:04d}.mp3" for val in vals]
                print(f"\tcnt: {cnt}, media:[{', '.join(f'{val:04d}' for val in vals)}]")

                if bnl_key not in bnl_section:
                    bnl_section[bnl_key] = {}
                bnl_section[bnl_key][f"mode_{lcnt}"] = media_list

            lcnt += 1

    def _oid_tbl(self, ptr: int, bnl_section: Dict, bnl_key: str) -> None:
        """Process OID table."""
        if ptr == 0xFFFFFFFF:
            return

        self._seek(ptr)
        cnt_data = self._read(2)
        cnt = struct.unpack('<H', cnt_data)[0]

        vals_data = self._read(cnt * 2)
        vals = struct.unpack(f'<{cnt}H', vals_data)

        oid_list = [f"oid_x{val:04X}" for val in vals]
        print(f"\tcnt: {cnt}, oids:[{', '.join(f'0x{val:04X}' for val in vals)}]")
        bnl_section[bnl_key] = oid_list

    def _quiz_one_quiz(self, ptr: int) -> Dict[str, Any]:
        """Process one quiz."""
        self._seek(ptr)
        header_data = self._read(10)
        q_type, q_cnt, q_asked, q_verify, q_oid = struct.unpack('<5H', header_data)

        print(f"\t\tqtype:{q_type:04X} cnt:{q_cnt:04X} questions:{q_asked:04X} "
              f"verify:{q_verify:04X} quiz_intro_oid: {q_oid:04X}")

        one_quiz = {
            'q_type': f"0x{q_type:04X}",
            'q_asked': f"0x{q_asked:04X}",
            'q_unk': f"0x{q_verify:04X}",
            'q_oid': f"oid_x{q_oid:04X}",
            'questions': []
        }

        ptrs_data = self._read(4 * q_cnt)
        ptrs = struct.unpack(f'<{q_cnt}I', ptrs_data)

        for ptr in ptrs:
            print(f"\t\t\tptr/{ptr:08X}: ", end="")
            self._seek(ptr)

            if q_type in [4, 8]:
                # Quiz types 4 and 8
                header_data = self._read(8)
                q4_oid, q4_unk1, q4_unk2, q4_unk3 = struct.unpack('<4H', header_data)

                print(f"quiz_question{q_type} oid:{q4_oid:04X} unk1:{q4_unk1:04X} "
                      f"unk2:{q4_unk2:04X} unk3:{q4_unk3:04X}")

                q4_data = {
                    f'q{q_type}_oid': f"oid_x{q4_oid:04X}",
                    f'q{q_type}_unk1': f"0x{q4_unk1:04X}",
                    f'q{q_type}_unk2': f"0x{q4_unk2:04X}",
                    f'q{q_type}_unk3': f"0x{q4_unk3:04X}"
                }

                field_names = [
                    "good_reply_oids", "unknown_oids", "good_reply_snd1", "good_reply_snd2",
                    "bad_reply_snd1", "bad_reply_snd2", "final_good", "final_bad"
                ]

                for i, field_name in enumerate(field_names):
                    cnt_data = self._read(2)
                    cnt = struct.unpack('<H', cnt_data)[0]
                    oids_data = self._read(2 * cnt)
                    oids = struct.unpack(f'<{cnt}H', oids_data)

                    oid_list = [f"oid_x{oid:04X}" for oid in oids]
                    print(f"\t\t\t\t{field_name:<15} oids:[{', '.join(f'oid_x{oid:04X}' for oid in oids)}]")

                    q4_data[f'q{q_type}_{field_name}'] = oid_list

                one_quiz['questions'].append(q4_data)

            elif q_type == 0:
                # Question type 0
                header_data = self._read(6)
                q0_unk, q0_oid, oid_cnt = struct.unpack('<3H', header_data)

                oids_data = self._read(2 * oid_cnt)
                oids = struct.unpack(f'<{oid_cnt}H', oids_data)

                print(f"quiz_question0 unk:{q0_unk:04X} oid_question:{q0_oid:04X} "
                      f"replies_oids:[{', '.join(f'0x{oid:04X}' for oid in oids)}]")

                question_data = {
                    'q1_unk': f"0x{q0_unk:04X}",
                    'q1_oid': f"oid_x{q0_oid:04X}",
                    'q1_good_reply_oids': [f"oid_x{oid:04X}" for oid in oids]
                }
                one_quiz['questions'].append(question_data)

            elif q_type == 1:
                # Question type 1
                header_data = self._read(6)
                q1_question, q1_correct_reply, oid_cnt = struct.unpack('<3H', header_data)

                oids_data = self._read(2 * oid_cnt)
                oids = struct.unpack(f'<{oid_cnt}H', oids_data)

                print(f"quiz_question1 oid_question:{q1_question:04X} "
                      f"oid_correct_reply:{q1_correct_reply:04X} "
                      f"replies_oids:[{', '.join(f'0x{oid:04X}' for oid in oids)}]")

                question_data = {
                    'q1_question': f"0x{q1_question:04X}",
                    'q1_correct_reply': f"oid_x{q1_correct_reply:04X}",
                    'q1_good_reply_oids': [f"oid_x{oid:04X}" for oid in oids]
                }
                one_quiz['questions'].append(question_data)

            else:
                raise ValueError(f"Unknown quiz question type: {q_type}")

        return one_quiz

    def _quiz_tbl(self, ptr: int) -> None:
        """Process quiz table."""
        first_ptr = None
        cnt = 0

        while True:
            self._seek(ptr)
            dptr_data = self._read(4)
            dptr = struct.unpack('<I', dptr_data)[0]

            print(f"\tquiz {cnt + 100:04X}) ptr/{dptr:08X}")
            quiz_data = self._quiz_one_quiz(dptr)

            if 'quiz' not in self.bnl_data:
                self.bnl_data['quiz'] = {'quizes': []}
            self.bnl_data['quiz']['quizes'].append(quiz_data)

            if first_ptr is None:
                first_ptr = dptr

            ptr += 4
            cnt += 1

            if first_ptr is not None and ptr >= first_ptr:
                break

    def _media_tbl(self, ptr: int, pre_key: List[int]) -> None:
        """Process media table and extract MP3 files."""
        cnt = 0
        bitrate_stats = {}
        key = self._keygen(pre_key)
        first_file_ptr = None

        while True:
            self._seek(ptr)
            data = self._read(8)
            d1, d2 = struct.unpack('<2I', data)

            if first_file_ptr is None:
                first_file_ptr = d1

            # Check for end of table
            if d2 == 0 or ptr + 4 >= first_file_ptr:
                print(f"\textracted 0000 to {cnt - 1:04d} media files")

                if bitrate_stats:
                    # Output most common bitrate
                    most_common = max(bitrate_stats.items(), key=lambda x: x[1])
                    percentage = int(most_common[1] * 100 / cnt)
                    print(f"\tmp3s_br: {most_common[0]}: {percentage}%")
                return

            output_filename = self.output_dir / f"media_{cnt:04d}.mp3"

            extract_file = False
            remove_file = False

            if self.extract_mp3_br:
                extract_file = True
                remove_file = True

            if self.extract_mp3:
                extract_file = True
                remove_file = False
                self.extract_mp3_br = True

            # Don't extract if file already exists with non-zero size
            if output_filename.exists() and output_filename.stat().st_size > 0:
                extract_file = False
                remove_file = False

            if extract_file:
                self._seek(d1)
                encrypted_data = self._read(d2 - d1)
                decrypted_data = self._decrypt_mem(encrypted_data, key)

                with open(output_filename, 'wb') as f:
                    f.write(decrypted_data)
            else:
                # Just mark the data as read
                self._seek(d2)
                self._mark_rbuf(d2 - d1)

            if self.extract_mp3_br and MUTAGEN_AVAILABLE:
                mp3_info = self._get_mp3_info(output_filename)
                if mp3_info:
                    bitrate_str = f"{mp3_info['bitrate']}kbps CBR mono/{mp3_info['sample_rate'] / 1000}kHz"
                    bitrate_stats[bitrate_str] = bitrate_stats.get(bitrate_str, 0) + 1

            if remove_file:
                output_filename.unlink(missing_ok=True)

            cnt += 1
            ptr += 4

    def _verify_rbuf(self) -> None:
        """Verify rbuf coverage."""
        if self.hi_rbuf <= self.lo_rbuf:
            return

        section = self.rbuf[self.lo_rbuf:self.hi_rbuf]
        # Count non-processed bytes (not #, \0, or \xFF)
        unprocessed = sum(1 for b in section if b not in [ord('#'), 0, 0xFF])

        print(f"coverage: [{self.lo_rbuf:08X}-{self.hi_rbuf:08X}] {unprocessed}")

    def disassemble(self) -> None:
        """Main disassembly function."""
        self._read_file()
        file_length = len(self.file_data)

        print(f"file: {self.input_file}")
        print(f"len: {file_length:08X}")

        # Read header
        print("header:")
        self._seek(0)
        header_data = self._read(80 * 4)
        dwords = struct.unpack('<80I', header_data)

        dkey = dwords[0]
        print(f"dkey: {dkey:08X}")
        print(f"number of quizes: {(dkey >> 8) & 0xFFFF}")

        # Initialize BNL data structure
        self.bnl_data = {
            'header': {
                'encryption': {
                    'header_key': f"0x{dkey:08X}"
                }
            }
        }

        # Process header pointers
        oid_table_ptr = self._get_ptr_value(dwords[1], dkey)
        print(f"end of header/oid table ptr: {oid_table_ptr:08X}")

        if not oid_table_ptr or (oid_table_ptr % 0x200):
            raise ValueError(f"OID table pointing to 0x{oid_table_ptr:X}, expecting multiples of 0x200")

        mtbl_ptr = self._get_ptr_value(dwords[2], dkey)
        print(f"media table: {mtbl_ptr:08X}")

        ptr_start_button_1st_read_media = self._get_ptr_value(dwords[3], dkey)
        ptr_start_button_2nd_read_media = self._get_ptr_value(dwords[4], dkey)

        unk_tbl_ptr5 = self._get_ptr_value(dwords[5], dkey)

        # Unpack words from dwords 6 and 7
        words = struct.unpack('<4H', struct.pack('<2I', dwords[6], dwords[7]))
        oid_min, oid_max, mediafiles_cnt, w3 = words

        print(f"min file oid: {oid_min:04X}")
        print(f"max file oid: {oid_max:04X}")
        print(f"media files cnt: {mediafiles_cnt}")
        print(f"w07b: {w3:04X}")

        unk_tbl_ptr8 = self._get_ptr_value(dwords[8], dkey)
        ptr_book_mode_read_media = self._get_ptr_value(dwords[9], dkey)

        print(f"dw0A: {self._get_ptr_value(dwords[10], dkey):08X}")
        book_modes = dwords[11]
        print(f"book modes: {book_modes:08X}")

        for i in range(12, 17):
            print(f"dw{i:02X}: {self._get_ptr_value(dwords[i], dkey):08X}")

        # Process various media tables
        print(f"start_button_1st_read: {ptr_start_button_1st_read_media:08X} (dw3)")
        self._allmedia_tbl(ptr_start_button_1st_read_media, self.bnl_data['header'],
                           "start_button_1st_read", book_modes)

        print(f"start_button_2nd_read: {ptr_start_button_2nd_read_media:08X} (dw4)")
        if ptr_start_button_2nd_read_media != 0xFFFFFFFF:
            self._allmedia_tbl(ptr_start_button_2nd_read_media, self.bnl_data['header'],
                               "start_button_2nd_read", book_modes)

        print(f"book_mode_read: {ptr_book_mode_read_media:08X} (dw9)")
        self._allmedia_tbl(ptr_book_mode_read_media, self.bnl_data['header'],
                           "book_mode_read", book_modes)

        # Process quiz tables
        ptr_quiz_table = self._get_ptr_value(dwords[17], dkey)
        print(f"quiz_table: {ptr_quiz_table:08X}")
        self._quiz_tbl(ptr_quiz_table)

        # Process quiz-related OID tables
        quiz_tables = [
            (18, "quiz_pos1"),
            (19, "quiz_pos2"),
            (20, "quiz_neg1"),
            (21, "quiz_neg2")
        ]

        for idx, table_name in quiz_tables:
            ptr = self._get_ptr_value(dwords[idx], dkey)
            print(f"{table_name}: {ptr:08X}")
            if 'quiz' not in self.bnl_data:
                self.bnl_data['quiz'] = {}
            self._oid_tbl(ptr, self.bnl_data['quiz'], table_name)

        # Process other header tables
        unk_tbl_ptr_16 = self._get_ptr_value(dwords[22], dkey)
        print(f"unk_tbl_ptr_16: {unk_tbl_ptr_16:08X}")
        self._oid_tbl(unk_tbl_ptr_16, self.bnl_data['header'], "unk_tbl_ptr_16")

        book_id = dwords[23]
        print(f"book_id: {book_id:08X} [{self._oid2rawoid(book_id)}]")
        self.bnl_data['header']['book_id'] = f"0x{book_id:04X}"

        # Process remaining header pointers (24-66)
        for i in range(24, 67):
            ptr = self._get_ptr_value(dwords[i], dkey)
            print(f"dw{i:02X}: {ptr:08X}")

        # Process specific OID tables
        oid_tables = [
            (39, "unk_tbl_ptr_27"),
            (40, "unk_tbl_ptr_28"),
            (41, "unk_tbl_ptr_29")
        ]

        for idx, table_name in oid_tables:
            ptr = self._get_ptr_value(dwords[idx], dkey)
            print(f"{table_name}: {ptr:08X}")
            self._oid_tbl(ptr, self.bnl_data['header'], table_name)

        ptr_quiz_results = self._get_ptr_value(dwords[42], dkey)
        print(f"quiz_results: {ptr_quiz_results:08X}")
        if 'quiz' not in self.bnl_data:
            self.bnl_data['quiz'] = {}
        self._oid_tbl(ptr_quiz_results, self.bnl_data['quiz'], "quiz_results")

        # Process remaining dwords
        for i in range(43, 80):
            ptr = self._get_ptr_value(dwords[i], dkey)
            print(f"dw{i:02X}: {ptr:08X}")

        # Process encryption key
        k3 = (dkey >> 24) & 0xFF
        self._seek(0x140)
        key_data = self._read(20)

        key_values = struct.unpack('<I16B', key_data)
        dw = key_values[0]
        pre_key = list(key_values[1:])

        print(f"key modifier: {k3:02X}")
        self.bnl_data['header']['encryption']['prekey_dw'] = f"0x{dw:08X}"
        self.bnl_data['header']['encryption']['prekey'] = [f"0x{b:02X}" for b in pre_key]

        print(f"Pre-key_dw: {dw:08X}")
        print(f"Pre-key: {' '.join(f'{b:02X}' for b in pre_key)}")

        # Apply key modifier
        real_key = [(b + k3) & 0xFF for b in pre_key]
        print(f"Realkey: {' '.join(f'{b:02X}' for b in real_key)}")

        # Process media table
        self._media_tbl(mtbl_ptr, real_key)

        print("end of header processing\n")

        # Process OID to media table
        print("OID2media table start")
        self._seek(oid_table_ptr)
        oid_count = oid_max - oid_min + 1
        oid_data = self._read(oid_count * 4)
        oid_ptrs = struct.unpack(f'<{oid_count}I', oid_data)

        self.bnl_data['oids'] = {}
        oids_ranges = {}
        o_st = None

        for i, ptr in enumerate(oid_ptrs):
            cnt = oid_min + i

            if ptr != 0xFFFFFFFF:
                print(f"file oid-{cnt:04X} [paper:{self._oid2rawoid(cnt)}]) "
                      f"{oid_table_ptr + 4 * (cnt - oid_min):08X} {ptr:08X}")
                self._allmedia_tbl(ptr, self.bnl_data['oids'], f"oid_x{cnt:04X}", book_modes)

                if o_st is None:
                    o_st = cnt
            else:
                if o_st is not None:
                    oids_ranges[f"{o_st:04X}-{cnt - 1:04X}"] = True
                o_st = None

        if o_st is not None:
            oids_ranges[f"{o_st:04X}-{oid_count - 1:04X}"] = True

        # Save files
        if self.save:
            # Save rbuf (always in current directory)
            with open("rbuf.dat", "wb") as f:
                f.write(self.rbuf)

            # Save YAML (always in current directory)
            with open("bnl.yaml", "w", encoding='utf-8') as f:
                # Write in the same format as the original Perl script
                yaml.dump(self.bnl_data['header'], f, default_flow_style=False, allow_unicode=True)
                f.write("---\n")
                if 'quiz' in self.bnl_data:
                    yaml.dump(self.bnl_data['quiz'], f, default_flow_style=False, allow_unicode=True)
                    f.write("---\n")
                yaml.dump(self.bnl_data['oids'], f, default_flow_style=False, allow_unicode=True)

        print(f"oid-spans:[{','.join(sorted(oids_ranges.keys()))}]")
        self._verify_rbuf()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BNL File Decryptor/Disassembler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s book.bnl --extract
  %(prog)s book.bnl --extract --output ./extracted_media
  %(prog)s book.bnl --bitrate --nosave
  %(prog)s book.bnl --extract --bitrate --output /path/to/output

Output files:
  MP3 files       Decrypted MP3 files (in output directory if specified)
  rbuf.dat        Copy of input file with read data marked (current directory)
  bnl.yaml        BNL data structures in YAML format (current directory)

Note: For MP3 bitrate analysis, install mutagen: pip install mutagen
        """
    )

    parser.add_argument(
        'input_file',
        help='Input BNL file to process'
    )

    parser.add_argument(
        '--extract',
        action='store_true',
        help='Extract MP3 files to output directory'
    )

    parser.add_argument(
        '--bitrate',
        action='store_true',
        help='Compute MP3 files bitrate (requires mutagen)'
    )

    parser.add_argument(
        '--nosave',
        action='store_true',
        help="Don't output any files (analysis only)"
    )

    parser.add_argument(
        '--output',
        type=str,
        default='.',
        help='Output directory for extracted MP3 files (default: current directory)'
    )

    args = parser.parse_args()

    # Validate input file
    if not Path(args.input_file).exists():
        print(f"Error: Input file '{args.input_file}' not found")
        sys.exit(1)

    # Validate output directory
    output_path = Path(args.output)
    if args.extract or args.bitrate:
        try:
            output_path.mkdir(parents=True, exist_ok=True)
            print(f"Output directory: {output_path.absolute()}")
        except Exception as e:
            print(f"Error: Cannot create output directory '{args.output}': {e}")
            sys.exit(1)

    # Check mutagen availability for bitrate analysis
    if args.bitrate and not MUTAGEN_AVAILABLE:
        print("Warning: mutagen not available. Bitrate analysis will be skipped.")
        print("Install with: pip install mutagen")

    # Configure options
    extract_mp3 = args.extract
    extract_mp3_br = args.bitrate
    save = not args.nosave

    try:
        # Create disassembler and run
        disassembler = BNLDisassembler(
            input_file=args.input_file,
            extract_mp3=extract_mp3,
            extract_mp3_br=extract_mp3_br,
            save=save,
            output_dir=args.output
        )

        disassembler.disassemble()

        # Print summary
        if extract_mp3 or extract_mp3_br:
            mp3_files = list(output_path.glob("media_*.mp3"))
            if mp3_files:
                print(f"\nExtracted {len(mp3_files)} MP3 files to: {output_path.absolute()}")
            else:
                print(f"\nNo MP3 files were extracted.")

        if save:
            print(f"Analysis files saved:")
            print(f"  - rbuf.dat: Coverage testing file")
            print(f"  - bnl.yaml: BNL data structures")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
"""
# Extract to current directory (default behavior)
python bnl_dis.py book.bnl --extract

# Extract to specific directory
python bnl_dis.py book.bnl --extract --output ./extracted_media

# Extract to absolute path
python bnl_dis.py book.bnl --extract --output /home/user/music/albi_files

# Combine with bitrate analysis
python bnl_dis.py book.bnl --extract --bitrate --output ./output

# Just analyze bitrates without keeping files, but specify temp directory
python bnl_dis.py book.bnl --bitrate --nosave --output ./temp
"""
