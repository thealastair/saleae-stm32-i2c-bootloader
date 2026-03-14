from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting

# Protocol constants
ACK = 0x79
NACK = 0x1F
BUSY = 0x76

COMMANDS = {
    0x00: "Get",
    0x01: "Get Version",
    0x02: "Get ID",
    0x11: "Read Memory",
    0x21: "Go",
    0x31: "Write Memory",
    0x32: "NS Write Memory",
    0x44: "Erase",
    0x45: "NS Erase",
    0x50: "Special",
    0x51: "Extended Special",
    0x63: "Write Protect",
    0x64: "NS Write Protect",
    0x73: "Write Unprotect",
    0x74: "NS Write Unprotect",
    0x82: "Readout Protect",
    0x83: "NS Readout Protect",
    0x92: "Readout Unprotect",
    0x93: "NS Readout Unprotect",
    0xA1: "NS Get Checksum",
}

SPECIAL_ERASE = {
    0xFFFF: "Global mass erase",
    0xFFFE: "Bank 1 mass erase",
    0xFFFD: "Bank 2 mass erase",
}


def _byte_val(frame):
    """Extract integer value from an I2C data frame."""
    d = frame.data.get("data")
    if isinstance(d, (bytes, bytearray)):
        return d[0]
    return int(d) & 0xFF


def _ack_str(val):
    if val == ACK:
        return "ACK"
    if val == NACK:
        return "NACK"
    if val == BUSY:
        return "BUSY"
    return f"0x{val:02X}"


class Stm32I2cBootloader(HighLevelAnalyzer):
    device_address = StringSetting(label="Device Address (e.g. 0x62 or 98)")

    result_types = {
        "cmd": {"format": "{{data.desc}}"},
        "ack": {"format": "{{data.desc}}"},
        "data": {"format": "{{data.desc}}"},
        "error": {"format": "{{data.desc}}"},
    }

    def __init__(self):
        addr_str = self.device_address.strip() if self.device_address else ""
        if addr_str:
            try:
                self._addr = int(addr_str, 0)  # auto-detects 0x prefix
            except ValueError:
                print(f"STM32 BL: invalid address '{addr_str}', using default 0x62")
                self._addr = 0x62
        else:
            self._addr = 0x62
        print(f"STM32 BL: device address = 0x{self._addr:02X}")
        self._reset()

    def _reset(self):
        self.state = "IDLE"
        self.cmd_code = None
        self.cmd_name = None
        self.cmd_start = None
        self.tx_buf = []          # bytes collected in current sub-phase
        self.is_read = False      # current I2C transfer direction
        self.phase = 0            # sub-phase within command
        self.expected = 0         # expected byte count for variable-length reads
        self.address_matched = False

    def decode(self, frame: AnalyzerFrame):
        t = frame.type

        if t == "start":
            self.tx_buf = []
            self.address_matched = False
            return

        if t == "address":
            addr = int(frame.data["address"][0]) if isinstance(frame.data["address"], (bytes, bytearray)) else int(frame.data["address"])
            self.is_read = bool(frame.data["read"])
            self.address_matched = (addr == self._addr)
            return

        if t == "stop":
            return self._on_stop(frame)

        if t == "data":
            if not self.address_matched:
                return
            val = _byte_val(frame)
            self.tx_buf.append((val, frame))
            return

        return

    def _on_stop(self, stop_frame):
        if not self.address_matched or not self.tx_buf:
            return
        results = self._process_transaction(stop_frame)
        self.tx_buf = []
        return results

    def _process_transaction(self, stop_frame):
        """Process a completed I2C transaction (start..stop) against state machine."""
        data = self.tx_buf
        if not data:
            return

        first_val = data[0][0]
        first_frame = data[0][1]
        last_frame = data[-1][1]

        # ── IDLE: expect a write with command + complement ──
        if self.state == "IDLE":
            if self.is_read:
                return
            if len(data) == 2:
                cmd = data[0][0]
                complement = data[1][0]
                if (cmd ^ complement) == 0xFF and cmd in COMMANDS:
                    self.cmd_code = cmd
                    self.cmd_name = COMMANDS[cmd]
                    self.cmd_start = first_frame.start_time
                    self.state = "WAIT_CMD_ACK"
                    return AnalyzerFrame("cmd", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name} (0x{cmd:02X})"
                    })
                else:
                    return AnalyzerFrame("error", first_frame.start_time, last_frame.end_time, {
                        "desc": f"Bad cmd: 0x{cmd:02X} ^ 0x{complement:02X} != 0xFF"
                    })
            return

        # ── WAIT_CMD_ACK: read 1 byte ACK/NACK from device ──
        if self.state == "WAIT_CMD_ACK":
            if self.is_read and len(data) >= 1:
                resp = first_val
                if resp == NACK:
                    desc = f"{self.cmd_name}: NACK"
                    self._reset()
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": desc
                    })
                if resp == ACK:
                    return self._enter_command_phase(first_frame, last_frame, data)
            return

        # ── Command-specific phases ──
        return self._handle_command_phase(first_frame, last_frame, data, stop_frame)

    def _enter_command_phase(self, first_frame, last_frame, data):
        """Called after receiving ACK for the command byte. Route to command handler."""
        cmd = self.cmd_code

        # Commands that receive data immediately in the ACK read transaction
        # Get: ACK + N + version + cmd_list ... + ACK  (all in one read)
        if cmd == 0x00:
            return self._handle_get(first_frame, last_frame, data)
        if cmd == 0x01:
            return self._handle_get_version(first_frame, last_frame, data)
        if cmd == 0x02:
            return self._handle_get_id(first_frame, last_frame, data)

        # Commands needing address phase next
        if cmd in (0x11, 0x21, 0x31, 0x32):
            self.state = "SEND_ADDRESS"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # Erase commands
        if cmd in (0x44, 0x45):
            self.state = "ERASE_NUM_PAGES"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # Write Protect
        if cmd in (0x63, 0x64):
            self.state = "WP_NUM_SECTORS"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # Simple ACK+ACK commands (Write Unprotect, Readout Protect, Readout Unprotect, NS variants)
        if cmd in (0x73, 0x74, 0x82, 0x83, 0x92, 0x93):
            self.state = "WAIT_FINAL_ACK"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # Special / Extended Special
        if cmd in (0x50, 0x51):
            self.state = "SEND_ADDRESS"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # NS Get Checksum
        if cmd == 0xA1:
            self.state = "SEND_ADDRESS"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

        # Fallback
        self.state = "WAIT_FINAL_ACK"
        return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
            "desc": f"{self.cmd_name}: ACK"
        })

    # ──────────────────────────────────────────────
    # GET command (0x00)
    # ──────────────────────────────────────────────
    def _handle_get(self, first_frame, last_frame, data):
        # Response: ACK, N, version, cmd0..cmdN-1, ACK
        # All received in reads after the ACK. The first byte (ACK=0x79) is data[0].
        # Depending on whether Logic captures it as one or multiple reads,
        # we may get all bytes in one transaction or need to accumulate.
        if len(data) >= 3:
            # Full response in one read
            n_bytes = data[1][0]  # number of bytes to follow - 1
            version = data[2][0]
            cmds = [d[0] for d in data[3:3 + n_bytes]]
            # Check for trailing ACK
            cmd_names = [COMMANDS.get(c, f"0x{c:02X}") for c in cmds]
            ver_major = (version >> 4) & 0xF
            ver_minor = version & 0xF
            desc = f"Get: v{ver_major}.{ver_minor}, cmds=[{', '.join(cmd_names)}]"
            self._reset()
            return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                "desc": desc
            })
        else:
            # Just ACK, need more reads
            self.state = "GET_DATA"
            self.phase = 0
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

    # ──────────────────────────────────────────────
    # GET VERSION command (0x01)
    # ──────────────────────────────────────────────
    def _handle_get_version(self, first_frame, last_frame, data):
        # Response: ACK, version, ACK
        if len(data) >= 3:
            version = data[1][0]
            ver_major = (version >> 4) & 0xF
            ver_minor = version & 0xF
            desc = f"Get Version: v{ver_major}.{ver_minor}"
            self._reset()
            return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                "desc": desc
            })
        else:
            self.state = "GET_VERSION_DATA"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

    # ──────────────────────────────────────────────
    # GET ID command (0x02)
    # ──────────────────────────────────────────────
    def _handle_get_id(self, first_frame, last_frame, data):
        # Response: ACK, N, PID_MSB, PID_LSB, ACK
        if len(data) >= 4:
            n = data[1][0]
            pid = (data[2][0] << 8) | data[3][0]
            desc = f"Get ID: PID=0x{pid:04X}"
            self._reset()
            return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                "desc": desc
            })
        else:
            self.state = "GET_ID_DATA"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: ACK"
            })

    # ──────────────────────────────────────────────
    # State machine for subsequent phases
    # ──────────────────────────────────────────────
    def _handle_command_phase(self, first_frame, last_frame, data, stop_frame):
        cmd = self.cmd_code
        state = self.state

        # ── GET continued data ──
        if state == "GET_DATA":
            if self.is_read:
                vals = [d[0] for d in data]
                n_bytes = vals[0]
                version = vals[1] if len(vals) > 1 else 0
                cmds = vals[2:2 + n_bytes] if len(vals) > 2 else []
                cmd_names = [COMMANDS.get(c, f"0x{c:02X}") for c in cmds]
                ver_major = (version >> 4) & 0xF
                ver_minor = version & 0xF
                desc = f"Get: v{ver_major}.{ver_minor}, cmds=[{', '.join(cmd_names)}]"
                self._reset()
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": desc
                })
            return

        if state == "GET_VERSION_DATA":
            if self.is_read:
                version = data[0][0]
                ver_major = (version >> 4) & 0xF
                ver_minor = version & 0xF
                desc = f"Get Version: v{ver_major}.{ver_minor}"
                self._reset()
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": desc
                })
            return

        if state == "GET_ID_DATA":
            if self.is_read:
                vals = [d[0] for d in data]
                n = vals[0]
                pid = (vals[1] << 8 | vals[2]) if len(vals) >= 3 else 0
                desc = f"Get ID: PID=0x{pid:04X}"
                self._reset()
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": desc
                })
            return

        # ── SEND_ADDRESS: host writes 4-byte address + checksum ──
        if state == "SEND_ADDRESS":
            if not self.is_read and len(data) == 5:
                addr = (data[0][0] << 24) | (data[1][0] << 16) | (data[2][0] << 8) | data[3][0]
                xor = data[0][0] ^ data[1][0] ^ data[2][0] ^ data[3][0]
                chk_ok = (xor == data[4][0])
                self.state = "WAIT_ADDR_ACK"
                desc = f"Addr: 0x{addr:08X}"
                if not chk_ok:
                    desc += " BAD_CHK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": desc
                })
            return

        # ── WAIT_ADDR_ACK ──
        if state == "WAIT_ADDR_ACK":
            if self.is_read and len(data) >= 1:
                resp = data[0][0]
                if resp == NACK:
                    desc = f"{self.cmd_name}: addr NACK"
                    self._reset()
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": desc
                    })
                if resp == ACK:
                    return self._after_addr_ack(first_frame, last_frame, data)
                if resp == BUSY:
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: BUSY"
                    })
            return

        # ── Read Memory: send count + complement ──
        if state == "READ_SEND_COUNT":
            if not self.is_read and len(data) == 2:
                n = data[0][0]
                self.expected = n + 1
                self.state = "READ_COUNT_ACK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"Read {self.expected} bytes"
                })
            return

        if state == "READ_COUNT_ACK":
            if self.is_read and len(data) >= 1:
                resp = data[0][0]
                if resp == NACK:
                    self._reset()
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: count NACK"
                    })
                if resp == ACK:
                    self.state = "READ_DATA"
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: ACK, reading..."
                    })
            return

        if state == "READ_DATA":
            if self.is_read:
                vals = [d[0] for d in data]
                hex_str = " ".join(f"{v:02X}" for v in vals[:16])
                if len(vals) > 16:
                    hex_str += f"... ({len(vals)}B)"
                self._reset()
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"Read: {hex_str}"
                })
            return

        # ── Write Memory: send N + data + checksum ──
        if state == "WRITE_SEND_DATA":
            if not self.is_read and len(data) >= 2:
                n = data[0][0]
                payload = [d[0] for d in data[1:1 + n + 1]]
                hex_str = " ".join(f"{v:02X}" for v in payload[:16])
                if len(payload) > 16:
                    hex_str += f"... ({len(payload)}B)"
                self.state = "WAIT_FINAL_ACK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"Write: {hex_str}"
                })
            return

        # ── Erase: number of pages ──
        if state == "ERASE_NUM_PAGES":
            if not self.is_read and len(data) >= 3:
                num = (data[0][0] << 8) | data[1][0]
                if num >= 0xFFF0:
                    erase_desc = SPECIAL_ERASE.get(num, f"Special 0x{num:04X}")
                    self.state = "WAIT_FINAL_ACK"
                    return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                        "desc": f"Erase: {erase_desc}"
                    })
                else:
                    actual_pages = num + 1
                    self.expected = actual_pages
                    self.state = "ERASE_ACK_PAGES"
                    return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                        "desc": f"Erase {actual_pages} pages"
                    })
            return

        if state == "ERASE_ACK_PAGES":
            if self.is_read and len(data) >= 1:
                resp = data[0][0]
                if resp == ACK:
                    self.state = "ERASE_PAGE_LIST"
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: ACK"
                    })
                if resp == NACK:
                    self._reset()
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: NACK"
                    })
                if resp == BUSY:
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: BUSY"
                    })
            return

        if state == "ERASE_PAGE_LIST":
            if not self.is_read:
                # 2*N bytes (page codes) + checksum
                page_data = [d[0] for d in data[:-1]]  # exclude checksum
                pages = []
                for i in range(0, len(page_data), 2):
                    if i + 1 < len(page_data):
                        pages.append((page_data[i] << 8) | page_data[i + 1])
                pages_str = ", ".join(str(p) for p in pages[:8])
                if len(pages) > 8:
                    pages_str += f"... ({len(pages)} total)"
                self.state = "WAIT_FINAL_ACK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"Erase pages: [{pages_str}]"
                })
            return

        # ── Write Protect: num sectors + sector codes ──
        if state == "WP_NUM_SECTORS":
            if not self.is_read and len(data) >= 2:
                n = data[0][0]
                self.expected = n + 1
                self.state = "WP_SECTOR_ACK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"WP: {self.expected} sectors"
                })
            return

        if state == "WP_SECTOR_ACK":
            if self.is_read:
                resp = data[0][0]
                if resp == ACK:
                    self.state = "WP_SECTOR_LIST"
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: ACK"
                    })
                if resp == NACK:
                    self._reset()
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: NACK"
                    })
            return

        if state == "WP_SECTOR_LIST":
            if not self.is_read:
                sectors = [d[0] for d in data[:-1]]  # exclude checksum
                sectors_str = ", ".join(str(s) for s in sectors[:8])
                if len(sectors) > 8:
                    sectors_str += f"... ({len(sectors)} total)"
                self.state = "WAIT_FINAL_ACK"
                return AnalyzerFrame("data", first_frame.start_time, last_frame.end_time, {
                    "desc": f"WP sectors: [{sectors_str}]"
                })
            return

        # ── WAIT_FINAL_ACK (or BUSY polling) ──
        if state == "WAIT_FINAL_ACK":
            if self.is_read and len(data) >= 1:
                resp = data[0][0]
                if resp == BUSY:
                    return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                        "desc": f"{self.cmd_name}: BUSY"
                    })
                status = _ack_str(resp)
                desc = f"{self.cmd_name}: {status}"
                self._reset()
                return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                    "desc": desc
                })
            return

        return

    def _after_addr_ack(self, first_frame, last_frame, data):
        """Route to next phase after address ACK depending on command."""
        cmd = self.cmd_code

        if cmd == 0x11:  # Read Memory
            self.state = "READ_SEND_COUNT"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: addr ACK"
            })

        if cmd in (0x31, 0x32):  # Write Memory / NS Write Memory
            self.state = "WRITE_SEND_DATA"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: addr ACK"
            })

        if cmd == 0x21:  # Go
            self.state = "WAIT_FINAL_ACK"
            return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
                "desc": f"{self.cmd_name}: addr ACK"
            })

        # Special / Extended Special / NS Get Checksum - just wait for final ack
        self.state = "WAIT_FINAL_ACK"
        return AnalyzerFrame("ack", first_frame.start_time, last_frame.end_time, {
            "desc": f"{self.cmd_name}: addr ACK"
        })
