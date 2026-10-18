"""Minimal binary Android XML (AXML) encoder/decoder.

Real APKs store AndroidManifest.xml (and compiled resources) in Android's
binary XML format. This module implements just enough of the format to
encode manifests for our synthetic test fixtures and to decode manifests
from real APKs:

  Chunks:  RES_XML_TYPE, RES_STRING_POOL_TYPE, START/END_NAMESPACE,
           START/END_ELEMENT (+ attributes with typed values).

String pools in both UTF-16 and UTF-8 are supported on decode; the encoder
writes UTF-16.

Typed attribute values supported: string, int (dec/hex), boolean.
Dimension/float/fraction/reference values decode as their raw string when
the encoder wrote them as strings, which is how aapt stores most manifest
attributes anyway.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

# Typed value types
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class XAttr:
    ns: str          # namespace URI ("" for none)
    name: str
    value: object    # str | int | bool


@dataclass
class XElement:
    name: str
    ns: str = ""
    attrs: list[XAttr] = field(default_factory=list)
    children: list["XElement"] = field(default_factory=list)
    text: str = ""

    def attr(self, name: str, ns: str = "") -> object | None:
        for a in self.attrs:
            if a.name == name and a.ns == ns:
                return a.value
        return None

    def find(self, name: str) -> "XElement | None":
        for c in self.children:
            if c.name == name:
                return c
        return None

    def findall(self, name: str) -> list["XElement"]:
        return [c for c in self.children if c.name == name]


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

class _Encoder:
    def __init__(self) -> None:
        self._strings: list[str] = []
        self._index: dict[str, int] = {}

    def s(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._strings)
            self._strings.append(value)
        return self._index[value]

    def encode(self, root: XElement) -> bytes:
        # pre-register every string so indices are stable
        self._collect(root)
        pool = self._string_pool()
        body = b""
        body += self._namespace(RES_XML_START_NAMESPACE_TYPE, "android", ANDROID_NS)
        body += self._element_start(root)
        for child in root.children:
            body += self._element_full(child)
        body += self._element_end(root)
        body += self._namespace(RES_XML_END_NAMESPACE_TYPE, "android", ANDROID_NS)
        header = struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(pool) + len(body))
        return header + pool + body

    def _collect(self, el: XElement) -> None:
        self.s(el.ns)
        self.s(el.name)
        for a in el.attrs:
            self.s(a.ns)
            self.s(a.name)
            if isinstance(a.value, str):
                self.s(a.value)
        for c in el.children:
            self._collect(c)

    def _string_pool(self) -> bytes:
        strings = self._strings
        offsets: list[int] = []
        data = b""
        for st in strings:
            offsets.append(len(data))
            enc = st.encode("utf-16-le")
            data += struct.pack("<H", len(st)) + enc + b"\x00\x00"
        n = len(strings)
        strings_start = 28 + 4 * n
        header = struct.pack(
            "<HHIIIIII", RES_STRING_POOL_TYPE, 28, 28 + 4 * n + len(data),
            n, 0, SORTED_FLAG, strings_start, 0,
        )
        offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
        return header + offsets_blob + data

    def _typed_value(self, value: object) -> tuple[int, int]:
        if isinstance(value, bool):
            return TYPE_INT_BOOLEAN, 0xFFFFFFFF if value else 0
        if isinstance(value, int):
            return TYPE_INT_DEC, value & 0xFFFFFFFF
        return TYPE_STRING, self.s(str(value))

    def _element_start(self, el: XElement) -> bytes:
        n = len(el.attrs)
        # each attribute: ns, name, rawValue, then typed value (size,res0,datatype,data)
        attr_blob = b""
        for a in el.attrs:
            dtype, data = self._typed_value(a.value)
            raw = self.s(str(a.value)) if isinstance(a.value, str) else 0xFFFFFFFF
            attr_blob += struct.pack("<III", self.s(a.ns), self.s(a.name), raw)
            attr_blob += struct.pack("<HBBI", 8, 0, dtype, data)
        ext = struct.pack("<IIHHHHHH", self.s(el.ns), self.s(el.name),
                          20, 20, n, 0xFFFF, 0xFFFF, 0xFFFF)
        size = 16 + len(ext) + len(attr_blob)
        header = struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, size, 0, 0xFFFFFFFF)
        return header + ext + attr_blob

    def _element_end(self, el: XElement) -> bytes:
        header = struct.pack("<HHIII", RES_XML_END_ELEMENT_TYPE, 16, 24, 0, 0xFFFFFFFF)
        return header + struct.pack("<II", self.s(el.ns), self.s(el.name))

    def _element_full(self, el: XElement) -> bytes:
        out = self._element_start(el)
        for c in el.children:
            out += self._element_full(c)
        out += self._element_end(el)
        return out

    def _namespace(self, ctype: int, prefix: str, uri: str) -> bytes:
        header = struct.pack("<HHIII", ctype, 16, 24, 0, 0xFFFFFFFF)
        return header + struct.pack("<II", self.s(prefix), self.s(uri))


def encode_axml(root: XElement) -> bytes:
    return _Encoder().encode(root)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class _DecodeError(ValueError):
    pass


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.strings: list[str] = []

    def _str(self, idx: int) -> str:
        if idx == 0xFFFFFFFF or idx < 0 or idx >= len(self.strings):
            return ""
        return self.strings[idx]

    def parse(self) -> XElement:
        data = self.data
        if len(data) < 8:
            raise _DecodeError("too short for AXML header")
        ctype, header_size, size = struct.unpack_from("<HHI", data, 0)
        if ctype != RES_XML_TYPE:
            raise _DecodeError(f"not AXML (type=0x{ctype:04x})")
        pos = header_size
        stack: list[XElement] = []
        root: XElement | None = None
        while pos + 8 <= len(data):
            ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
            if csize < 8 or pos + csize > len(data):
                break
            if ctype == RES_STRING_POOL_TYPE:
                self._parse_string_pool(data[pos:pos + csize])
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                el = self._parse_start_element(data[pos:pos + csize])
                if stack:
                    stack[-1].children.append(el)
                else:
                    root = el
                stack.append(el)
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()
            # namespaces / cdata ignored
            pos += csize
        if root is None:
            raise _DecodeError("no root element found")
        return root

    def _parse_string_pool(self, chunk: bytes) -> None:
        (string_count, style_count, flags, strings_start,
         _styles_start) = struct.unpack_from("<IIIII", chunk, 8)
        if flags & UTF8_FLAG:
            self._parse_utf8_pool(chunk, string_count, strings_start)
        else:
            self._parse_utf16_pool(chunk, string_count, strings_start)

    def _parse_utf16_pool(self, chunk: bytes, count: int, start: int) -> None:
        offsets = struct.unpack_from(f"<{count}I", chunk, 28)
        out = []
        for off in offsets:
            pos = start + off
            (char_count,) = struct.unpack_from("<H", chunk, pos)
            pos += 2
            raw = chunk[pos:pos + char_count * 2]
            out.append(raw.decode("utf-16-le", errors="replace"))
        self.strings = out

    def _parse_utf8_pool(self, chunk: bytes, count: int, start: int) -> None:
        offsets = struct.unpack_from(f"<{count}I", chunk, 28)
        out = []
        for off in offsets:
            pos = start + off
            char_count, pos = self._read_varint(chunk, pos)
            byte_count, pos = self._read_varint(chunk, pos)
            raw = chunk[pos:pos + byte_count]
            out.append(raw.decode("utf-8", errors="replace"))
        self.strings = out

    @staticmethod
    def _read_varint(chunk: bytes, pos: int) -> tuple[int, int]:
        b = chunk[pos]
        if b & 0x80:
            return ((b & 0x7F) << 8) | chunk[pos + 1], pos + 2
        return b, pos + 1

    def _parse_start_element(self, chunk: bytes) -> XElement:
        # ResXMLTree_node: header(8) + lineNumber(4) + comment(4)
        ns_idx, name_idx = struct.unpack_from("<II", chunk, 16)
        (attr_start, attr_size, attr_count,
         _id_idx, _class_idx, _style_idx) = struct.unpack_from("<HHHHHH", chunk, 24)
        el = XElement(name=self._str(name_idx), ns=self._str(ns_idx))
        base = 16 + attr_start
        for i in range(attr_count):
            off = base + i * attr_size
            a_ns, a_name, _raw = struct.unpack_from("<III", chunk, off)
            _size, _res0, dtype, data = struct.unpack_from("<HBBI", chunk, off + 12)
            value: object
            if dtype == TYPE_STRING:
                value = self._str(data)
            elif dtype == TYPE_INT_BOOLEAN:
                value = data != 0
            elif dtype in (TYPE_INT_DEC, TYPE_INT_HEX):
                value = struct.unpack("<i", struct.pack("<I", data))[0]
            else:
                # A resource reference (e.g. @string/app_name): the raw string
                # index is empty, so keep the resource id in an honest,
                # greppable form. Resolving it needs resources.arsc; the
                # manifest layer treats this as "unresolved" and falls back
                # instead of leaking a placeholder into the UI.
                value = self._str(_raw) if _raw != 0xFFFFFFFF else f"@0x{data:08x}"
            el.attrs.append(XAttr(ns=self._str(a_ns), name=self._str(a_name), value=value))
        return el


def parse_axml(data: bytes) -> XElement:
    """Decode binary Android XML bytes into an XElement tree."""
    return _Decoder(data).parse()


def manifest_to_text(el: XElement, indent: int = 0) -> str:
    """Render a decoded manifest tree as readable XML text (for reports)."""
    pad = "  " * indent
    attrs = "".join(
        f' {a.name}="{a.value}"' if not a.ns
        else f' android:{a.name}="{a.value}"'
        for a in el.attrs
    )
    if not el.children and not el.text:
        return f"{pad}<{el.name}{attrs}/>"
    inner = "".join("\n" + manifest_to_text(c, indent + 1) for c in el.children)
    return f"{pad}<{el.name}{attrs}>{inner}\n{pad}</{el.name}>"
