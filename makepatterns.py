import idaapi # type: ignore
import idautils # type: ignore
import idc # type: ignore
import ida_bytes # type: ignore
import re
from pathlib import Path

def get_insn_pattern(ea):
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if length == 0:
        return ["%02X" % ida_bytes.get_byte(ea)]
    pat = ["%02X" % ida_bytes.get_byte(ea + i) for i in range(length)]
    to_wildcard = set()
    for op in insn.ops:
        if op.type == idaapi.o_void:
            break
        if op.offb == 0:
            continue
        for j in range(op.offb, length):
            to_wildcard.add(j)
    for j in to_wildcard:
        pat[j] = "?"
    return pat

def trim(parts):
    while parts and parts[-1] == "?":
        parts.pop()
    return parts

def scan_pattern(pattern_str):
    parts = pattern_str.split()
    sig = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(sig, 0, " ".join("??" if p == "?" else p for p in parts), 16)
    if err:
        return []
    results = []
    end = idaapi.inf_get_max_ea()
    ea = idaapi.get_imagebase()
    while ea < end:
        result = ida_bytes.bin_search(ea, end, sig, ida_bytes.BIN_SEARCH_FORWARD)
        found = result[0] if isinstance(result, tuple) else result
        if found == idaapi.BADADDR:
            break
        results.append(found)
        if len(results) > 2:
            break
        ea = found + 1
    return results

def build_func_pattern(ea, max_bytes=64):
    func = idaapi.get_func(ea)
    func_end = func.end_ea if func else ea + max_bytes
    chunks, count, cursor = [], 0, ea
    while cursor != idaapi.BADADDR and cursor < func_end and count < max_bytes:
        p = get_insn_pattern(cursor)
        chunks.extend(p)
        count += len(p)
        cursor = idc.next_head(cursor, func_end)
    return " ".join(trim(chunks))

def collect_forward(start_ea, func, after):
    end = start_ea
    for _ in range(after):
        nxt = idc.next_head(end, func.end_ea)
        if nxt == idaapi.BADADDR:
            break
        end = nxt
    chunks, ea = [], start_ea
    while ea != idaapi.BADADDR and ea <= end:
        chunks.extend(get_insn_pattern(ea))
        if ea == end:
            break
        ea = idc.next_head(ea, func.end_ea)
    return chunks

def build_data_xref_pattern(target_ea, after=4):
    for xref in idautils.XrefsTo(target_ea, 0):
        ref_ea = xref.frm
        func = idaapi.get_func(ref_ea)
        if not func:
            continue
        chunks = collect_forward(ref_ea, func, after)
        if chunks:
            pat = " ".join(trim(chunks))
            if pat:
                return pat
    return None

def build_func_xref_pattern(target_ea, before=3, after=2):
    for xref in idautils.XrefsTo(target_ea, 0):
        ref_ea = xref.frm
        func = idaapi.get_func(ref_ea)
        if not func:
            continue
        start = ref_ea
        for _ in range(before):
            prev = idc.prev_head(start, func.start_ea)
            if prev == idaapi.BADADDR:
                break
            start = prev
        chunks, ea = [], start
        while ea != idaapi.BADADDR and ea <= ref_ea:
            chunks.extend(get_insn_pattern(ea))
            if ea == ref_ea:
                break
            ea = idc.next_head(ea, func.end_ea)
        after_chunks = collect_forward(ref_ea, func, after)
        if chunks:
            chunks.extend(after_chunks[len(get_insn_pattern(ref_ea)):])
        if chunks:
            pat = " ".join(trim(chunks))
            if pat:
                return pat
    return None

def make_pattern(ea):
    func = idaapi.get_func(ea)
    is_func = func and func.start_ea == ea

    if is_func:
        for max_b in [32, 64, 128]:
            pat = build_func_pattern(ea, max_b)
            if not pat:
                continue
            results = scan_pattern(pat)
            if len(results) == 1 and results[0] == ea:
                return pat
        for before, after in [(3, 2), (5, 3), (8, 5)]:
            pat = build_func_xref_pattern(ea, before, after)
            if not pat:
                continue
            results = scan_pattern(pat)
            if len(results) == 1:
                return pat
        return build_func_pattern(ea)
    else:
        for after in [4, 6, 10]:
            pat = build_data_xref_pattern(ea, after)
            if not pat:
                continue
            results = scan_pattern(pat)
            if len(results) == 1:
                return pat
        return build_data_xref_pattern(ea) or " ".join("%02X" % ida_bytes.get_byte(ea + i) for i in range(16))

REBASE_RE = re.compile(r'(\w+)\s*=\s*rebase\(\s*(0x[0-9A-Fa-f]+)\s*\)')

def parse_batch(text):
    return [(m.group(1), int(m.group(2), 16)) for m in REBASE_RE.finditer(text)]

class patternaction(idaapi.action_handler_t):
    ACTION_ID = "patternpromax:run"

    def activate(self, ctx):
        raw = idaapi.ask_text(0, "", "plez paste rebase() decl:")
        if not raw:
            return 1
        entries = parse_batch(raw)
        if not entries:
            idaapi.warning("cant find rebase decl")
            return 1
        base = idaapi.get_imagebase()
        lines = []
        for name, offset in entries:
            pat = make_pattern(base + offset)
            line = "%s: %s" % (name, pat)
            lines.append(line)
            print("(me pro)] " + line)
        try:
            out = Path.home() / "Downloads" / "makepatterns.log"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("\n".join(lines) + "\n")
            idaapi.info("Saved to:\n" + str(out))
        except Exception as e:
            print("me fail idk why " + str(e))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class wowsetuppro(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup, patternaction.ACTION_ID, "pattern maker promax")

class patternmakerpromax(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "top ten reasons why i hate jews"
    help = "i dont like helping"
    wanted_name = "pattern maker promax"
    wanted_hotkey = ""

    def init(self):
        idaapi.register_action(idaapi.action_desc_t(
            patternaction.ACTION_ID, "pattern maker promax", patternaction(), "", "", -1))
        self._hooks = wowsetuppro()
        self._hooks.hook()
        print("[%s] me load pro" % "pattern maker promax")
        return idaapi.PLUGIN_KEEP

    def run(self, arg): pass

    def term(self):
        self._hooks.unhook()
        idaapi.unregister_action(patternaction.ACTION_ID)

def PLUGIN_ENTRY():
    return patternmakerpromax()