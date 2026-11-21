"""KICSP 학술대회 양식(hwpx)에 논문 내용을 채운다.

1단계(이 스크립트): 양식의 문단·글자 모양 ID를 그대로 써서 section0.xml을 다시 만든다.
  - 본문 안의 $...$ 는 한글 수식 스크립트이며, 자리표시자 @@E{n}@@ 로 바꾸고 eqs.json에 기록한다.
  - 그림 자리는 @@FIG{n}@@ 로 남긴다.
2단계(finalize_hwp.ps1): 한글 자동화로 자리표시자를 수식 개체·그림으로 바꾸고 .hwp/.hwpx로 저장한다.

실행: python build_hwpx.py <양식.hwpx> <content.py> <출력.hwpx> <eqs.json>
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

EQS: list[dict] = []
EQ_SIZE = [900]   # 수식 기준 크기(HWPUNIT, 900 = 9pt). 표 안에서는 800.


def eqify(text: str) -> str:
    """'$script$'를 수식 자리표시자로 바꾼다."""
    def repl(m):
        EQS.append({"script": m.group(1).strip(), "size": EQ_SIZE[0]})
        return f"@@E{len(EQS)}@@"
    return re.sub(r"\$([^$]+)\$", repl, text)


def t(text: str) -> str:
    return escape(eqify(text))


def run(char: int, text: str | None) -> str:
    if text is None or text == "":
        return f'<hp:run charPrIDRef="{char}"/>'
    return f'<hp:run charPrIDRef="{char}"><hp:t>{t(text)}</hp:t></hp:run>'


def para(ppr: int, style: int, runs: list[str]) -> str:
    return (f'<hp:p id="2147483648" paraPrIDRef="{ppr}" styleIDRef="{style}" pageBreak="0" '
            f'columnBreak="0" merged="0">{"".join(runs)}</hp:p>')


def sup_runs(base: int, sup: int, text: str) -> list[str]:
    """'길보경^1, 박여경^1*' 처럼 ^ 뒤 숫자·*를 위첨자로."""
    out = []
    for part in re.split(r"(\^[0-9*]+)", text):
        if not part:
            continue
        out.append(run(sup, part[1:]) if part.startswith("^") else run(base, part))
    return out


# ---------------------------------------------------------------- 표
BF_BASE = None
BF_NEW: dict[tuple, int] = {}


def border_fill(left, right, top, bottom, fill) -> int:
    key = (left, right, top, bottom, fill)
    if key not in BF_NEW:
        BF_NEW[key] = 13 + len(BF_NEW)
    return BF_NEW[key]


def bf_xml(bid: int, key: tuple) -> str:
    left, right, top, bottom, fill = key

    def side(name, spec):
        typ, width = spec
        return f'<hh:{name}Border type="{typ}" width="{width}" color="#000000"/>'
    brush = (f'<hc:fillBrush><hc:winBrush faceColor="{fill}" hatchColor="#000000" alpha="0"/></hc:fillBrush>'
             if fill else "")
    return (f'<hh:borderFill id="{bid}" threeD="0" shadow="0" centerLine="NONE" breakCellSeparateLine="0">'
            '<hh:slash type="NONE" Crooked="0" isCounter="0"/><hh:backSlash type="NONE" Crooked="0" isCounter="0"/>'
            f'{side("left", left)}{side("right", right)}{side("top", top)}{side("bottom", bottom)}'
            '<hh:diagonal type="SOLID" width="0.1 mm" color="#000000"/>' + brush + '</hh:borderFill>')


THICK, THIN, NONE = ("SOLID", "0.4 mm"), ("SOLID", "0.12 mm"), ("NONE", "0.12 mm")


def table(rows: list[list[str]], widths: list[float], total: int = 23200, cell_char: int = 47,
          cell_para: int = 42, tid: int = 1611263700) -> str:
    """첫 행은 머리글(회색 바탕). 위·아래 굵은 선, 머리글 아래 가는 선, 세로 가는 선."""
    ws = [int(total * w / sum(widths)) for w in widths]
    nr, nc = len(rows), len(rows[0])
    trs = []
    for r, row in enumerate(rows):
        tcs = []
        for c, text in enumerate(row):
            head = r == 0
            bid = border_fill(NONE if c == 0 else THIN, NONE if c == nc - 1 else THIN,
                              THICK if head else NONE, THICK if r == nr - 1 else (THIN if head else NONE),
                              "#E5E5E5" if head else None)
            lines = text.split("\n")
            ps = "".join(para(cell_para, 11, [run(cell_char, ln)]) for ln in lines)
            tcs.append(
                f'<hp:tc name="" header="{1 if head else 0}" hasMargin="0" protect="0" editable="0" dirty="0" '
                f'borderFillIDRef="{bid}"><hp:subList id="" textDirection="HORIZONTAL" lineWrap="BREAK" '
                'vertAlign="CENTER" linkListIDRef="0" linkListNextIDRef="0" textWidth="0" textHeight="0" '
                f'hasTextRef="0" hasNumRef="0">{ps}</hp:subList><hp:cellAddr colAddr="{c}" rowAddr="{r}"/>'
                f'<hp:cellSpan colSpan="1" rowSpan="1"/><hp:cellSz width="{ws[c]}" height="900"/>'
                '<hp:cellMargin left="100" right="100" top="60" bottom="60"/></hp:tc>')
        trs.append("<hp:tr>" + "".join(tcs) + "</hp:tr>")
    tbl = (f'<hp:tbl id="{tid}" zOrder="3" numberingType="TABLE" textWrap="TOP_AND_BOTTOM" textFlow="BOTH_SIDES" '
           f'lock="0" dropcapstyle="None" pageBreak="CELL" repeatHeader="1" rowCnt="{nr}" colCnt="{nc}" '
           f'cellSpacing="0" borderFillIDRef="3" noAdjust="0"><hp:sz width="{sum(ws)}" widthRelTo="ABSOLUTE" '
           f'height="{900 * nr}" heightRelTo="ABSOLUTE" protect="0"/><hp:pos treatAsChar="1" affectLSpacing="0" '
           'flowWithText="1" allowOverlap="0" holdAnchorAndSO="0" vertRelTo="PARA" horzRelTo="PARA" vertAlign="TOP" '
           'horzAlign="LEFT" vertOffset="0" horzOffset="0"/><hp:outMargin left="0" right="0" top="0" bottom="0"/>'
           '<hp:inMargin left="100" right="100" top="60" bottom="60"/>' + "".join(trs) + "</hp:tbl>")
    return para(34, 10, [f'<hp:run charPrIDRef="41">{tbl}</hp:run>'])


# ---------------------------------------------------------------- 본문 블록
CAP_PARA = 46   # 새로 추가: 34(가운데 정렬) + 다음 문단과 함께(표·그림과 떨어지지 않게)
REF_CHAR = 85   # 새로 추가: Times New Roman 9pt, 장평 90, 자간 -6
ACK_CHAR = 86   # 새로 추가: 휴먼명조 10pt


def body_block(kind: str, *args) -> str:
    if kind == "h1":
        num, title = args
        return para(31, 0, [run(76, None)]) + para(3, 29, [run(49, num), run(52, ". " + title)])
    if kind == "h2":
        return para(40, 8, [run(53, args[0])])
    if kind == "p":
        return para(0, 0, [run(71, "  " + args[0])])
    if kind == "eq":           # 가운데 정렬 식 + 번호
        script, no = args
        return para(34, 10, [run(71, f"${script}$  ({no})")])
    if kind == "fig":
        return para(34, 10, [run(71, f"@@FIG{args[0]}@@")])
    if kind == "figcap":
        return para(34, 10, [run(56, args[0])])
    if kind == "tabcap":
        return para(CAP_PARA, 10, [run(56, args[0])])
    if kind == "table":
        rows, widths = args
        EQ_SIZE[0] = 800
        try:
            return table(rows, widths)
        finally:
            EQ_SIZE[0] = 900
    if kind == "ack_title":
        return para(31, 0, [run(76, None)]) + para(4, 7, [run(53, "ACKNOWLEDGMENTS")])
    if kind == "ack":
        return para(0, 0, [run(ACK_CHAR, args[0])])
    if kind == "ref_title":
        return para(4, 7, [run(53, "REFERENCES")])
    if kind == "ref":
        return para(43, 0, [run(REF_CHAR, args[0])])   # 43: 내어쓰기
    raise ValueError(kind)


def add_char_shapes(header: str) -> str:
    base = re.search(r'<hh:charPr id="71".*?</hh:charPr>', header, re.S).group(0)
    ref = (base.replace('id="71"', f'id="{REF_CHAR}"')
               .replace('latin="4"', 'latin="7"', 1)
               .replace('<hh:ratio hangul="96" latin="96" hanja="96" japanese="96" other="96" symbol="96" user="96"/>',
                        '<hh:ratio hangul="90" latin="90" hanja="90" japanese="90" other="90" symbol="90" user="90"/>')
               .replace('<hh:spacing hangul="-8" latin="-8" hanja="-8" japanese="-8" other="-8" symbol="-8" user="-8"/>',
                        '<hh:spacing hangul="-6" latin="-6" hanja="-6" japanese="-6" other="-6" symbol="-6" user="-6"/>'))
    ack = base.replace('id="71"', f'id="{ACK_CHAR}"').replace('height="900"', 'height="1000"', 1)
    header = header.replace("</hh:charProperties>", ref + ack + "</hh:charProperties>")
    n = len(re.findall(r"<hh:charPr ", header))
    header = re.sub(r'<hh:charProperties itemCnt="\d+"', f'<hh:charProperties itemCnt="{n}"', header)
    p34 = re.search(r'<hh:paraPr id="34".*?</hh:paraPr>', header, re.S).group(0)
    cap = p34.replace('id="34"', f'id="{CAP_PARA}"', 1).replace('keepWithNext="0"', 'keepWithNext="1"')
    header = header.replace("</hh:paraProperties>", cap + "</hh:paraProperties>")
    n = len(re.findall(r"<hh:paraPr ", header))
    header = re.sub(r'<hh:paraProperties itemCnt="\d+"', f'<hh:paraProperties itemCnt="{n}"', header)
    bfs = "".join(bf_xml(i, k) for k, i in sorted(BF_NEW.items(), key=lambda kv: kv[1]))
    header = header.replace("</hh:borderFills>", bfs + "</hh:borderFills>")
    n = len(re.findall(r"<hh:borderFill ", header))
    return re.sub(r'<hh:borderFills itemCnt="\d+"', f'<hh:borderFills itemCnt="{n}"', header)


def drop_para(s: str, text: str) -> str:
    """text가 든 가장 안쪽 문단을 통째로 지운다(양식의 안내 문구)."""
    i = s.index(text)
    a = s.rindex("<hp:p ", 0, i)
    b = s.index("</hp:p>", i) + len("</hp:p>")
    return s[:a] + s[b:]


def replace_once(s: str, old: str, new: str) -> str:
    if s.count(old) != 1:
        raise ValueError(f"양식에서 {old[:60]!r}가 {s.count(old)}번 나옴")
    return s.replace(old, new)


def build(template: Path, content, out: Path, eqs_path: Path) -> None:
    work = Path(tempfile.mkdtemp())
    with zipfile.ZipFile(template) as z:
        z.extractall(work)
    sec = (work / "Contents/section0.xml").read_text(encoding="utf-8")
    sec = re.sub(r"<hp:linesegarray>.*?</hp:linesegarray>", "", sec)   # 한글이 열 때 다시 계산
    C = content

    # --- 머리 표: 제목·저자·영문 제목·Abstract·Key Words
    sec = replace_once(sec, '<hp:run charPrIDRef="62"><hp:t>한국 융합신호처리학술대회 논문지 제목 두줄</hp:t></hp:run>',
                       run(62, C.TITLE_KO))
    for note in ("* 전체 2페이지 이내로 작성 요망", "(글자모양 : 휴먼고딕, 크기:14", "(글자모양 : 돋움, 크기:10",
                 "(서체:영문 Arial, 크기: 14pt", "(서체:돋움, 크기: 10pt, 가운데정렬)", "(서체: Times New Roman, 크기: 8pt"):
        sec = drop_para(sec, note)
    sec = drop_para(sec, '<hp:run charPrIDRef="84"/>')   # 제목 아래 빈 줄(양식 안내문 자리)
    sec = replace_once(sec, '<hp:run charPrIDRef="81"><hp:t>홍길동1, 홍길서2*</hp:t></hp:run>',
                       "".join(sup_runs(81, 64, C.AUTHORS_KO)))
    sec = replace_once(sec, '<hp:run charPrIDRef="81"><hp:t>1한국대학교 정보통신학부, 2문화대학교 나노공학부</hp:t></hp:run>',
                       "".join(sup_runs(81, 64, C.AFFIL_KO)))
    sec = replace_once(sec, '<hp:t>The Korea Institute of Convergence Signal Processing</hp:t>', f"<hp:t>{t(C.TITLE_EN)}</hp:t>")
    en_auth = re.search(r'<hp:run charPrIDRef="63"><hp:t>Kil-Dong Hong</hp:t></hp:run>.*?<hp:run charPrIDRef="65"><hp:t>\*</hp:t></hp:run>', sec, re.S).group(0)
    sec = replace_once(sec, en_auth, "".join(sup_runs(79, 64, C.AUTHORS_EN)))
    aff1 = '<hp:run charPrIDRef="64"><hp:t>1</hp:t></hp:run><hp:run charPrIDRef="80"><hp:t>Division of Information Communication, Hankook University</hp:t></hp:run>'
    sec = replace_once(sec, aff1, "".join(sup_runs(80, 64, C.AFFIL_EN)))
    aff2 = re.search(r'<hp:p [^>]*><hp:run charPrIDRef="64"><hp:t>2</hp:t></hp:run><hp:run charPrIDRef="80"><hp:t>Division of Nano-technology, Moonhwa University</hp:t></hp:run></hp:p>', sec).group(0)
    sec = replace_once(sec, aff2, "")
    abs_old = re.search(r'<hp:run charPrIDRef="83"><hp:t>With the explosively.*?</hp:t></hp:run>', sec, re.S).group(0)
    sec = replace_once(sec, abs_old, run(83, C.ABSTRACT))
    kw_old = re.search(r'<hp:run charPrIDRef="78"><hp:t charStyleIDRef="24">Convergence</hp:t></hp:run>.*?<hp:run charPrIDRef="30"><hp:t charStyleIDRef="24">혼합정렬\)</hp:t></hp:run>', sec, re.S).group(0)
    sec = replace_once(sec, kw_old, f'<hp:run charPrIDRef="78"><hp:t charStyleIDRef="24">{t(C.KEYWORDS)}</hp:t></hp:run>')

    # --- 본문: 머리 표 뒤 'Ⅰ. 서론' 문단부터 마지막 빈 문단 앞까지 교체
    start = sec.index("</hp:tbl></hp:run>", sec.index("Abstract")) + len("</hp:tbl></hp:run>")
    end = sec.rindex('<hp:p id="0" paraPrIDRef="26"')
    first_num, first_title = C.BODY[0][1], C.BODY[0][2]
    body = run(49, first_num) + run(52, ". " + first_title) + "</hp:p>"
    body += "".join(body_block(b[0], *b[1:]) for b in C.BODY[1:])
    sec = sec[:start] + body + sec[end:]

    (work / "Contents/section0.xml").write_text(sec, encoding="utf-8")
    hdr = (work / "Contents/header.xml").read_text(encoding="utf-8")
    (work / "Contents/header.xml").write_text(add_char_shapes(hdr), encoding="utf-8")

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w") as z:
        z.write(work / "mimetype", "mimetype", compress_type=zipfile.ZIP_STORED)
        for f in sorted(work.rglob("*")):
            rel = f.relative_to(work).as_posix()
            if f.is_file() and rel != "mimetype":
                z.write(f, rel, compress_type=zipfile.ZIP_DEFLATED)
    shutil.rmtree(work, ignore_errors=True)
    eqs_path.write_text(json.dumps(EQS, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{out} 생성, 수식 {len(EQS)}개")


if __name__ == "__main__":
    spec = importlib.util.spec_from_file_location("content", sys.argv[2])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    build(Path(sys.argv[1]), mod, Path(sys.argv[3]), Path(sys.argv[4]))
