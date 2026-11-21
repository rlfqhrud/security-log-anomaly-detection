"""논문 Fig. 1 (시스템 구성도, 영문) 생성."""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

plt.rcParams["font.family"] = "Arial"
fig, ax = plt.subplots(figsize=(3.35, 1.55), dpi=400)
ax.set_xlim(-2, 103); ax.set_ylim(0, 46); ax.axis("off")

def box(x, y, w, h, title, sub, fc):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.5", fc=fc, ec="#333", lw=0.6))
    ax.text(x + w / 2, y + h * 0.64, title, ha="center", va="center", fontsize=4.6, weight="bold")
    ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center", fontsize=4.3, color="#333")

def arrow(x1, y1, x2, y2, label=None, dy=1.6):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=0.6, color="#333", mutation_scale=5))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, ha="center", va="bottom", fontsize=4.2, color="#555")

W, H = 26, 13
top, bot = 29, 4
box(0, top, W, H, "(1) Preprocessing", "CICIDS2017 flows", "#eef3fb")
box(37, top, W, H, "(2) Detection", "ML classifier per flow", "#eef3fb")
box(74, top, W, H, "(3) Alert & Risk", "R = T × I × A", "#fdf1e6")
box(74, bot, W, H, "(4) LLM Summary", "GPT, rationale input", "#eaf6ee")
box(37, bot, W, H, "(5) Alert Bot", "Discord / report / log", "#eaf6ee")
box(0, bot, W, H, "SOC Analyst", "prioritized alerts", "#f4f4f4")
arrow(27, top + H / 2, 36, top + H / 2, "flows")
arrow(64, top + H / 2, 73, top + H / 2, "labels")
arrow(87, top - 0.8, 87, bot + H + 0.8)
ax.text(88.6, (top + bot + H) / 2, "Critical / Alert", fontsize=4.2, color="#555", va="center")
arrow(73, bot + H / 2, 64, bot + H / 2, "text")
arrow(36, bot + H / 2, 27, bot + H / 2, "notify")
fig.savefig(sys.argv[1], bbox_inches="tight", pad_inches=0.02)
