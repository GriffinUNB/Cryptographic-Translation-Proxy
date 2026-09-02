import os, shutil, glob
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

dir_path = os.path.dirname(os.path.abspath(__file__))
results_dir = os.path.join(dir_path, "results")
timing_dir = os.path.join(dir_path, "timing_data")
out_dir = os.path.join(dir_path, "..", "figures")
tables_dir = os.path.join(dir_path, "..", "tables")
os.makedirs(out_dir, exist_ok=True)
os.makedirs(tables_dir, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8.5,
    "legend.fontsize": 6.5,
    "xtick.labelsize": 7,
    "ytick.labelsize": 6.5,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.pad_inches": 0.02,
    "hatch.linewidth": 0.4,
})

colors = {
    "black": "#000000",
    "blue": "#0072B2",       # Classical crypto / Go stdlib
    "vermilion": "#D55E00",  # PQC crypto / CIRCL / HSM signing
    "green": "#009E73",      # Software Core keygen
    "purple": "#CC79A7",     # HSM Core keygen
    "red": "#C00000",        # Go runtime startup
    "cyan": "#00A6D6",       # Other signer load
    "profile": "#E69F00",    # Profile loading
    "module": "#56B4E9",     # PKCS#11 module / slot enumeration
    "session": "#009E73",    # Session search / C_OpenSession
    "extract": "#9467BD",    # Key/public-key extraction
    "internal": "#8C564B",   # Internal overhead
    "pqc_processing": "#F0E442",  # PQC/Catalyst processing
    "verify_overhead": "#6A3D9A", # Verify overhead
    "framework": "#17BECF",  # Certificate framework + PEM
    "total": "#BDBDBD",      # Total-only fallback bar
}

issue_hatches = ["\\\\", "xx", "--", "oo", "||", "..."]

LEVELS = ["l1", "l3", "l5"]
LEVEL_LABELS = ["Low Security\nP-256 & ML-44", "Medium Security\nP-384 & ML-65", "High Security\nP-521 & ML-87"]
PANEL_LABELS = ["(a)", "(b)", "(c)"]
DISPLAY_NAMES = {"l1": "Low Security", "l3": "Medium Security", "l5": "High Security"}
ALGO_FULL = {"ecdsa-p256": "ECDSA P-256", "ecdsa-p384": "ECDSA P-384", "ecdsa-p521": "ECDSA P-521",
             "ml-dsa-44": "ML-DSA-44", "ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87"}

def load_vals_stats(prefix, tag):
    f = os.path.join(timing_dir, f"{prefix}_{tag}_ms.txt")
    if not os.path.isfile(f):
        batch_files = sorted(glob.glob(os.path.join(timing_dir, f"{prefix}_batch*_{tag}_ms.txt")))
        if not batch_files:
            return 0.0, 0.0
        arr = np.concatenate([np.loadtxt(bf) for bf in batch_files])
    else:
        arr = np.loadtxt(f)
    arr = np.atleast_1d(arr)
    arr = arr[arr > 0]
    if len(arr) == 0:
        return 0.0, 0.0
    return float(np.mean(arr)), float(np.std(arr))

def load_vals_raw(prefix, tag):
    """Load raw timing array (for per-sample difference computations)."""
    f = os.path.join(timing_dir, f"{prefix}_{tag}_ms.txt")
    if not os.path.isfile(f):
        batch_files = sorted(glob.glob(os.path.join(timing_dir, f"{prefix}_batch*_{tag}_ms.txt")))
        if not batch_files:
            return np.array([])
        arr = np.concatenate([np.loadtxt(bf) for bf in batch_files])
    else:
        arr = np.loadtxt(f)
    arr = np.atleast_1d(arr)
    arr = arr[arr > 0]
    return arr

def fmt_ms(mean_val, std_val, dec=2):
    if abs(mean_val) < 0.0005:
        return "$-$"
    if std_val > 0.001:
        return f"${mean_val:.{dec}f} \\pm {std_val:.{dec}f}$"
    return f"${mean_val:.{dec}f}$"

def load_exclusive_stats(prefix, outer_tag, subtract_tags):
    """Compute a nested-timer residual per invocation before averaging."""
    outer = load_vals_raw(prefix, outer_tag)
    if len(outer) == 0:
        return 0.0, 0.0
    residual = outer.copy()
    for tag in subtract_tags:
        part = load_vals_raw(prefix, tag)
        if len(part) == 0:
            continue
        if len(part) != len(residual):
            return 0.0, 0.0
        residual -= part
    residual = np.maximum(residual, 0.0)
    return float(np.mean(residual)), float(np.std(residual))

def gen_issue_figure():
    fig, axes = plt.subplots(1, 3, figsize=(7.65, 3.3), sharey=False)
    i_keys = ["classical_ca", "pqc_ca", "classicalhp", "pqchp"]
    i_labels = ["C-CA", "P-CA", "C-CTP", "P-CTP"]

    latex_rows = []

    for li, level in enumerate(LEVELS):
        ax = axes[li]
        x = np.arange(len(i_keys))
        w = 0.55

        hsm_m, prof_m, sign_m, int_ovh, go_m = [], [], [], [], []
        hsm_s, prof_s, go_s = [], [], []
        hsm_sign_m, hsm_sign_s = [], []  # HSM signing time (from hsm_sign timer)
        cat_oh_m = []  # Catalyst overhead (hybrid only)
        p11_mod_seg, p11_sk_seg, p11_ext_seg = [], [], []
        macro_stds = []
        pqc_sw = [0, 0, 0, 0]
        pqc_sw_s = [0, 0, 0, 0]
        c_login_m = [0]*4
        other_signer_m = [0]*4  # amortized C Login + remaining

        for ei, key in enumerate(i_keys):
            ms, ms_std = load_vals_stats(f"{level}_issue_{key}", "main_start")
            it, it_std = load_vals_stats(f"{level}_issue_{key}", "issue_total")
            prof, p_std = load_vals_stats(f"{level}_issue_{key}", "issue_load_profile")

            is_hybrid = "hp" in key
            sign_tag = "load_hybrid_signer" if is_hybrid else "load_signer"
            sign, s_std = load_vals_stats(f"{level}_issue_{key}", sign_tag)

            # Amortize C_Login: session pool keeps sessions warm across most issuances.
            # Raw c_login fires N_login times out of N_total issuances (N_login < N_total).
            # Amortized per-issuance cost = mean(c_login) × N_login / N_total.
            n_total = 1000
            c_login_raw, _ = load_vals_stats(f"{level}_issue_{key}", "c_login")
            c_login_count = 0
            f_login = os.path.join(timing_dir, f"{level}_issue_{key}_c_login_ms.txt")
            if os.path.isfile(f_login):
                c_login_count = len(np.loadtxt(f_login))
            c_login_amortized = c_login_raw * c_login_count / n_total if c_login_raw > 0 else 0.0

            # HSM signing time (Go timer wraps C_SignInit + C_Sign + Go overhead)
            # For hybrid: sign_catalyst = total Catalyst signing (3× C_Sign), hsm_sign = per-call
            # Always use hsm_sign for consistent per-call comparison across entity types
            hsm, h_std = load_vals_stats(f"{level}_issue_{key}", "hsm_sign")
            if hsm == 0:
                hsm, h_std = load_vals_stats(f"{level}_issue_{key}", "sign_catalyst")
            # Catalyst overhead for hybrid entities (sign_catalyst minus 3× per-call hsm_sign)
            cat_overhead = 0
            if is_hybrid:
                cat_total, _ = load_vals_stats(f"{level}_issue_{key}", "sign_catalyst")
                if cat_total > 0 and hsm > 0:
                    cat_overhead = max(0, cat_total - hsm * 3)  # sign_catalyst includes 3× hsm_sign

            p11_mod, _   = load_vals_stats(f"{level}_issue_{key}", "pkcs11_find_slot")
            p11_pool, _  = load_vals_stats(f"{level}_issue_{key}", "pkcs11_session_pool")
            p11_fk, _    = load_vals_stats(f"{level}_issue_{key}", "pkcs11_find_key")
            p11_ext, _   = load_vals_stats(f"{level}_issue_{key}", "pkcs11_extract_pub")
            if is_hybrid:
                ec, _ = load_vals_stats(f"{level}_issue_{key}", "pkcs11_extract_pub_classical")
                ep, _ = load_vals_stats(f"{level}_issue_{key}", "pkcs11_extract_pub_pqc")
                fc, _ = load_vals_stats(f"{level}_issue_{key}", "pkcs11_find_key_classical")
                fp, _ = load_vals_stats(f"{level}_issue_{key}", "pkcs11_find_key_pqc")
                if ec > 0: p11_ext = ec + ep
                if fc > 0: p11_fk = fc + fp

            total = it if it > 0 else (ms if ms > 0 else 0)
            go_start, go_start_std = load_exclusive_stats(
                f"{level}_issue_{key}", "main_start", ["issue_total"])

            p11_mod_v = p11_mod
            p11_sk_v = p11_pool + p11_fk
            p11_ext_v = p11_ext
            sign_remaining = max(0, sign - p11_mod_v - p11_sk_v - p11_ext_v)

            c_login_seg = c_login_amortized
            other_signer = max(0, sign_remaining - c_login_seg)
            c_login_m[ei] = c_login_seg
            other_signer_m[ei] = other_signer

            prof_m.append(prof)
            prof_s.append(p_std)
            sign_m.append(sign_remaining)
            hsm_m.append(sign_remaining)
            hsm_s.append(s_std)
            hsm_sign_m.append(hsm)
            hsm_sign_s.append(h_std)
            cat_oh_m.append(cat_overhead)
            p11_mod_seg.append(p11_mod_v)
            p11_sk_seg.append(p11_sk_v)
            p11_ext_seg.append(p11_ext_v)
            go_m.append(go_start)
            go_s.append(go_start_std)

            pqc_raw = 0
            if "pqc" in key.lower() and "ca" in key:
                pqc_t, pqc_ts = load_vals_stats(f"{level}_issue_{key}", "sign_and_marshal")
                pqc_s_val, _ = load_vals_stats(f"{level}_issue_{key}", "sign_tbs")
                if pqc_t > 0:
                    pqc_raw = pqc_t + pqc_s_val
                    pqc_sw[ei] = pqc_raw
                    pqc_sw_s[ei] = pqc_ts
            elif "hp" in key:
                cat_s, cat_std = load_vals_stats(f"{level}_issue_{key}", "save_catalyst")
                if cat_s > 0:
                    pqc_raw = cat_s
                    pqc_sw[ei] = cat_s
                    pqc_sw_s[ei] = cat_std

            comps = c_login_m[ei] + other_signer_m[ei] + cat_oh_m[ei] + prof + p11_mod_v + p11_sk_v + p11_ext_v + go_start + pqc_raw + hsm_sign_m[ei]
            intrnl = max(0, total - comps)
            if intrnl == 0 and comps > total:
                excess = comps - total
                other_signer_m[ei] = max(0, other_signer_m[ei] - excess)
            int_ovh.append(intrnl)
            macro_stds.append(ms_std)

        ax.bar(x, c_login_m, w, label="C Login (amortized)", color=colors["vermilion"], edgecolor="black", lw=0.6, hatch="//")
        b = list(c_login_m)
        sub_series = [
            (other_signer_m, "Other signer load", colors["cyan"], ".."),
            (prof_m, "Profile loading", colors["profile"], issue_hatches[0]),
            (p11_mod_seg, "PKCS#11 module", colors["module"], issue_hatches[1]),
            (p11_sk_seg, "Session search", colors["session"], issue_hatches[2]),
            (p11_ext_seg, "Key extract", colors["extract"], issue_hatches[3]),
            (int_ovh, "Internal overhead", colors["internal"], issue_hatches[4]),
            (go_m, "Go startup", colors["red"], issue_hatches[5]),
        ]
        for s_vals, label_str, g_color, g_hatch in sub_series:
            ax.bar(x, s_vals, w, bottom=b, label=label_str, color=g_color, edgecolor="black", lw=0.6, hatch=g_hatch)
            b = [b_val + s_val for b_val, s_val in zip(b, s_vals)]
        ax.bar(x, pqc_sw, w, bottom=b, label="PQC/Catalyst processing", color=colors["pqc_processing"], edgecolor="black", lw=0.6, hatch="..")
        b = [b_val + p for b_val, p in zip(b, pqc_sw)]
        ax.bar(x, hsm_sign_m, w, bottom=b, label="HSM Signing", color=colors["blue"], edgecolor="black", lw=0.6)
        b = [b_val + s for b_val, s in zip(b, hsm_sign_m)]
        ax.bar(x, cat_oh_m, w, bottom=b, label="Catalyst overhead", color=colors["purple"], edgecolor="black", lw=0.6, hatch="xx")
        b = [b_val + c for b_val, c in zip(b, cat_oh_m)]
        bar_totals = b

        for i in range(4):
            if bar_totals[i] > 0:
                ax.annotate(f"{bar_totals[i]:.1f} ms", (i, bar_totals[i]),
                            textcoords="offset points", xytext=(0, 3),
                            ha="center", fontsize=6.5, fontweight="bold")
                lbl = i_labels[i]
                
                hsm_str  = fmt_ms(c_login_m[i], hsm_s[i])
                os_str   = fmt_ms(other_signer_m[i], 0.0)
                hsm_sign_str = fmt_ms(hsm_sign_m[i], hsm_sign_s[i])
                cat_oh_str = fmt_ms(cat_oh_m[i], 0.0)
                pqc_str  = fmt_ms(pqc_sw[i], pqc_sw_s[i])
                prof_str = fmt_ms(prof_m[i], prof_s[i])
                mod_str  = fmt_ms(p11_mod_seg[i], 0.0)
                sk_str   = fmt_ms(p11_sk_seg[i], 0.0)
                ext_str  = fmt_ms(p11_ext_seg[i], 0.0)
                ovh_str  = fmt_ms(int_ovh[i], 0.0)
                go_str   = fmt_ms(go_m[i], go_s[i])
                tot_str  = f"\\textbf{{{fmt_ms(bar_totals[i], macro_stds[i])}}}"
                
                latex_rows.append(f"  {DISPLAY_NAMES[level]} & {lbl} & {hsm_str} & {os_str} & {hsm_sign_str} & {cat_oh_str} & {pqc_str} & {prof_str} & {mod_str} & {sk_str} & {ext_str} & {ovh_str} & {go_str} & {tot_str} \\\\")

        ax.set_xticks(x)
        ax.set_xticklabels(i_labels, fontsize=7, rotation=25, ha="right")
        ax.set_xlabel(f"{PANEL_LABELS[li]} {LEVEL_LABELS[li]}", fontsize=8, fontweight="bold", labelpad=2)
        ax.set_ylabel("Latency (ms)", fontsize=7.5)
        ax.yaxis.grid(True, linestyle="--", alpha=0.4, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(0, 120)
        ax.set_yticks(np.arange(0, 121, 20))
        ax.tick_params(axis='y', labelsize=6.5, labelleft=True)

    tex_content = (
        "\\begin{table*}[htbp]\n"
        "  \\centering\n"
        "  \\caption{\\textcolor{red}{Certificate issuance micro-timing breakdown (mean $\\pm$ SD, ms).}}\n"
        "  \\label{tab:issue-latency}\n"
        "  \\scriptsize\\setlength{\\tabcolsep}{1.5pt}\n"
        "  \\begin{tabular}{llrrrrrrrrrrrr}\n"
        "    \\toprule\n"
        "    \\textbf{Level} & \\textbf{Cert} & \\textbf{C Login} & \\textbf{Other Sign} & \\textbf{HSM Sign} & \\textbf{Cat OH} & \\textbf{PQC Tmplt} & \\textbf{Prof Load} & \\textbf{P11 Mod} & \\textbf{Sess Srch} & \\textbf{Key Extr} & \\textbf{Int Ovhd} & \\textbf{Go Start} & \\textbf{Total ($\\mu \\pm \\sigma$)} \\\\\n"
        "    \\midrule\n"
        + "\n".join(latex_rows) + "\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table*}\n"
    )
    tex_content = tex_content.replace("PQC Tmplt", "Hyb Proc")
    with open(os.path.join(tables_dir, "tab-issue-latency.tex"), "w") as fh:
        fh.write(tex_content)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=6.8, ncol=6, loc="lower center", bbox_to_anchor=(0.5, 0.005),
               frameon=True, edgecolor="black", columnspacing=1.0, handlelength=2.0, handleheight=1.2, borderpad=0.5)
    plt.subplots_adjust(wspace=0.28, bottom=0.32, left=0.08, right=0.99)
    fig.savefig(os.path.join(out_dir, "fig-issue-latency.pdf"), format="pdf")
    fig.savefig(os.path.join(out_dir, "fig-issue-latency.png"), format="png", dpi=300)
    plt.close()

def gen_verify_figure():
    fig, axes = plt.subplots(1, 3, figsize=(7.65, 3.3), sharey=False)
    v_keys = ["verify_classical", "verify_pqc", "verify_classicalhp", "verify_pqchp"]
    v_labels = ["C-CA", "P-CA", "C-CTP", "P-CTP"]

    latex_rows = []

    for li, level in enumerate(LEVELS):
        ax = axes[li]
        x = np.arange(len(v_keys))
        w = 0.55
        stdlib_m, stdlib_s = [], []
        circl_m, circl_s   = [], []
        ovh_m, go_m, go_s  = [], [], []
        macro_stds = []

        for ei, pk in enumerate(v_keys):
            _, ms_std           = load_vals_stats(f"{level}_{pk}", "main_start")
            stdlib, stdlib_std = load_vals_stats(f"{level}_{pk}", "verify_stdlib")
            circl, circl_std   = load_vals_stats(f"{level}_{pk}", "verify_circl")

            go_start, go_start_std = load_exclusive_stats(
                f"{level}_{pk}", "main_start", ["verify_total"])
            stdlib_m.append(stdlib)
            stdlib_s.append(stdlib_std)
            circl_m.append(circl)
            circl_s.append(circl_std)
            go_m.append(go_start)
            go_s.append(go_start_std)
            ovh, _ = load_exclusive_stats(
                f"{level}_{pk}", "verify_total", ["verify_stdlib", "verify_circl"])
            ovh_m.append(ovh)
            macro_stds.append(ms_std)

        ax.bar(x, stdlib_m, w, label="Go stdlib", color=colors["blue"], edgecolor="black", lw=0.6, hatch="//")
        ax.bar(x, circl_m, w, bottom=stdlib_m, label="CIRCL", color=colors["vermilion"], edgecolor="black", lw=0.6, hatch="\\\\")
        b_c = [s + c for s, c in zip(stdlib_m, circl_m)]
        ax.bar(x, ovh_m, w, bottom=b_c, label="Overhead", color=colors["verify_overhead"], edgecolor="black", lw=0.6, hatch="xx")
        b_o = [b + o for b, o in zip(b_c, ovh_m)]
        ax.bar(x, go_m, w, bottom=b_o, label="Go startup", color=colors["red"], edgecolor="black", lw=0.6, hatch="oo")

        bar_totals = [s + c + o + g for s, c, o, g in zip(stdlib_m, circl_m, ovh_m, go_m)]
        for i in range(4):
            if bar_totals[i] > 0:
                ax.annotate(f"{bar_totals[i]:.1f} ms", (i, bar_totals[i]),
                            textcoords="offset points", xytext=(0, 3),
                            ha="center", fontsize=6.5, fontweight="bold")
                lbl = v_labels[i]
                
                std_str = fmt_ms(stdlib_m[i], stdlib_s[i], dec=3)
                cir_str = fmt_ms(circl_m[i], circl_s[i], dec=3)
                ovh_str = fmt_ms(ovh_m[i], 0.0, dec=3)
                go_str  = fmt_ms(go_m[i], go_s[i], dec=3)
                tot_str = f"\\textbf{{{fmt_ms(bar_totals[i], macro_stds[i], dec=3)}}}"
                
                latex_rows.append(f"  {DISPLAY_NAMES[level]} & {lbl} & {std_str} & {cir_str} & {ovh_str} & {go_str} & {tot_str} \\\\")

        ax.set_xticks(x)
        ax.set_xticklabels(v_labels, fontsize=6.5, rotation=25, ha="right")
        ax.set_xlabel(f"{PANEL_LABELS[li]} {LEVEL_LABELS[li]}", fontsize=8, fontweight="bold", labelpad=2)
        ax.set_ylabel("Latency (ms)", fontsize=7.5)
        ax.yaxis.grid(True, linestyle="--", alpha=0.4, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(0, 12)
        ax.set_yticks(np.arange(0, 13, 2))
        ax.tick_params(axis='y', labelsize=6.5, labelleft=True)

    tex_content = (
        "\\begin{table*}[htbp]\n"
        "  \\centering\n"
        "  \\caption{\\textcolor{red}{Certificate verification micro-timing breakdown (mean $\\pm$ SD, ms).}}\n"
        "  \\label{tab:verify-latency}\n"
        "  \\begin{tabular}{llrrrrr}\n"
        "    \\toprule\n"
        "    \\textbf{Level} & \\textbf{Cert} & \\textbf{Go Stdlib} & \\textbf{CIRCL} & \\textbf{Overhead} & \\textbf{Go Startup} & \\textbf{Total ($\\mu \\pm \\sigma$)} \\\\\n"
        "    \\midrule\n"
        + "\n".join(latex_rows) + "\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table*}\n"
    )
    with open(os.path.join(tables_dir, "tab-verify-latency.tex"), "w") as fh:
        fh.write(tex_content)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=8, ncol=4, loc="lower center", bbox_to_anchor=(0.5, 0.005),
               frameon=True, edgecolor="black", columnspacing=0.8, handlelength=1.2, borderpad=0.5)
    plt.subplots_adjust(wspace=0.28, bottom=0.30, left=0.08, right=0.99)
    fig.savefig(os.path.join(out_dir, "fig-verify-latency.pdf"), format="pdf")
    fig.savefig(os.path.join(out_dir, "fig-verify-latency.png"), format="png", dpi=300)
    plt.close()

def gen_cert_size_figure():
    fig, axes = plt.subplots(1, 3, figsize=(7.65, 3.3), sharey=False)
    s_labels = ["C-CA", "P-CA", "C-CTP Root", "P-CTP Root",
                "C-CTP Cross", "P-CTP Cross",
                "C-CA Client", "P-CA Client", "C-CTP Client", "P-CTP Client"]
    
    def read_size(prefix, n, tag=None):
        suffix = f"_{tag}" if tag else ""
        fp = os.path.join(results_dir, f"{prefix}_size-{n}{suffix}.txt")
        if not os.path.isfile(fp):
            fp = os.path.join(results_dir, f"size-{n}{suffix}.txt")
        if not os.path.isfile(fp):
            return 0
        try:
            return int(open(fp).read().strip())
        except ValueError:
            return 0

    names = ["classical-ca", "pqc-ca", "classical-hp-root", "pqc-hp-root",
             "classical-hp-cross", "pqc-hp-cross",
             "classical-client", "pqc-client", "classical-hp-client", "pqc-hp-client"]

    latex_rows = []

    for idx, level in enumerate(LEVELS):
        ax = axes[idx]
        s_vals = [read_size(level, n) for n in names]
        cc = [read_size(level, n, "classical") for n in names]
        pc = [read_size(level, n, "pqc") for n in names]
        framework = [s - c - p for s, c, p in zip(s_vals, cc, pc)]

        x = np.arange(len(s_labels))
        w = 0.55
        ax.bar(x, cc, w, label="Classical crypto", color=colors["blue"], edgecolor="black", lw=0.6, hatch="//")
        ax.bar(x, pc, w, bottom=list(cc), label="PQC crypto", color=colors["vermilion"], edgecolor="black", lw=0.6, hatch="\\\\")
        bottom = [c + p for c, p in zip(cc, pc)]
        ax.bar(x, framework, w, bottom=bottom, label="Framework + PEM", color=colors["framework"], edgecolor="black", lw=0.6, hatch="..")

        for i, v in enumerate(s_vals):
            if v > 0:
                ax.annotate(f"{v:,} B", (i, v), textcoords="offset points",
                            xytext=(0, 3), ha="center", va="bottom", rotation=90,
                            fontsize=5.5, fontweight="bold")
                def fmt_b(v):
                    return f"{v:,} B" if v > 0 else "$-$"
                latex_rows.append(f"  {DISPLAY_NAMES[level]} & {s_labels[i]} & {fmt_b(cc[i])} & {fmt_b(pc[i])} & {fmt_b(framework[i])} & \\textbf{{{fmt_b(s_vals[i])}}} \\\\")

        ax.set_xticks(x)
        ax.set_xticklabels(s_labels, fontsize=6, rotation=25, ha="right")
        ax.set_xlabel(f"{PANEL_LABELS[idx]} {LEVEL_LABELS[idx]}", fontsize=8, fontweight="bold", labelpad=2)
        ax.set_ylabel("Size (bytes)", fontsize=7.5)
        ax.yaxis.grid(True, linestyle="--", alpha=0.4, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(0, 15000)
        ax.set_yticks(np.arange(0, 15001, 2500))
        ax.tick_params(axis='y', labelsize=6.5, labelleft=True)

    tex_content = (
        "\\begin{table*}[htbp]\n"
        "  \\centering\n"
        "  \\caption{\\textcolor{red}{Certificate-size breakdown (bytes).}}\n"
        "  \\label{tab:cert-sizes}\n"
        "  \\begin{tabular}{llrrrr}\n"
        "    \\toprule\n"
        "    \\textbf{Level} & \\textbf{Cert Tag} & \\textbf{Classical} & \\textbf{PQC Crypto} & \\textbf{Framework/PEM} & \\textbf{Total Size} \\\\\n"
        "    \\midrule\n"
        + "\n".join(latex_rows) + "\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table*}\n"
    )
    with open(os.path.join(tables_dir, "tab-cert-sizes.tex"), "w") as fh:
        fh.write(tex_content)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles, labels,
        loc="lower center", bbox_to_anchor=(0.5, 0.005),
        ncol=3, fontsize=8, frameon=True, edgecolor="black", handlelength=1.2, columnspacing=1.5, borderpad=0.5
    )
    plt.subplots_adjust(wspace=0.28, bottom=0.32, left=0.08, right=0.99)
    fig.savefig(os.path.join(out_dir, "fig-cert-sizes.pdf"), format="pdf")
    fig.savefig(os.path.join(out_dir, "fig-cert-sizes.png"), format="png", dpi=300)
    plt.close()

def gen_keygen_figure():
    kc_keys = {"l1": ["ecdsa-p256", "ml-dsa-44"], "l3": ["ecdsa-p384", "ml-dsa-65"], "l5": ["ecdsa-p521", "ml-dsa-87"]}
    kc_labels = ["ECDSA\nP-256", "ML-DSA\n44", "ECDSA\nP-384", "ML-DSA\n65", "ECDSA\nP-521", "ML-DSA\n87"]

    fig, axes = plt.subplots(1, 3, figsize=(7.65, 3.6), sharey=False)
    latex_rows = []

    for li, level in enumerate(LEVELS):
        ax = axes[li]
        x = np.arange(2)
        w = 0.55

        fw_m = [0]*2
        login_m = [0]*2
        slot_m = [0]*2
        fk_m = [0]*2
        ext_m = [0]*2
        go_m = [0]*2
        fw_s = [0]*2
        login_s = [0]*2
        go_s = [0]*2
        tot_m = [0]*2
        tot_s = [0]*2

        for bi, algo in enumerate(kc_keys[level]):
            p = f"kc_hsm_{algo}"
            fw,  fw_sd   = load_vals_stats(p, "fw_keygen")
            lg,  lg_sd   = load_vals_stats(p, "c_login")
            sl,  _       = load_vals_stats(p, "pkcs11_find_slot")
            fkv, _       = load_vals_stats(p, "pkcs11_find_key")
            ext, _       = load_vals_stats(p, "pkcs11_extract_pub")
            kp,  kp_sd   = load_vals_stats(p, f"kp_generate_hsm_{algo}")
            ms,  ms_sd   = load_vals_stats(p, "main_start")

            fw_m[bi] = fw
            fw_s[bi] = fw_sd
            login_m[bi] = lg
            login_s[bi] = lg_sd
            slot_m[bi] = sl
            fk_m[bi] = fkv
            ext_m[bi] = ext
            go_m[bi] = max(0.0, ms - kp) if ms > 0 and kp > 0 else 0.0
            if go_m[bi] > 0:
                ms_raw = load_vals_raw(p, "main_start")
                kp_raw = load_vals_raw(p, f"kp_generate_hsm_{algo}")
                n = min(len(ms_raw), len(kp_raw))
                if n > 0:
                    go_s[bi] = float(np.std(ms_raw[:n] - kp_raw[:n]))
                else:
                    go_s[bi] = 0.0
            else:
                go_s[bi] = 0.0
            tot_m[bi] = ms if ms > 0 else kp
            tot_s[bi] = ms_sd if ms > 0 else kp_sd

        pkcs11_overhead_m = [0.0]*2
        pkcs11_overhead_s = [0.0]*2
        for bi in range(2):
            sum6 = fw_m[bi] + login_m[bi] + slot_m[bi] + fk_m[bi] + ext_m[bi] + go_m[bi]
            pkcs11_overhead_m[bi] = max(0.0, tot_m[bi] - sum6)

        b = [0.0, 0.0]
        seg_series = [
             (login_m, "C_Login (auth)",      colors["vermilion"], "//"),
             (pkcs11_overhead_m, "Other PKCS#11 overhead", colors["internal"], ".."),
             (slot_m,  "Slot enumeration",    colors["module"], "\\\\"),
             (fk_m,    "Key search",          colors["session"], "xx"),
             (ext_m,   "Pub key extract",     colors["extract"], "--"),
            (go_m,    "Go startup",          colors["red"], "..."),
        ]
        for s_vals, label_str, g_color, g_hatch in seg_series:
            for bi in range(2):
                ax.bar(x[bi], s_vals[bi], w, bottom=b[bi], color=g_color, edgecolor="black", lw=0.6, hatch=g_hatch,
                       label=label_str if li == 0 and bi == 0 else "")
            b = [b_val + s_val for b_val, s_val in zip(b, s_vals)]
        bar_colors = [colors["blue"], colors["vermilion"]]
        for bi in range(2):
            ax.bar(x[bi], fw_m[bi], w, bottom=b[bi], color=bar_colors[bi], edgecolor="black", lw=0.6, hatch="//",
                   label="Classical keygen" if li == 0 and bi == 0 else "PQC keygen" if li == 0 and bi == 1 else "")
        b = [b_val + f for b_val, f in zip(b, fw_m)]

        bar_totals = list(tot_m)
        bar_labels = [kc_labels[li * 2], kc_labels[li * 2 + 1]]

        for i in range(2):
            if bar_totals[i] > 0:
                ax.annotate(f"{bar_totals[i]:.1f} ms", (i, bar_totals[i]),
                            textcoords="offset points", xytext=(0, 3),
                            ha="center", fontsize=6.5, fontweight="bold")
            algo_str = ALGO_FULL.get(kc_keys[level][i], kc_keys[level][i])
            latex_rows.append(
                f"  {DISPLAY_NAMES[level]} & HSM & {algo_str} & {fmt_ms(fw_m[i], fw_s[i], 3)} & {fmt_ms(login_m[i], login_s[i], 3)} & {fmt_ms(pkcs11_overhead_m[i], pkcs11_overhead_s[i], 3)} & {fmt_ms(slot_m[i], 0.0, 3)} & {fmt_ms(fk_m[i], 0.0, 3)} & {fmt_ms(ext_m[i], 0.0, 3)} & {fmt_ms(go_m[i], go_s[i], 3)} & \\textbf{{{fmt_ms(tot_m[i], tot_s[i], 3)}}} \\\\"
            )

        ax.set_xticks(x)
        ax.set_xticklabels(bar_labels, fontsize=6.5, rotation=25, ha="right")
        ax.set_xlabel(f"{PANEL_LABELS[li]} {LEVEL_LABELS[li]}", fontsize=8, fontweight="bold", labelpad=2)
        ax.set_ylabel("Latency (ms)", fontsize=7.5)
        ax.yaxis.grid(True, linestyle="--", alpha=0.4, lw=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(0, 120)
        ax.set_yticks(np.arange(0, 121, 20))
        ax.tick_params(axis='y', labelsize=6.5)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=8, ncol=4, loc="lower center", bbox_to_anchor=(0.5, 0.005),
               frameon=True, edgecolor="black", columnspacing=1.0, handlelength=2.0, handleheight=1.2, borderpad=0.5)
    plt.subplots_adjust(wspace=0.28, bottom=0.36, left=0.08, right=0.99)

    tex_content = (
        "\\begin{table*}[htbp]\n"
        "  \\centering\n"
        "  \\caption{\\textcolor{red}{HSM key-generation micro-timing breakdown (mean $\\pm$ SD, ms).}}\n"
        "  \\label{tab:keygen-latency}\n"
        "  \\scriptsize\\setlength{\\tabcolsep}{1.5pt}\n"
        "  \\begin{tabular}{lllrrrrrrrr}\n"
        "    \\toprule\n"
        "    \\textbf{Level} & \\textbf{Mode} & \\textbf{Algorithm} & \\textbf{Firmware} & \\textbf{C\\_Login} & \\textbf{PKCS\\#11 OH} & \\textbf{Slot enum} & \\textbf{Key search} & \\textbf{Pub extract} & \\textbf{Go start} & \\textbf{Total ($\\mu \\pm \\sigma$)} \\\\\n"
        "    \\midrule\n"
        + "\n".join(latex_rows) + "\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table*}\n"
    )
    with open(os.path.join(tables_dir, "tab-keygen-latency.tex"), "w") as fh:
        fh.write(tex_content)

    fig.savefig(os.path.join(out_dir, "fig-keygen-latency.pdf"), format="pdf")
    fig.savefig(os.path.join(out_dir, "fig-keygen-latency.png"), format="png", dpi=300)
    plt.close()

def generate_ctp_figures():
    gen_cert_size_figure()
    gen_keygen_figure()
    gen_issue_figure()
    gen_verify_figure()

    latex_fig_dir = os.path.join(dir_path, "..", "figures")
    latex_tab_dir = os.path.join(dir_path, "..", "tables")
    os.makedirs(latex_fig_dir, exist_ok=True)
    os.makedirs(latex_tab_dir, exist_ok=True)
    for fname in os.listdir(out_dir):
        if not fname.endswith((".pdf", ".png")):
            continue
        src = os.path.join(out_dir, fname)
        dst = os.path.join(latex_fig_dir, fname)
        if os.path.abspath(src) == os.path.abspath(dst):
            continue
        if os.path.islink(dst) or os.path.isfile(dst):
            os.remove(dst)
        shutil.copy2(src, dst)
    for fname in os.listdir(tables_dir):
        if not fname.endswith(".tex"):
            continue
        src = os.path.join(tables_dir, fname)
        dst = os.path.join(latex_tab_dir, fname)
        if os.path.abspath(src) == os.path.abspath(dst):
            continue
        if os.path.islink(dst) or os.path.isfile(dst):
            os.remove(dst)
        shutil.copy2(src, dst)

if __name__ == "__main__":
    generate_ctp_figures()
