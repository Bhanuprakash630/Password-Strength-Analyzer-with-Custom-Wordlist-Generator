#!/usr/bin/env python3
"""
wordlist.py
Password analyzer + small custom wordlist generator (CLI)

Usage examples:
  python wordlist.py --password "hbsdubcuv @1232"
  python wordlist.py --inputs "alice,fluffy,1990" --output mylist.txt
Dependencies:
  pip install zxcvbn-python
  (optional) pip install nltk
"""
import argparse
import math
import re
import sys
import itertools
from datetime import datetime
from typing import List, Dict

# Try to import zxcvbn from common package names
zxcvbn_func = None
try:
    # preferred: zxcvbn-python (pip name: zxcvbn-python)
    from zxcvbn import zxcvbn as _zxcvbn_func
    zxcvbn_func = _zxcvbn_func
except Exception:
    try:
        # sometimes import path varies
        import zxcvbn
        if hasattr(zxcvbn, 'zxcvbn'):
            zxcvbn_func = zxcvbn.zxcvbn
    except Exception:
        zxcvbn_func = None

# Simple leet map for wordlist generator
LEET_MAP = {
    'a': ['4', '@'],
    'b': ['8'],
    'e': ['3'],
    'i': ['1', '!'],
    'l': ['1', '|'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'z': ['2']
}
SEPARATORS = ['', '.', '_', '-', '']  # common separators ('' repeated intentionally)

# ---------- Password analysis ----------
def fallback_entropy(password: str) -> float:
    """Very simple entropy fallback when zxcvbn isn't available or doesn't provide entropy."""
    if not password:
        return 0.0
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^A-Za-z0-9]', password): charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)

def analyze_password(password: str) -> Dict:
    """Return a normalized analysis dict. Uses zxcvbn if available, otherwise fallback."""
    out = {
        'password': password,
        'score': None,
        'entropy': None,
        'crack_times_display': None,
        'feedback': None,
        'matches': None,
        'note': None,
    }
    if zxcvbn_func:
        try:
            r = zxcvbn_func(password)
            out['score'] = r.get('score')
            # Some zxcvbn variants may not include 'entropy' key; compute fallback if missing
            entropy = r.get('entropy')
            out['entropy'] = entropy if entropy is not None else round(fallback_entropy(password), 2)
            out['crack_times_display'] = r.get('crack_times_display')
            out['feedback'] = r.get('feedback')
            out['matches'] = r.get('sequence')
            out['note'] = 'zxcvbn used.'
            return out
        except Exception as ex:
            out['note'] = f'zxcvbn failed: {ex}. Used fallback.'
    # Fallback path
    out['score'] = None
    out['entropy'] = round(fallback_entropy(password), 2)
    out['crack_times_display'] = {
        'online_throttling_100_per_hour': 'unknown',
        'online_no_throttling_10_per_second': 'unknown',
        'offline_slow_hashing_1e4_per_second': 'unknown',
        'offline_fast_hashing_1e10_per_second': 'unknown'
    }
    out['feedback'] = {'warning': 'zxcvbn not available; using simple entropy estimate.'}
    out['matches'] = None
    return out

def pretty_print_analysis(an: Dict):
    print("Password analysis:")
    print(f"  password: {an.get('password')}")
    score = an.get('score')
    print(f"  score: {score if score is not None else 'N/A'}")
    print(f"  entropy (bits): {an.get('entropy')}")
    ctd = an.get('crack_times_display') or {}
    # print commonly useful crack time lines if available
    if isinstance(ctd, dict):
        for k in ['online_throttling_100_per_hour', 'online_no_throttling_10_per_second',
                  'offline_slow_hashing_1e4_per_second', 'offline_fast_hashing_1e10_per_second']:
            v = ctd.get(k)
            if v:
                print(f"  {k}: {v}")
    fb = an.get('feedback') or {}
    if fb:
        warning = fb.get('warning') if isinstance(fb, dict) else None
        suggestions = fb.get('suggestions') if isinstance(fb, dict) else None
        print(f"  feedback.warning: {warning or ''}")
        if suggestions:
            for s in suggestions:
                print(f"    - {s}")
    # matches can be long; show short summary
    matches = an.get('matches')
    if matches:
        print(f"  matches: {len(matches)} items (showing types/tokens):")
        for m in matches[:6]:
            typ = m.get('pattern', '<pattern>')
            token = m.get('token') or m.get('sequence') or ''
            print(f"    - {typ} : '{token}'")
    note = an.get('note')
    if note:
        print(f"  note: {note}")

# ---------- Simple wordlist generator ----------
def normalize_inputs(raw: str) -> List[str]:
    """Split comma-separated inputs and clean tokens."""
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(',') if p.strip()]
    cleaned = []
    for p in parts:
        # split on non-alphanum to extract parts like dates, e.g. 1990-01-01 -> 1990 01 01
        tokens = re.split(r'\W+', p)
        for t in tokens:
            t = t.strip()
            if t:
                cleaned.append(t)
    # dedupe preserving order
    seen = set()
    out = []
    for w in cleaned:
        lw = w.lower()
        if lw not in seen:
            seen.add(lw)
            out.append(w)
    return out

def leet_variants(word: str, max_variants=10):
    """Generate a small number of leet variants deterministically."""
    variants = {word}
    lower = word.lower()
    # for each character, try substitutions but keep branching limited
    for i, ch in enumerate(lower):
        if ch in LEET_MAP:
            for sub in LEET_MAP[ch]:
                v = list(lower)
                v[i] = sub
                variants.add(''.join(v))
        if len(variants) >= max_variants:
            break
    return sorted(variants)

def case_variants(word: str):
    """Return a few case variants."""
    return sorted(set([word.lower(), word.upper(), word.title(), word.capitalize()]))

def expand_seeds(seeds: List[str], use_leet=True, use_case=True, years=None):
    pool = set()
    for s in seeds:
        candidates = {s}
        if use_case:
            candidates |= set(case_variants(s))
        if use_leet:
            # apply leet to lower-case only variants to reduce explosion
            for c in list(candidates):
                for lv in leet_variants(c):
                    candidates.add(lv)
        # append years if provided
        if years:
            for y in years:
                for base in list(candidates):
                    pool.add(f"{base}{y}")
                    pool.add(f"{y}{base}")
        pool |= set(candidates)
    return sorted(pool)

def combine_words(words: List[str], separators=SEPARATORS, max_pairs=5000):
    """Create ordered pairs with separators (and include single words). Keep count limited."""
    out = []
    out.extend(words)  # singletons
    count = 0
    for a, b in itertools.permutations(words, 2):
        for sep in separators:
            out.append(f"{a}{sep}{b}")
            count += 1
            if count >= max_pairs:
                return out
    return out

def write_wordlist(words: List[str], path: str):
    with open(path, 'w', encoding='utf-8', errors='ignore') as f:
        for w in words:
            f.write(w + "\n")

# ---------- CLI ----------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Password analyzer + focused wordlist generator")
    parser.add_argument('--password', '-p', help='Password to analyze', default=None)
    parser.add_argument('--inputs', '-i', help='Comma-separated seeds (names, pets, dates)', default='')
    parser.add_argument('--years', nargs=2, type=int, metavar=('START','END'),
                        help='Optional year range to include (e.g. 1980 2025)', default=None)
    parser.add_argument('--no-leet', action='store_true', help='Disable leet variants')
    parser.add_argument('--no-case', action='store_true', help='Disable case variants')
    parser.add_argument('--output', '-o', help='Output wordlist file', default='wordlist.txt')
    parser.add_argument('--max-words', type=int, default=20000, help='Trim final list to this many words')
    args = parser.parse_args(argv)

    if args.password is not None:
        analysis = analyze_password(args.password)
        pretty_print_analysis(analysis)
        print("")

    seeds = normalize_inputs(args.inputs)
    # add some common words
    common = ['password', 'pass', 'admin', 'welcome', 'qwerty', '12345', 'iloveyou']

    seeds_all = list(dict.fromkeys(seeds + common))

    # prepare year list
    years = None
    if args.years:
        ys, ye = args.years
        if ys > ye:
            ys, ye = ye, ys
        years = [str(y) for y in range(ys, ye + 1)]
    else:
        # default small range (last 40 years) to avoid huge lists
        cur = datetime.now().year
        years = [str(y) for y in range(cur-30, cur+1)]

    expanded = expand_seeds(seeds_all, use_leet=not args.no_leet, use_case=not args.no_case, years=years)
    combos = combine_words(expanded, separators=SEPARATORS, max_pairs=5000)

    final = list(dict.fromkeys(expanded + combos))
    if args.max_words and len(final) > args.max_words:
        # keep shorter entries first for usefulness
        final = sorted(final, key=lambda x: (len(x), x))[:args.max_words]

    try:
        write_wordlist(final, args.output)
        print(f"Wrote {len(final)} words to {args.output}")
    except Exception as e:
        print("Failed to write wordlist:", e, file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
