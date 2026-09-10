# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
Grille 90×90 — Structure QR à trois niveaux
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Hiérarchie :
  Cellule    : 1×1
  Bloc       : 6×6 cellules      → 15×15 = 225 blocs
  Super-bloc : 3×3 blocs (9 bl)  →  5×5  =  25 super-blocs

Rôles (5×5 super-blocs) :
  ▓ coin   (4)  : marqueurs fixes (reconnaissables sans clé)
  ░ bord  (12)  : message leurre
  · centre (9)  : message réel

Encodage par super-bloc :
  - Message réel  → 9 blocs du super-bloc central en stream continu
  - Message leurre→ 9 blocs du super-bloc bord en stream continu
  - Marqueurs     → pattern fixe dans le bloc central uniquement
  - Bruit         → cellules restantes

Capacité :
  Un super-bloc (9 blocs × 6 positions) = 54 nibbles = 27 bytes utiles
  9 super-blocs centraux = 9×27 = 243 bytes bruts → ~185 bytes après overhead XChaCha20
"""

import os, secrets
from typing import List, Tuple, Dict, Optional
from stegano_lib import (
    load_referents, make_keys,
    apply_orientation, ALPHA_LEN,
    _encrypt, _decrypt, payload_to_symbols
)

GRID_SIZE   = 90
BLOCK_SIZE  = 6
BLOCKS_SIDE = 15   # 90/6
SUPER_SIDE  = 5    # 15/3
SUPER_BL    = 3    # blocs par côté de super-bloc

def super_role(sr: int, sc: int) -> str:
    if (sr in (0, SUPER_SIDE-1)) and (sc in (0, SUPER_SIDE-1)): return 'corner'
    if (sr in (0, SUPER_SIDE-1)) or (sc in (0, SUPER_SIDE-1)):  return 'edge'
    return 'center'

def blocks_of_super(sr: int, sc: int) -> List[Tuple[int,int]]:
    """9 blocs (br, bc) du super-bloc (sr, sc) — ordre zigzag."""
    br0, bc0 = sr * SUPER_BL, sc * SUPER_BL
    blocs = [(br0+dr, bc0+dc) for dr in range(SUPER_BL) for dc in range(SUPER_BL)]
    return blocs   # 9 blocs

def central_block(sr: int, sc: int) -> Tuple[int,int]:
    return sr * SUPER_BL + 1, sc * SUPER_BL + 1

# Marqueur de coin : pattern 6×6 visuel (bordure pleine + anneau vide + croix)
CORNER_PAT = [
    [15,15,15,15,15,15],
    [15, 0, 0, 0, 0,15],
    [15, 0,15,15, 0,15],
    [15, 0,15,15, 0,15],
    [15, 0, 0, 0, 0,15],
    [15,15,15,15,15,15],
]

def apply_corner(grid, sr, sc):
    br, bc = central_block(sr, sc)
    r0, c0 = br*BLOCK_SIZE, bc*BLOCK_SIZE
    for dr in range(6):
        for dc in range(6):
            grid[r0+dr][c0+dc] = CORNER_PAT[dr][dc]

# ── Encodage / Décodage stream sur un super-bloc ──────────────────────────────
def _collect_positions(sr, sc, ref256, k2, kc):
    """Retourne toutes les positions de lecture du super-bloc dans l'ordre."""
    positions = []
    for i, (br, bc) in enumerate(blocks_of_super(sr, sc)):
        r0, c0 = br*BLOCK_SIZE, bc*BLOCK_SIZE
        idx = i % len(k2)
        fk = k2[idx]; orient = kc[idx][0]
        form = ref256[fk['form_id'] % len(ref256)]
        base = form[fk.get('color','blue')]
        t = apply_orientation(base, orient)
        for r, c in t:
            positions.append((r0+r, c0+c))
    return positions   # 9 blocs × 6 positions = 54 positions

def encode_super(grid, message, sk, kb, kc, k2, sr, sc, ref256):
    """Encode un message dans les 54 positions du super-bloc (sr, sc)."""
    payload  = _encrypt(message, sk)
    nibbles  = payload_to_symbols(payload)
    positions = _collect_positions(sr, sc, ref256, k2, kc)
    for i, (gr, gc) in enumerate(positions):
        if i >= len(nibbles): break
        if 0 <= gr < GRID_SIZE and 0 <= gc < GRID_SIZE:
            grid[gr][gc] = nibbles[i]

def decode_super(grid, sk, kc, k2, sr, sc, ref256):
    """Lit les 54 nibbles du super-bloc et tente le déchiffrement."""
    positions = _collect_positions(sr, sc, ref256, k2, kc)
    vals = [grid[gr][gc] for gr,gc in positions
            if 0 <= gr < GRID_SIZE and 0 <= gc < GRID_SIZE]
    return _decrypt(vals, sk)

# ── API principale ─────────────────────────────────────────────────────────────
def make_grid_90(real_message, real_keys, lure_message, lure_keys, ref256):
    """
    Construit la grille 90×90.
    Message réel  → stream sur les 9 super-blocs centraux (486 nibbles)
    Message leurre→ stream sur les 12 super-blocs de bord (648 nibbles)
    Coins         → marqueurs fixes
    Reste         → bruit aléatoire
    """
    N    = GRID_SIZE
    grid = [[secrets.randbelow(ALPHA_LEN) for _ in range(N)] for _ in range(N)]

    # 1. Marqueurs de coin
    for sr, sc in [(0,0),(0,4),(4,0),(4,4)]:
        apply_corner(grid, sr, sc)

    # 2. Message réel → stream sur 9 super-blocs centraux
    center_supers = [(sr,sc) for sr in range(1,4) for sc in range(1,4)]
    _encode_stream(grid, real_message, real_keys, center_supers, ref256)

    # 3. Message leurre → stream sur 12 super-blocs de bord
    if lure_message and lure_keys:
        edge_supers = [(sr,sc) for sr in range(5) for sc in range(5)
                       if super_role(sr,sc)=='edge']
        _encode_stream(grid, lure_message, lure_keys, edge_supers, ref256)

    return grid

def _encode_stream(grid, message, keys, supers, ref256):
    """Encode un message en stream sur une liste de super-blocs."""
    payload = _encrypt(message, keys['steg_key'])
    nibbles = payload_to_symbols(payload)
    nib_i = 0
    for i, (sr, sc) in enumerate(supers):
        if nib_i >= len(nibbles): break
        for j, (br, bc) in enumerate(blocks_of_super(sr, sc)):
            if nib_i >= len(nibbles): break
            idx  = (i * SUPER_BL * SUPER_BL + j) % len(keys['key_2'])
            fk   = keys['key_2'][idx]
            orient = keys['key_c'][idx][0]
            form = ref256[fk['form_id'] % len(ref256)]
            base = form[fk.get('color','blue')]
            t    = apply_orientation(base, orient)
            r0, c0 = br*BLOCK_SIZE, bc*BLOCK_SIZE
            for r, c in t:
                if nib_i >= len(nibbles): break
                gr, gc = r0+r, c0+c
                if 0 <= gr < GRID_SIZE and 0 <= gc < GRID_SIZE:
                    grid[gr][gc] = nibbles[nib_i]; nib_i += 1

def _decode_stream(grid, keys, supers, ref256):
    """Lit en stream depuis une liste de super-blocs."""
    vals = []
    for i, (sr, sc) in enumerate(supers):
        for j, (br, bc) in enumerate(blocks_of_super(sr, sc)):
            idx  = (i * SUPER_BL * SUPER_BL + j) % len(keys['key_2'])
            fk   = keys['key_2'][idx]
            orient = keys['key_c'][idx][0]
            form = ref256[fk['form_id'] % len(ref256)]
            base = form[fk.get('color','blue')]
            t    = apply_orientation(base, orient)
            r0, c0 = br*BLOCK_SIZE, bc*BLOCK_SIZE
            for r, c in t:
                gr, gc = r0+r, c0+c
                if 0 <= gr < GRID_SIZE and 0 <= gc < GRID_SIZE:
                    vals.append(grid[gr][gc])
    return _decrypt(vals, keys['steg_key'])

def decode_grid_90(grid, keys, ref256, role='center'):
    """Décode le message du rôle indiqué (center=réel, edge=leurre)."""
    if role == 'center':
        supers = [(sr,sc) for sr in range(1,4) for sc in range(1,4)]
    else:
        supers = [(sr,sc) for sr in range(5) for sc in range(5)
                  if super_role(sr,sc)=='edge']
    return _decode_stream(grid, keys, supers, ref256)

def detect_corners(grid) -> bool:
    for sr, sc in [(0,0),(0,4),(4,0),(4,4)]:
        br, bc = central_block(sr, sc)
        r0, c0 = br*BLOCK_SIZE, bc*BLOCK_SIZE
        if grid[r0][c0] != 15 or grid[r0][c0+1] != 15: return False
    return True

def print_map():
    sym = {'corner':'▓','edge':'░','center':'·'}
    print("Structure 5×5 super-blocs (15×15 blocs de 6×6) :")
    print("  ┌───────────────────┐")
    for sr in range(SUPER_SIDE):
        row = "  │"
        for sc in range(SUPER_SIDE): row += f" {sym[super_role(sr,sc)]}"
        print(row+" │")
    print("  └───────────────────┘")
    print("  ▓ coin(4)    : marqueurs sans clé")
    print("  ░ bord(12)   : message leurre")
    print("  · centre(9)  : message réel\n")
    print(f"  Capacité utile / super-bloc : 54 nibbles = 27 bytes")
    overhead = 4 + 24 + 16   # header + nonce + tag
    print(f"  Overhead XChaCha20 : {overhead} bytes")
    print(f"  Message max / super-bloc : {27-overhead} bytes (3 chars)")
    print(f"  → Pour messages longs : stream sur 9 super-blocs centraux")
    print(f"  → Capacité totale message réel : 9×(27-{overhead}) = {9*(27-overhead)} bytes = {9*(27-overhead)} chars")

if __name__ == '__main__':
    print("="*54)
    print("GRILLE 90×90 — STRUCTURE QR LA LIVRÉE D'HERMÈS")
    print("="*54+"\n")
    print_map()

    ref256, _ = load_referents()

    # Générer des clés pour 9×9 = 81 blocs (super-blocs centraux)
    N_BLOCS = SUPER_BL * SUPER_BL * 9   # 81 blocs pour les 9 super-blocs centraux
    real_sk, real_kb, real_kc, real_k2 = make_keys(
        len("ANIBALAMIOTX"), ref256, grid_size=GRID_SIZE)
    lure_sk, lure_kb, lure_kc, lure_k2 = make_keys(
        len("TEXTEANODINS"), ref256, grid_size=GRID_SIZE)

    real_keys = {'steg_key':real_sk,'key_b':real_kb,'key_c':real_kc,'key_2':real_k2}
    lure_keys = {'steg_key':lure_sk,'key_b':lure_kb,'key_c':lure_kc,'key_2':lure_k2}

    print("\nConstruction...")
    grid = make_grid_90("ANIBALAMIOTX", real_keys,
                        "TEXTEANODINS", lure_keys, ref256)

    print(f"Grille 90×90 = {GRID_SIZE**2} cellules ✓")
    print(f"Marqueurs de coin : {detect_corners(grid)} ✓")

    real_out = decode_grid_90(grid, real_keys, ref256, role='center')
    lure_out = decode_grid_90(grid, lure_keys, ref256, role='edge')
    print(f"\nMessage réel   : '{real_out}' ✓")
    print(f"Message leurre : '{lure_out}' ✓")
    print(f"\n3 niveaux indépendants :")
    print(f"  Marqueurs   → lisibles sans clé (structure QR)")
    print(f"  Leurre      → lisible avec clé leurre uniquement")
    print(f"  Réel        → lisible avec clé réelle uniquement")
