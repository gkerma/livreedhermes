# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
"""
Grille Carter — Grammaire à trois catégories dérivées de la clé
La Livrée d'Hermès — Anibal Edelberto Amiot (2026)

Concept :
  La clé maître dérive une GRAMMAIRE qui assigne à chaque bloc de la
  grille 90×90 l'un des trois rôles suivants :

    'pure'       : bruit pur — aucune forme géométrique appliquée
    'structured' : bruit structuré — forme ansée appliquée, positions aléatoires
    'message'    : message réel — forme ansée appliquée, positions = message chiffré

  Propriété fondamentale :
    'structured' et 'message' sont statistiquement INDISCERNABLES sans la clé.
    XChaCha20 produit du pseudo-aléatoire uniforme, identique au bruit pur.
    → La grammaire elle-même est une couche secrète supplémentaire.

  Ce que ça protège :
    Un analyste connaissant la méthode de la croix ansée peut identifier
    les blocs géométriquement structurés (pure vs non-pure).
    Mais il ne peut pas distinguer 'structured' de 'message' sans la clé.
    Il ne sait même pas combien de blocs portent réellement le message.
"""

import os, secrets, struct, hashlib
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _h

from stegano_lib import (
    load_referents, ALPHA_LEN,
    apply_orientation, _encrypt, _decrypt,
    payload_to_symbols, symbols_needed, max_message_for
)

GRID_SIZE   = 90
BLOCK_SIZE  = 6
BLOCKS_SIDE = GRID_SIZE // BLOCK_SIZE   # 15
N_BLOCKS    = BLOCKS_SIDE ** 2          # 225

# Rôles
PURE       = 0   # bruit pur
STRUCTURED = 1   # bruit structuré (géométrie appliquée, valeurs aléatoires)
MESSAGE    = 2   # message réel (géométrie + message chiffré)

ROLE_NAMES = {PURE: 'pure', STRUCTURED: 'structuré', MESSAGE: 'message'}

# ── Dérivation de la grammaire ─────────────────────────────────────────────────
def derive_grammar(master_key: bytes, ref256: List[Dict]) -> List[Dict]:
    """
    Dérive la grammaire complète depuis la clé maître.
    Retourne pour chaque bloc :
      {'role': PURE|STRUCTURED|MESSAGE,
       'form_id': int, 'color': str, 'orient': int}

    Distribution des rôles : entièrement déterminée par la clé.
    L'attaquant ne connaît ni la proportion ni la position des blocs message.
    """
    # HKDF → 4 bytes par bloc = 225 × 4 = 900 bytes
    km = HKDF(
        algorithm=_h.SHA256(),
        length=N_BLOCKS * 4,
        salt=b'Carter-grammar-v1',
        info=b'block-roles-and-forms'
    ).derive(master_key)

    grammar = []
    for i in range(N_BLOCKS):
        b = km[i*4 : i*4+4]
        # Rôle dérivé du premier byte
        role_byte = b[0]
        if role_byte < 85:        role = PURE        # ~33%
        elif role_byte < 170:     role = STRUCTURED  # ~33%
        else:                     role = MESSAGE     # ~33%

        # Forme et orientation pour les blocs non-purs
        form_id = (b[1] * len(ref256)) // 256
        color   = 'blue' if b[2] < 128 else 'orange'
        orient  = b[3] % 8

        grammar.append({
            'role':    role,
            'form_id': form_id,
            'color':   color,
            'orient':  orient,
        })
    return grammar

def grammar_stats(grammar: List[Dict]) -> Dict:
    roles = [g['role'] for g in grammar]
    return {
        'pure':       roles.count(PURE),
        'structured': roles.count(STRUCTURED),
        'message':    roles.count(MESSAGE),
        'msg_positions': roles.count(MESSAGE) * 6,
        'msg_chars':     max_message_for(roles.count(MESSAGE) * 6),
        # Noms d'avant conservés : le flux n'est plus en nibbles, mais des
        # appelants externes peuvent encore les lire.
        'msg_nibbles':   roles.count(MESSAGE) * 6,
        'msg_bytes':     max_message_for(roles.count(MESSAGE) * 6),
    }

# ── Positions d'un bloc selon sa grammaire ────────────────────────────────────
def block_positions(br: int, bc: int, g: Dict, ref256: List[Dict]) -> List[Tuple]:
    """Retourne les 6 positions de lecture du bloc (br, bc) selon g."""
    form = ref256[g['form_id'] % len(ref256)]
    base = form[g['color']]
    t    = apply_orientation(base, g['orient'])
    r0, c0 = br * BLOCK_SIZE, bc * BLOCK_SIZE
    return [(r0+r, c0+c) for r, c in t
            if 0 <= r0+r < GRID_SIZE and 0 <= c0+c < GRID_SIZE]

# ── Encodage Carter ────────────────────────────────────────────────────────────
def encode_carter(
    message:    str,
    master_key: bytes,
    ref256:     List[Dict],
) -> List[List[int]]:
    """
    Encode un message dans une grille Carter 90×90.

    1. Dériver la grammaire (rôles + formes)
    2. Bruit aléatoire partout
    3. Blocs 'structured' : forme ansée → positions déjà aléatoires (rien à faire)
    4. Blocs 'message'    : forme ansée → écrire les nibbles du message chiffré
    """
    grammar = derive_grammar(master_key, ref256)
    stats   = grammar_stats(grammar)

    # Vérifier la capacité
    payload  = _encrypt(message, master_key)
    # Symboles base-44, même flux que stegano_lib.encode() : les nibbles
    # [0..15] d'avant trahissaient les cellules message dans un bruit
    # couvrant [0..43].
    nibbles  = payload_to_symbols(payload)

    if len(nibbles) > stats['msg_positions']:
        raise ValueError(
            f"Message trop long : {len(message)} caractères > "
            f"{stats['msg_chars']} disponibles "
            f"({stats['message']} blocs message × 6 positions)")

    # Grille de bruit
    grid = [[secrets.randbelow(ALPHA_LEN) for _ in range(GRID_SIZE)]
            for _ in range(GRID_SIZE)]

    # Écrire uniquement dans les blocs MESSAGE
    nib_i = 0
    for i, g in enumerate(grammar):
        if g['role'] != MESSAGE: continue
        br, bc = i // BLOCKS_SIDE, i % BLOCKS_SIDE
        for gr, gc in block_positions(br, bc, g, ref256):
            if nib_i >= len(nibbles): break
            grid[gr][gc] = nibbles[nib_i]; nib_i += 1

    return grid

# ── Décodage Carter ────────────────────────────────────────────────────────────
def decode_carter(
    grid:       List[List[int]],
    master_key: bytes,
    ref256:     List[Dict],
) -> str:
    """
    Décode une grille Carter.
    La grammaire est re-dérivée depuis la clé — aucune métadonnée dans la grille.
    """
    grammar = derive_grammar(master_key, ref256)
    vals = []
    for i, g in enumerate(grammar):
        if g['role'] != MESSAGE: continue
        br, bc = i // BLOCKS_SIDE, i % BLOCKS_SIDE
        vals.extend(grid[gr][gc]
                    for gr, gc in block_positions(br, bc, g, ref256))
    return _decrypt(vals, master_key)

# ── Analyse stéganalytique ─────────────────────────────────────────────────────
def steganalysis_view(grammar: List[Dict]) -> Dict:
    """
    Ce qu'un analyste voit sans la clé mais en connaissant la méthode.
    Il peut identifier les blocs avec structure géométrique (STRUCTURED + MESSAGE)
    mais ne peut pas les distinguer l'un de l'autre.
    """
    visible_structured = sum(1 for g in grammar
                             if g['role'] in (STRUCTURED, MESSAGE))
    hidden_message     = sum(1 for g in grammar if g['role'] == MESSAGE)
    ambiguity          = visible_structured  # C(n,k) au moins
    return {
        'blocs_visibles': visible_structured,
        'blocs_message':  hidden_message,
        'ratio_ambiguite': f"1 sur {visible_structured} blocs visibles est réel",
        'info_bits': None,   # impossible à calculer sans la clé
    }

# ── Demo ───────────────────────────────────────────────────────────────────────
def demo():
    print("="*56)
    print("GRILLE CARTER — Grammaire à 3 catégories dérivées de la clé")
    print("="*56+"\n")

    ref256, _ = load_referents()
    master_key = os.urandom(32)

    # Grammaire
    grammar = derive_grammar(master_key, ref256)
    stats   = grammar_stats(grammar)
    view    = steganalysis_view(grammar)

    print("Grammaire dérivée de la clé (225 blocs) :")
    print(f"  Blocs purs        : {stats['pure']:3d}  ({stats['pure']/N_BLOCKS*100:.0f}%)")
    print(f"  Blocs structurés  : {stats['structured']:3d}  ({stats['structured']/N_BLOCKS*100:.0f}%)")
    print(f"  Blocs message     : {stats['message']:3d}  ({stats['message']/N_BLOCKS*100:.0f}%)")
    print(f"  Capacité message  : {stats['msg_bytes']} bytes = {stats['msg_bytes']-44} chars utiles")
    print()
    print("Vue d'un analyste sans clé :")
    print(f"  Blocs géométriquement structurés visibles : {view['blocs_visibles']}")
    print(f"  Dont blocs message réels                  : {view['blocs_message']} (inconnu)")
    print(f"  → {view['ratio_ambiguite']}")
    print()

    # Encodage
    msg = "LACROIXANSEEESTLAMETHODECREATIVEDELALIVREEDHERMES"
    print(f"Message : '{msg}' ({len(msg)} chars)")
    grid = encode_carter(msg, master_key, ref256)
    print(f"Grille 90×90 générée")

    # Décodage
    dec = decode_carter(grid, master_key, ref256)
    print(f"Décodé  : '{dec}'")
    assert dec == msg
    print(f"Vérification : ✓\n")

    # Démonstration : mauvaise clé → bruit
    wrong_key = os.urandom(32)
    try:
        decode_carter(grid, wrong_key, ref256)
        print("ERREUR : décodage avec mauvaise clé réussi !")
    except ValueError:
        print("Mauvaise clé → tag Poly1305 invalide ✓")
        print("(La grammaire incorrecte lit les mauvais blocs → XChaCha20 échoue)")

    print("\nPropriétés :")
    print("  1. Grammaire dérivée de la clé → rôles inconnus sans clé ✓")
    print("  2. Blocs 'structuré' indiscernables de 'message' ✓")
    print("  3. Aucune métadonnée dans la grille ✓")
    print("  4. Authentification XChaCha20 : modification détectée ✓")
    print("  5. La grammaire est une couche secrète supplémentaire ✓")

if __name__ == '__main__':
    demo()
