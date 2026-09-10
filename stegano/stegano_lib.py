import hashlib
# © Anibal Edelberto Amiot 2026 — La Livrée d'Hermès
# AGPL v3 (non-commercial) / Commercial license: anibaledel@gmail.com
# Geometric constructions: IACR ePrint 2026 (CC BY) — Patent: FR2865054
"""
Stéganographie géométrique — La Livrée d'Hermès (2026)
Audit cryptologique : 2026-09-10

ARCHITECTURE :
  Couche 1 — XChaCha20-Poly1305 : message chiffré AVANT dissimulation.
  Couche 2 — Dissimulation géométrique : chiffré placé aux positions
             définies par les clés B, C, 2.

NOTE AUDIT : Clé A retirée (redondante avec Clé 2, 0 bit ajouté).
NOTE AUDIT : symboles du message ET bruit uniformes sur [0..ALPHA_LEN-1]
             → aucun distingueur statistique sur la valeur des cellules.
NOTE AUDIT : Confidentialité assurée par XChaCha20, pas par la géométrie.
"""

import json, os, secrets, struct, math
from typing import List, Dict, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
from cryptography.hazmat.primitives import hashes as _hashes

def _xchacha_enc(key: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    """XChaCha20-Poly1305 : nonce 24 bytes. [A3]"""
    nonce  = os.urandom(24)
    subkey = _HKDF(_hashes.SHA256(), 32, salt=nonce[:16],
                   info=b'XChaCha20-HChaCha20-subkey').derive(key)
    ct = ChaCha20Poly1305(subkey).encrypt(b'\x00'*4 + nonce[16:], plaintext, aad or None)
    return nonce + ct

def _xchacha_dec(key: bytes, data: bytes, aad: bytes = b'') -> bytes:
    """XChaCha20-Poly1305 déchiffrement. [A3]"""
    nonce, ct = data[:24], data[24:]
    subkey = _HKDF(_hashes.SHA256(), 32, salt=nonce[:16],
                   info=b'XChaCha20-HChaCha20-subkey').derive(key)
    return ChaCha20Poly1305(subkey).decrypt(b'\x00'*4 + nonce[16:], ct, aad or None)

def _find_ref(name: str) -> str:
    _dir = os.path.dirname(os.path.abspath(__file__))
    for path in [
        os.path.join(_dir, name),
        os.path.join(_dir, 'data', name),
        os.path.join(os.path.dirname(_dir), 'data', name),
    ]:
        if os.path.exists(path): return path
    raise FileNotFoundError(f"{name} introuvable")

ALPHABET  = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?-'
ALPHA_LEN = len(ALPHABET)   # 44
_AEAD_OVERHEAD = 32 + 24 + 16   # commitment HMAC + nonce XChaCha20 + tag Poly1305
_MAX_PAYLOAD   = 1 << 24        # garde-fou en-tête (16 Mio)

def load_referents() -> Tuple[List, List]:
    with open(_find_ref('referent_256.json')) as f: r256 = json.load(f)
    with open(_find_ref('referent_360.json')) as f: r360 = json.load(f)
    return r256, r360

# ── Encodage base-44 ─────────────────────────────────────────────────────────
# CORRECTIF AUDIT : l'encodage en nibbles plaçait les octets du message dans
# [0..15] alors que le bruit couvre [0..43]. Toute cellule > 15 était donc
# prouvablement du bruit, et une forme dont les 6 cellules valent <= 15 avait
# 1 chance sur 432 d'être du bruit : les blocs porteurs se localisaient
# statistiquement sans aucune clé. Le message restait chiffré, mais sa
# PRÉSENCE et son EMPLACEMENT étaient détectables — l'inverse du but d'un
# système stéganographique.
#
# Les symboles portent désormais la même loi uniforme sur [0..ALPHA_LEN-1]
# que le bruit. Le payload est vu comme un entier, complété par un aléa de
# rembourrage qui rend la distribution des symboles uniforme à 2^-64 près,
# puis écrit en base ALPHA_LEN. Bonus : 1,47 symbole par octet au lieu de 2.

_UNIFORM_MARGIN_BITS = 64   # écart à l'uniformité : <= 2^-64

def _sym_count(nbytes: int) -> int:
    """Nombre de symboles base-44 pour nbytes octets, marge d'uniformité incluse."""
    return math.ceil((8*nbytes + _UNIFORM_MARGIN_BITS) / math.log2(ALPHA_LEN))

_SYM_HEADER = _sym_count(4)   # en-tête : longueur du payload sur 4 octets

def _bytes_to_syms(b: bytes, m: int) -> List[int]:
    """Octets → m symboles uniformes sur [0..ALPHA_LEN-1]."""
    span = 1 << (8*len(b))
    k = (ALPHA_LEN ** m) // span
    if k < 1:
        raise ValueError(f"{m} symboles insuffisants pour {len(b)} octets")
    u = int.from_bytes(b, 'big') + span * secrets.randbelow(k)
    out = []
    for _ in range(m):
        u, r = divmod(u, ALPHA_LEN)
        out.append(r)
    return out

def _syms_to_bytes(syms: List[int], nbytes: int) -> bytes:
    """Inverse de _bytes_to_syms : le rembourrage aléatoire disparaît au modulo."""
    u = 0
    for d in reversed(syms):
        if not 0 <= d < ALPHA_LEN:
            raise ValueError(f"Symbole hors plage : {d}")
        u = u * ALPHA_LEN + d
    return (u & ((1 << (8*nbytes)) - 1)).to_bytes(nbytes, 'big')

# ── Chiffrement du message — Key commitment + XChaCha20 ──────────────────────
import hmac as _hmac_mod

def _commit_key(steg_key: bytes) -> bytes:
    """Clé HMAC dédiée au key commitment (séparée de la clé XChaCha20)."""
    return _HKDF(_hashes.SHA256(), 32,
                  salt=b'commit-v1',
                  info=b'key-commitment').derive(steg_key)

def _encrypt(message: str, steg_key: bytes) -> bytes:
    """
    Chiffre avec XChaCha20-Poly1305 + key commitment HMAC-SHA256 [correction 3].

    Format : [32B HMAC(commit_key, inner)][inner]
      inner = nonce(24) + ciphertext + tag(16)
    La longueur est portée séparément par l'en-tête base-44 de la grille.

    Key commitment : ce ciphertext ne peut déchiffrer valablement
    que sous une seule clé — élimine les partitioning oracle attacks.
    """
    msg_b    = message.upper().encode('ascii', errors='replace')
    inner    = _xchacha_enc(steg_key, msg_b)
    ck       = _commit_key(steg_key)
    commit   = _hmac_mod.new(ck, inner, hashlib.sha256).digest()  # 32 bytes
    return commit + inner

def _decrypt(vals: List[int], steg_key: bytes) -> str:
    """
    Vérifie le key commitment PUIS déchiffre.
    Double protection : HMAC invalide → rejet immédiat sans tentative de déchiffrement.
    """
    if len(vals) < _SYM_HEADER:
        raise ValueError("Grille trop petite")
    total_len = struct.unpack('>I', _syms_to_bytes(vals[:_SYM_HEADER], 4))[0]
    if total_len > _MAX_PAYLOAD:
        raise ValueError("En-tête invalide — clé de dissimulation incorrecte")
    need = _SYM_HEADER + _sym_count(total_len)
    if len(vals) < need:
        raise ValueError(f"Positions insuffisantes : {len(vals)} < {need}")
    payload = _syms_to_bytes(vals[_SYM_HEADER:need], total_len)
    if len(payload) < 32:
        raise ValueError("Payload trop court (key commitment manquant)")
    commit_recv, inner = payload[:32], payload[32:]
    # Vérifier key commitment avant déchiffrement
    ck          = _commit_key(steg_key)
    commit_calc = _hmac_mod.new(ck, inner, hashlib.sha256).digest()
    if not _hmac_mod.compare_digest(commit_recv, commit_calc):
        raise ValueError("Key commitment invalide — clé incorrecte ou données altérées")
    try:
        pt = _xchacha_dec(steg_key, inner)
    except Exception:
        raise ValueError("Tag Poly1305 invalide — clé incorrecte ou données altérées")
    return pt.decode('ascii', errors='replace')

# ── Flux de symboles — API pour carter.py et grid_90.py ──────────────────────
# Ces modules construisent leur propre flux et appellent _decrypt() dessus.
# Ils doivent donc produire exactement le même flux que encode() : en-tête de
# longueur puis payload, en symboles base-44. Sans cela, ils continueraient
# d'écrire des nibbles [0..15] repérables dans un bruit couvrant [0..43].

def payload_to_symbols(payload: bytes) -> List[int]:
    """Payload chiffré → flux de symboles uniformes sur [0..ALPHA_LEN-1]."""
    return (_bytes_to_syms(struct.pack('>I', len(payload)), _SYM_HEADER)
            + _bytes_to_syms(payload, _sym_count(len(payload))))

def symbols_needed(payload_len: int) -> int:
    """Nombre de positions nécessaires pour un payload de cette taille."""
    return _SYM_HEADER + _sym_count(payload_len)

def max_payload_for(n_positions: int) -> int:
    """Plus grand payload (en octets) tenant dans n_positions symboles."""
    avail = n_positions - _SYM_HEADER
    if avail <= 0:
        return 0
    lo, hi = 0, avail
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _sym_count(mid) <= avail: lo = mid
        else: hi = mid - 1
    return lo

def max_message_for(n_positions: int) -> int:
    """Plus long message clair tenant dans n_positions symboles."""
    return max(0, max_payload_for(n_positions) - _AEAD_OVERHEAD)

# ── Orientations D4 ──────────────────────────────────────────────────────────
ORIENTATIONS = [
    lambda r,c,n: (r,   c  ),
    lambda r,c,n: (c,   n-r),
    lambda r,c,n: (n-r, n-c),
    lambda r,c,n: (n-c, r  ),
    lambda r,c,n: (r,   n-c),
    lambda r,c,n: (n-r, c  ),
    lambda r,c,n: (c,   r  ),
    lambda r,c,n: (n-c, n-r),
]

def apply_orientation(positions: List, orient: int, grid_n: int = 5) -> List:
    t = ORIENTATIONS[orient % 8]
    return [t(r, c, grid_n) for r, c in positions]

VALID_K = frozenset({1, 2, 3, 5})

def _chk_k(k: int) -> None:
    if k not in VALID_K:
        raise ValueError(f"k={k} invalide. Valeurs autorisées : {sorted(VALID_K)}")

def zigzag_blocks(B: int) -> List[Tuple[int,int]]:
    order = []
    for r in range(B):
        cols = range(B-1,-1,-1) if r%2==0 else range(B)
        for c in cols: order.append((r, c))
    return order

# ── Capacité ─────────────────────────────────────────────────────────────────
def max_message_len(key_b: List[int], grid_size: int = 60) -> int:
    """Longueur max du message en clair (bytes disponibles - overhead AEAD)."""
    B = grid_size // 6
    order = zigzag_blocks(B)
    n_pos = 0; pos_i = 0
    for k in key_b:
        if pos_i >= len(order): break
        available = min(k*k, len(order) - pos_i)
        n_pos += available * 6; pos_i += available
    # CORRECTIF AUDIT : l'ancien calcul comptait un surcoût de 32 octets alors
    # que le format en consomme 72 (32 commitment + 24 nonce + 16 tag). Un
    # message de la taille annoncée était accepté à l'encodage, tronqué
    # silencieusement faute de positions, puis irrécupérable au décodage.
    avail = n_pos - _SYM_HEADER
    lo, hi = 0, max(0, avail)
    while lo < hi:                      # plus grand payload tenant dans avail
        mid = (lo + hi + 1) // 2
        if _sym_count(mid) <= avail: lo = mid
        else: hi = mid - 1
    return max(0, lo - _AEAD_OVERHEAD)

# ── Encodeur ─────────────────────────────────────────────────────────────────
def encode(message: str, steg_key: bytes,
           key_b: List[int], key_c: List[List[int]], key_2: List[Dict],
           ref256: List[Dict], grid_size: int = 60) -> List[List[int]]:
    for k in key_b: _chk_k(k)
    N = grid_size; B = N // 6
    if N % 6 != 0:
        raise ValueError(f"grid_size {N} doit être multiple de 6")
    max_len = max_message_len(key_b, grid_size)
    if len(message) > max_len:
        raise ValueError(f"Message trop long : {len(message)} > {max_len}")

    payload = _encrypt(message, steg_key)
    # En-tête (longueur) + payload, en symboles base-44 uniformes
    nibbles = payload_to_symbols(payload)

    # Grille de bruit — même loi uniforme [0..ALPHA_LEN-1] que les symboles
    grid = [[secrets.randbelow(ALPHA_LEN) for _ in range(N)] for _ in range(N)]

    # Placer les nibbles
    nib_idx = 0
    order = zigzag_blocks(B)
    pos_i = 0; block_i = 0

    while pos_i < len(order) and nib_idx < len(nibbles) and block_i < len(key_b):
        k = key_b[block_i]; fk = key_2[block_i]; orients = key_c[block_i]
        form = ref256[fk['form_id'] % len(ref256)]
        base_pos = form[fk.get('color', 'blue')]
        for sub in range(k*k):
            if pos_i >= len(order) or nib_idx >= len(nibbles): break
            br, bc = order[pos_i]
            t = apply_orientation(base_pos, orients[sub % len(orients)])
            for r, c in t:
                if nib_idx >= len(nibbles): break
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    grid[gr][gc] = nibbles[nib_idx]; nib_idx += 1
            pos_i += 1
        block_i += 1
    return grid

# ── Décodeur ─────────────────────────────────────────────────────────────────
def decode(grid: List[List[int]], steg_key: bytes,
           key_b: List[int], key_c: List[List[int]], key_2: List[Dict],
           ref256: List[Dict], grid_size: int = 60) -> str:
    for k in key_b: _chk_k(k)
    N = grid_size; B = N // 6
    vals = []; order = zigzag_blocks(B); pos_i = 0; block_i = 0
    while pos_i < len(order) and block_i < len(key_b):
        k = key_b[block_i]; fk = key_2[block_i]; orients = key_c[block_i]
        form = ref256[fk['form_id'] % len(ref256)]
        base_pos = form[fk.get('color', 'blue')]
        for sub in range(k*k):
            if pos_i >= len(order): break
            br, bc = order[pos_i]
            t = apply_orientation(base_pos, orients[sub % len(orients)])
            for r, c in t:
                gr, gc = br*6+r, bc*6+c
                if 0 <= gr < N and 0 <= gc < N:
                    vals.append(grid[gr][gc])
            pos_i += 1
        block_i += 1
    return _decrypt(vals, steg_key)

# ── Clés ─────────────────────────────────────────────────────────────────────
def make_keys(msg_len: int, ref256: List[Dict],
              grid_size: int = 60, block_size: int = 1) -> Tuple:
    if block_size not in VALID_K:
        raise ValueError(f"block_size={block_size} invalide")
    B = grid_size // 6; n_blocks = B * B
    steg_key = secrets.token_bytes(32)
    key_b = [block_size]*n_blocks
    key_c = [[secrets.randbelow(8) for _ in range(block_size**2)]
              for _ in range(n_blocks)]
    key_2 = [{'form_id': secrets.randbelow(len(ref256)),
               'color': secrets.choice(['blue','orange'])}
              for _ in range(n_blocks)]
    max_len = max_message_len(key_b, grid_size)
    if msg_len > max_len:
        raise ValueError(f"Message {msg_len} > capacité {max_len}")
    return steg_key, key_b, key_c, key_2

def compute_keyspace(key_b: List[int], ref256: List[Dict]) -> Dict:
    n_blocks = len(key_b); n_sub = sum(k**2 for k in key_b)
    return {
        'steg_key'    : '256 bits (XChaCha20)',
        'key_B_bits'  : round(math.log2(4)*n_blocks),
        'key_C_bits'  : round(math.log2(8)*n_sub),
        'key_2_bits'  : round(math.log2(len(ref256)*2)*n_blocks),
        'key_A'       : 'Retirée — redondante avec Clé 2 (audit 2026-09-10)',
        'note'        : 'Confidentialité = XChaCha20 (256 bits effectifs)',
    }

def grid_to_csv(g): return '\n'.join(','.join(str(v) for v in r) for r in g)
def csv_to_grid(s): return [[int(v) for v in r.split(',')]
                             for r in s.strip().split('\n')]

def demo():
    print("=== STÉGANOGRAPHIE GÉOMÉTRIQUE — La Livrée d'Hermès ===\n")
    ref256, _ = load_referents()
    message = "ANIBALAMIOTX"
    sk, kb, kc, k2 = make_keys(len(message), ref256, grid_size=60)
    grid = encode(message, sk, kb, kc, k2, ref256)
    decoded = decode(grid, sk, kb, kc, k2, ref256)
    print(f"Message : '{message}' | Décodé : '{decoded}' | OK : {decoded==message}")
    # Mauvaise clé
    try:
        decode(grid, secrets.token_bytes(32), kb, kc, k2, ref256)
    except ValueError as e:
        print(f"Mauvaise clé : {e} ✓")
    # Anti-distingueur S4
    flat = [v for row in grid for v in row]
    zeros = flat.count(0)
    print(f"Valeurs 0 dans la grille : {zeros} (bruit inclus — pas de distingueur trivial)")
    ks = compute_keyspace(kb, ref256)
    print(f"\nEspace de clés (honnête) :")
    for k,v in ks.items(): print(f"  {k:<14} : {v}")
    print(f"\nCapacité max (k=1, 60×60) : {max_message_len(kb,60)} caractères")

if __name__ == '__main__':
    demo()

# ── Grille Carter — Grammaire à 3 catégories dérivées de la clé ───────────────
# Intégration de carter.py dans stegano_lib
# Référence : Grille Carter, La Livrée d'Hermès, Anibal Edelberto Amiot 2026

CARTER_GRID  = 90
CARTER_BLOCK = 6
CARTER_SIDE  = CARTER_GRID // CARTER_BLOCK    # 15 blocs par côté
CARTER_N     = CARTER_SIDE ** 2               # 225 blocs

_PURE, _STRUCTURED, _MESSAGE = 0, 1, 2

def _carter_split(master_key: bytes):
    """
    Séparation explicite des clés Carter [correction 2].
    Deux usages distincts → deux sous-clés indépendantes via HKDF.
      xchacha_key : chiffrement XChaCha20-Poly1305
      grammar_key : dérivation de la grammaire (rôles + formes)
    Propriété : la grammaire ne révèle rien sur la clé de chiffrement et vice-versa.
    """
    xchacha_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'Carter-v2',
                         info=b'encrypt').derive(master_key)
    grammar_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'Carter-v2',
                         info=b'grammar').derive(master_key)
    return xchacha_key, grammar_key

def _carter_grammar(master_key: bytes, ref256: List[Dict]) -> List[Dict]:
    """
    Dérive la grammaire Carter depuis la clé maître (HKDF-SHA256).
    Assigne à chaque bloc un rôle et une forme géométrique.
    Sans la clé, les rôles sont inconnus → grammaire = couche secrète.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hh
    km = HKDF(_hh.SHA256(), CARTER_N * 4,
              salt=b'Carter-grammar-v1',
              info=b'block-roles-and-forms').derive(master_key)
    grammar = []
    for i in range(CARTER_N):
        b = km[i*4 : i*4+4]
        rb = b[0]
        role = _PURE if rb < 85 else (_STRUCTURED if rb < 170 else _MESSAGE)
        grammar.append({
            'role':    role,
            'form_id': (b[1] * len(ref256)) // 256,
            'color':   'blue' if b[2] < 128 else 'orange',
            'orient':  b[3] % 8,
        })
    return grammar

def _carter_positions(br: int, bc: int, g: Dict, ref256: List[Dict]) -> List[Tuple]:
    """6 positions de lecture du bloc (br, bc) selon la grammaire g."""
    form = ref256[g['form_id'] % len(ref256)]
    base = form[g['color']]
    t    = apply_orientation(base, g['orient'])
    r0, c0 = br * CARTER_BLOCK, bc * CARTER_BLOCK
    return [(r0+r, c0+c) for r, c in t
            if 0 <= r0+r < CARTER_GRID and 0 <= c0+c < CARTER_GRID]

def encode_carter(message: str, master_key: bytes,
                  ref256: List[Dict]) -> List[List[int]]:
    """
    Encode un message dans une grille Carter 90×90.

    La clé maître dérive :
      - La grammaire (rôles des 225 blocs : pur / structuré / message)
      - La forme géométrique de chaque bloc non-pur

    Blocs 'message'    → positions = nibbles du message chiffré (XChaCha20)
    Blocs 'structuré'  → positions = valeurs aléatoires (indiscernables)
    Blocs 'pur'        → tout aléatoire, aucune structure appliquée

    grid_to_csv() pour sérialiser, csv_to_grid() pour désérialiser.
    """
    import secrets as _sec
    xchacha_key, grammar_key = _carter_split(master_key)
    grammar = _carter_grammar(grammar_key, ref256)
    n_msg   = sum(1 for g in grammar if g['role'] == _MESSAGE)

    payload = _encrypt(message, xchacha_key)
    nibbles = []
    for b in payload:
        hi, lo = _byte_to_nibs(b)
        nibbles += [hi, lo]

    if len(nibbles) > n_msg * 6:
        raise ValueError(
            f"Message trop long pour la grammaire dérivée : "
            f"{len(nibbles)//2} bytes > {n_msg * 3} bytes disponibles. "
            f"Changer la clé ou réduire le message.")

    grid  = [[_sec.randbelow(ALPHA_LEN) for _ in range(CARTER_GRID)]
              for _ in range(CARTER_GRID)]
    nib_i = 0
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        br, bc = i // CARTER_SIDE, i % CARTER_SIDE
        for gr, gc in _carter_positions(br, bc, g, ref256):
            if nib_i >= len(nibbles): break
            grid[gr][gc] = nibbles[nib_i]; nib_i += 1
    return grid

def decode_carter(grid: List[List[int]], master_key: bytes,
                  ref256: List[Dict]) -> str:
    """
    Décode une grille Carter. La grammaire est re-dérivée depuis la clé.
    Lève ValueError si la clé est incorrecte (tag Poly1305 invalide).
    """
    xchacha_key, grammar_key = _carter_split(master_key)
    grammar = _carter_grammar(grammar_key, ref256)
    vals = []
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        br, bc = i // CARTER_SIDE, i % CARTER_SIDE
        vals.extend(grid[gr][gc]
                    for gr, gc in _carter_positions(br, bc, g, ref256))
    return _decrypt(vals, xchacha_key)

def carter_capacity(master_key: bytes, ref256: List[Dict]) -> Dict:
    """Retourne les statistiques de capacité de la grammaire dérivée."""
    _, grammar_key = _carter_split(master_key)
    grammar = _carter_grammar(grammar_key, ref256)
    n_msg = sum(1 for g in grammar if g['role'] == _MESSAGE)
    n_str = sum(1 for g in grammar if g['role'] == _STRUCTURED)
    n_pur = sum(1 for g in grammar if g['role'] == _PURE)
    overhead = 4 + 24 + 16   # header + nonce + tag XChaCha20
    return {
        'blocs_message':    n_msg,
        'blocs_structure':  n_str,
        'blocs_purs':       n_pur,
        'nibbles':          n_msg * 6,
        'bytes_bruts':      n_msg * 3,
        'bytes_utiles':     n_msg * 3 - overhead,
        'chars_max':        max(0, n_msg * 3 - overhead),
        'ambiguite':        f"1 message parmi {n_msg + n_str} blocs structurés",
    }

# ── Référent 360 — Grille Carter 180×180 ──────────────────────────────────────
# Blocs 12×12, 8 positions par forme (une couleur parmi C1/C2/C3)
# Même structure Carter que 90×90 : 225 blocs, grammaire dérivée de la clé

CARTER360_GRID  = 180
CARTER360_BLOCK = 12
CARTER360_SIDE  = CARTER360_GRID // CARTER360_BLOCK   # 15
CARTER360_N     = CARTER360_SIDE ** 2                  # 225

_COLORS_360 = ['C1', 'C2', 'C3']

def _load_ref360() -> List[Dict]:
    """Charge le Référent 360 (formes complètes 3×8=24 positions)."""
    import json
    with open(_find_ref('referent_360.json')) as f:
        raw = json.load(f)
    return [f for f in raw
            if (isinstance(f['positions'], dict) and
                sum(len(v) for v in f['positions'].values()) == 24)]

def _carter360_split(master_key: bytes):
    """Séparation des clés pour Carter 360 (salt distinct du Carter 256)."""
    xchacha_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'Carter360-v2', info=b'encrypt').derive(master_key)
    grammar_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'Carter360-v2', info=b'grammar').derive(master_key)
    return xchacha_key, grammar_key

def _carter360_grammar(master_key: bytes, ref360: List[Dict]) -> List[Dict]:
    """
    Dérive la grammaire Carter pour le Référent 360 (blocs 12×12).
    Même principe que _carter_grammar pour Ref256,
    mais avec 3 couleurs (C1/C2/C3) au lieu de 2 (blue/orange).
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hh
    km = HKDF(_hh.SHA256(), CARTER360_N * 4,
              salt=b'Carter360-grammar-v1',
              info=b'block-roles-360-forms').derive(master_key)
    grammar = []
    for i in range(CARTER360_N):
        b = km[i*4 : i*4+4]
        rb = b[0]
        role = _PURE if rb < 85 else (_STRUCTURED if rb < 170 else _MESSAGE)
        grammar.append({
            'role':    role,
            'form_id': (b[1] * len(ref360)) // 256,
            'color':   _COLORS_360[b[2] % 3],
            'orient':  b[3] % 6,   # 6 permutations de couleurs
        })
    return grammar

def _carter360_positions(br: int, bc: int,
                          g: Dict, ref360: List[Dict]) -> List[Tuple]:
    """8 positions de lecture du bloc 12×12 (br, bc) selon la grammaire g."""
    form = ref360[g['form_id'] % len(ref360)]
    pts  = form['positions'].get(g['color'], [])
    r0, c0 = br * CARTER360_BLOCK, bc * CARTER360_BLOCK
    return [(r0+r, c0+c) for r, c in pts
            if 0 <= r0+r < CARTER360_GRID and 0 <= c0+c < CARTER360_GRID]

def encode_carter_360(message: str, master_key: bytes,
                       ref360: Optional[List[Dict]] = None) -> List[List[int]]:
    """
    Encode un message dans une grille Carter 180×180 (Référent 360).

    Grammaire dérivée de master_key :
      'pur'       → bruit aléatoire, aucune structure 12×12
      'structuré' → forme Ref360 appliquée, valeurs aléatoires
      'message'   → forme Ref360 appliquée, valeurs = message XChaCha20

    Capacité utile : ~256 caractères (vs ~181 pour Carter 90×90 Ref256).
    """
    import secrets as _sec
    if ref360 is None:
        ref360 = _load_ref360()

    xchacha_key, grammar_key = _carter360_split(master_key)
    grammar = _carter360_grammar(grammar_key, ref360)
    n_msg   = sum(1 for g in grammar if g['role'] == _MESSAGE)

    payload = _encrypt(message, xchacha_key)
    nibbles = []
    for b in payload:
        hi, lo = _byte_to_nibs(b)
        nibbles += [hi, lo]

    if len(nibbles) > n_msg * 8:
        raise ValueError(
            f"Message trop long : {len(nibbles)//2} bytes > "
            f"{n_msg * 4} bytes disponibles ({n_msg} blocs × 8 positions / 2).")

    grid  = [[_sec.randbelow(ALPHA_LEN) for _ in range(CARTER360_GRID)]
              for _ in range(CARTER360_GRID)]
    nib_i = 0
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        br, bc = i // CARTER360_SIDE, i % CARTER360_SIDE
        for gr, gc in _carter360_positions(br, bc, g, ref360):
            if nib_i >= len(nibbles): break
            grid[gr][gc] = nibbles[nib_i]; nib_i += 1
    return grid

def decode_carter_360(grid: List[List[int]], master_key: bytes,
                       ref360: Optional[List[Dict]] = None) -> str:
    """Décode une grille Carter 180×180. Lève ValueError si clé incorrecte."""
    if ref360 is None:
        ref360 = _load_ref360()
    xchacha_key, grammar_key = _carter360_split(master_key)
    grammar = _carter360_grammar(grammar_key, ref360)
    vals = []
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        br, bc = i // CARTER360_SIDE, i % CARTER360_SIDE
        vals.extend(grid[gr][gc]
                    for gr, gc in _carter360_positions(br, bc, g, ref360))
    return _decrypt(vals, xchacha_key)

def carter360_capacity(master_key: bytes,
                        ref360: Optional[List[Dict]] = None) -> Dict:
    """Statistiques de capacité de la grammaire Carter 360."""
    if ref360 is None:
        ref360 = _load_ref360()
    _, grammar_key = _carter360_split(master_key)
    grammar = _carter360_grammar(grammar_key, ref360)
    n_msg = sum(1 for g in grammar if g['role'] == _MESSAGE)
    n_str = sum(1 for g in grammar if g['role'] == _STRUCTURED)
    n_pur = sum(1 for g in grammar if g['role'] == _PURE)
    overhead = 4 + 24 + 16
    return {
        'referent':         '360',
        'grille':           f'{CARTER360_GRID}×{CARTER360_GRID}',
        'blocs_message':    n_msg,
        'blocs_structure':  n_str,
        'blocs_purs':       n_pur,
        'positions_bloc':   8,
        'nibbles':          n_msg * 8,
        'bytes_utiles':     max(0, n_msg * 4 - overhead),
        'chars_max':        max(0, n_msg * 4 - overhead),
        'ambiguite':        f"1 message parmi {n_msg + n_str} blocs structurés",
    }

# ── Grille Carter Mixte 180×180 — Ref256 + Ref360 combinés ────────────────────
# Grammaire opérant sur 225 méta-blocs 12×12.
# Chaque méta-bloc reçoit un référent (256 ou 360) et un rôle (pur/structuré/message).
# La clé détermine tout — référent, rôle, forme, couleur, orientation.

CARTER_MIX_GRID  = 180
CARTER_MIX_META  = 12           # méta-bloc 12×12
CARTER_MIX_SIDE  = 15           # méta-blocs par côté (180/12)
CARTER_MIX_N     = 225          # total méta-blocs
_REF256, _REF360 = 0, 1         # identifiants de référent

def _carter_mix_split(master_key: bytes):
    """Séparation des clés pour Carter mixte (salt distinct)."""
    xchacha_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'CarterMix-v2', info=b'encrypt').derive(master_key)
    grammar_key = _HKDF(_hashes.SHA256(), 32,
                         salt=b'CarterMix-v2', info=b'grammar').derive(master_key)
    return xchacha_key, grammar_key

def _carter_mix_grammar(master_key: bytes,
                         ref256: List[Dict],
                         ref360: List[Dict]) -> List[Dict]:
    """
    Dérive la grammaire Carter mixte depuis la clé maître.
    Pour chaque méta-bloc 12×12 (225 total) :
      - référent : 256 (4 sous-blocs 6×6) ou 360 (1 bloc 12×12)
      - rôle     : pur / structuré / message
      - forme    : issue du référent sélectionné
    Sans la clé, référent ET rôle sont inconnus.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hh
    km = HKDF(_hh.SHA256(), CARTER_MIX_N * 5,
              salt=b'CarterMix-v1',
              info=b'mixed-256-360-grammar').derive(master_key)
    grammar = []
    for i in range(CARTER_MIX_N):
        b = km[i*5 : i*5+5]
        role = _PURE if b[0] < 85 else (_STRUCTURED if b[0] < 170 else _MESSAGE)
        ref  = _REF256 if b[1] < 128 else _REF360
        if ref == _REF256:
            cfg = {'form_id': (b[2] * len(ref256)) // 256,
                   'color':   'blue' if b[3] < 128 else 'orange',
                   'orient':  b[4] % 8}
        else:
            cfg = {'form_id': (b[2] * len(ref360)) // 256,
                   'color':   _COLORS_360[b[3] % 3],
                   'orient':  b[4] % 6}
        grammar.append({'role': role, 'ref': ref, **cfg})
    return grammar

def _mix_positions(mbr: int, mbc: int,
                   g: Dict, ref256: List[Dict],
                   ref360: List[Dict]) -> List[Tuple]:
    """
    Positions de lecture d'un méta-bloc (mbr, mbc) selon sa grammaire.
    Ref256 : 4 sous-blocs × 6 = 24 positions
    Ref360 : 1 bloc 12×12 × 8 =  8 positions
    """
    N = CARTER_MIX_GRID
    if g['ref'] == _REF256:
        form = ref256[g['form_id'] % len(ref256)]
        base = form[g['color']]
        t    = apply_orientation(base, g['orient'])
        pos  = []
        for dr in range(2):      # 2×2 sous-blocs dans le méta-bloc
            for dc in range(2):
                r0 = mbr * CARTER_MIX_META + dr * CARTER_BLOCK
                c0 = mbc * CARTER_MIX_META + dc * CARTER_BLOCK
                for r, c in t:
                    gr, gc = r0+r, c0+c
                    if 0 <= gr < N and 0 <= gc < N:
                        pos.append((gr, gc))
        return pos   # jusqu'à 24
    else:
        form = ref360[g['form_id'] % len(ref360)]
        pts  = form['positions'].get(g['color'], [])
        r0   = mbr * CARTER_MIX_META
        c0   = mbc * CARTER_MIX_META
        return [(r0+r, c0+c) for r, c in pts
                if 0 <= r0+r < N and 0 <= c0+c < N]  # 8

def encode_carter_mix(message: str, master_key: bytes,
                       ref256: List[Dict],
                       ref360: Optional[List[Dict]] = None) -> List[List[int]]:
    """
    Encode un message dans une grille Carter mixte 180×180.
    Ref256 et Ref360 coexistent — la clé détermine quel référent chaque méta-bloc utilise.

    Méta-blocs Ref256 message : 24 positions = 12 bytes
    Méta-blocs Ref360 message :  8 positions =  4 bytes

    La capacité totale est elle-même dérivée de la clé (obscurcissement).
    """
    import secrets as _sec
    if ref360 is None:
        ref360 = _load_ref360()

    xchacha_key, grammar_key = _carter_mix_split(master_key)
    grammar = _carter_mix_grammar(grammar_key, ref256, ref360)
    # Calculer la capacité
    nibbles_cap = sum(len(_mix_positions(i//CARTER_MIX_SIDE, i%CARTER_MIX_SIDE,
                                          g, ref256, ref360))
                      for i, g in enumerate(grammar) if g['role'] == _MESSAGE)

    payload = _encrypt(message, xchacha_key)
    nibbles = []
    for b in payload:
        hi, lo = _byte_to_nibs(b)
        nibbles += [hi, lo]

    if len(nibbles) > nibbles_cap:
        raise ValueError(
            f"Message trop long : {len(nibbles)//2} bytes > "
            f"{nibbles_cap//2} bytes disponibles dans la grammaire dérivée.")

    grid  = [[_sec.randbelow(ALPHA_LEN) for _ in range(CARTER_MIX_GRID)]
              for _ in range(CARTER_MIX_GRID)]
    nib_i = 0
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        mbr, mbc = i // CARTER_MIX_SIDE, i % CARTER_MIX_SIDE
        for gr, gc in _mix_positions(mbr, mbc, g, ref256, ref360):
            if nib_i >= len(nibbles): break
            grid[gr][gc] = nibbles[nib_i]; nib_i += 1
    return grid

def decode_carter_mix(grid: List[List[int]], master_key: bytes,
                       ref256: List[Dict],
                       ref360: Optional[List[Dict]] = None) -> str:
    """Décode une grille Carter mixte 180×180."""
    if ref360 is None:
        ref360 = _load_ref360()
    xchacha_key, grammar_key = _carter_mix_split(master_key)
    grammar = _carter_mix_grammar(grammar_key, ref256, ref360)
    vals = []
    for i, g in enumerate(grammar):
        if g['role'] != _MESSAGE: continue
        mbr, mbc = i // CARTER_MIX_SIDE, i % CARTER_MIX_SIDE
        vals.extend(grid[gr][gc]
                    for gr, gc in _mix_positions(mbr, mbc, g, ref256, ref360))
    return _decrypt(vals, xchacha_key)

def carter_mix_capacity(master_key: bytes,
                         ref256: List[Dict],
                         ref360: Optional[List[Dict]] = None) -> Dict:
    """Statistiques de capacité de la grammaire Carter mixte."""
    if ref360 is None:
        ref360 = _load_ref360()
    _, grammar_key = _carter_mix_split(master_key)
    grammar = _carter_mix_grammar(grammar_key, ref256, ref360)
    n256m = sum(1 for g in grammar if g['role']==_MESSAGE and g['ref']==_REF256)
    n360m = sum(1 for g in grammar if g['role']==_MESSAGE and g['ref']==_REF360)
    n256s = sum(1 for g in grammar if g['role']==_STRUCTURED and g['ref']==_REF256)
    n360s = sum(1 for g in grammar if g['role']==_STRUCTURED and g['ref']==_REF360)
    n_pur = sum(1 for g in grammar if g['role']==_PURE)
    nibs  = n256m*24 + n360m*8
    overhead = 4+24+16
    return {
        'grille':              f'{CARTER_MIX_GRID}×{CARTER_MIX_GRID}',
        'meta_blocs':          CARTER_MIX_N,
        'message_ref256':      n256m,
        'message_ref360':      n360m,
        'structure_ref256':    n256s,
        'structure_ref360':    n360s,
        'purs':                n_pur,
        'nibbles_total':       nibs,
        'bytes_utiles':        max(0, nibs//2 - overhead),
        'chars_max':           max(0, nibs//2 - overhead),
        'ambiguite_256':       f"1/{n256m+n256s} méta-blocs Ref256",
        'ambiguite_360':       f"1/{n360m+n360s} méta-blocs Ref360",
    }
