import collections
from typing import Dict, Tuple

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from vyper import compile_code
from paths import CONTRACTS_DIR, CORPUS_PATH

# -- 1  Count all n-byte windows, 1 <= n <= 4 ---------------------------
def _count_windows(data: bytes) -> Dict[int, collections.Counter]:
    """
    Returns a dict where keys are lengths (1,2,3,4)
    and values are `Counter` objects that count all windows of that length.
    """
    counts = {2: collections.Counter(),
              3: collections.Counter(),
              4: collections.Counter()}
    for L in range(2, 5):
        for i in range(len(data) - L + 1):
            token = data[i:i+L]
            counts[L][token] += 1
    return counts

# -- 2  Pick the top-1024 token for each length -------------------------
def _top_tokens(counts: Dict[int, collections.Counter],
                top_n: int = 1024) -> Tuple[Dict[bytes, int], int]:
    """
    Creates the 4096-code table (12-bit).
    Code layout: 0-1023 = 4-byte, 1024-2047 = 3-byte,
                 2048-3071 = 2-byte, 3072-4095 = 1-byte.
    Returns (token_to_code, num_codes_used).
    """
    token_to_code: Dict[bytes, int] = {}
    token_to_code[b'\x00\x00\x00\x00'] = 0
    code = 1
    # 4-byte tokens first (codes 0-1023)
    for tok, _ in counts[4].most_common(top_n - 1):
        token_to_code[tok] = code
        code += 1
    # Pad to code 1024 if fewer than 1024 4-byte tokens
    code = top_n

    # 3-byte tokens (codes 1024-2047)
    for tok, _ in counts[3].most_common(top_n):
        token_to_code[tok] = code
        code += 1
    # Pad to code 2048
    code = top_n * 2

    # 2-byte tokens (codes 2048-3071)
    for tok, _ in counts[2].most_common(top_n):
        token_to_code[tok] = code
        code += 1
    # Pad to code 3072
    code = top_n * 3

    # 1-byte tokens (codes 3072-3327)
    for i in range(256):
        token_to_code[bytes([i])] = code
        code += 1

    return token_to_code, code   # code == 3328 (256 1-byte tokens used out of 1024 slots)

# -- 3  Build the binary dictionary blobs ----------------------------
def _make_dict_blobs(token_to_code: Dict[bytes, int]) -> Tuple[bytes, list[int], list[int]]:
    """
    Builds:
      - DICT_BYTES : concatenated token bytes, 10240 total
                     (1024*4 + 1024*3 + 1024*2 + 1024*1)
      - DICT_OFFS  : 4096 uint16 offsets into DICT_BYTES
      - DICT_LEN   : 4096 uint8 lengths (1-4)
    Returns the three arrays (as python lists for easy transfer).
    """
    # Prepare 4096 slots with placeholders
    max_codes = 4096
    DICT_BYTES = bytearray(10240)  # 1024*4 + 1024*3 + 1024*2 + 1024*1
    DICT_OFFS  = [0] * max_codes
    DICT_LEN   = [0] * max_codes

    # We'll scan token_to_code, but need to know the order of assignments.
    # We know the order: 4-byte first, 3-byte, 2-byte, 1-byte.
    # We'll reconstruct that order by grouping tokens by length.
    groups = {4: [], 3: [], 2: [], 1: []}
    for tok, code in token_to_code.items():
        groups[len(tok)].append((tok, code))

    # Write tokens contiguously, tracking offsets
    pos = 0
    for length in [4, 3, 2, 1]:
        for tok, code in sorted(groups[length], key=lambda x: x[1]):  # same code order
            DICT_OFFS[code] = pos
            DICT_LEN[code]  = length
            DICT_BYTES[pos:pos+length] = tok
            pos += length

    return bytes(DICT_BYTES), DICT_OFFS, DICT_LEN

# -- 4  Public helper -----------------------------------------------
def build_12bit_dict_from_corpus(corpus_path: str) -> Tuple[Dict[bytes, int], bytes, list[int], list[int]]:
    """
    Main entry point.
    Returns:
        token_to_code : mapping from token bytes to 12-bit code
        DICT_BYTES   : 10240-byte blob
        DICT_OFFS    : 4096 uint16 list
        DICT_LEN     : 4096 uint8 list
    """
    with open(corpus_path, "rb") as f:
        data = f.read()

    counts = _count_windows(data)
    token_to_code, _ = _top_tokens(counts)
    DICT_BYTES, DICT_OFFS, DICT_LEN = _make_dict_blobs(token_to_code)
    return token_to_code, DICT_BYTES, DICT_OFFS, DICT_LEN

# Backward-compat alias
build_10bit_dict_from_corpus = build_12bit_dict_from_corpus

def encode_msg(msg: bytes, token_to_code: dict[bytes, int]) -> bytes:
    """
    Encode *msg* using the compressed 12-bit dictionary.

    The function scans the source from left to right and, at every
    position, picks the **longest** token that is present in `token_to_code`.

    Two selected codes are packed into a 3-byte word, exactly as
    the decoder expects (2 x 12-bit -> 3 bytes).
    """
    codes = []

    i = 0
    L = len(msg)
    while i < L:
        # try 4-byte token
        if i + 4 <= L and msg[i:i+4] in token_to_code and token_to_code[msg[i:i+4]] > 0:
            codes.append(token_to_code[msg[i:i+4]])
            i += 4
            continue

        # try 3-byte token
        if i + 3 <= L and msg[i:i+3] in token_to_code:
            codes.append(token_to_code[msg[i:i+3]])
            i += 3
            continue

        # try 2-byte token
        if i + 2 <= L and msg[i:i+2] in token_to_code:
            codes.append(token_to_code[msg[i:i+2]])
            i += 2
            continue

        # fallback to 1-byte token (must exist in the dict)
        codes.append(token_to_code[msg[i:i+1]])
        i += 1

    # --------------------------------------------------------------------
    #  Padding: we pack the codes in groups of 2.  If a group is incomplete
    #  we pad with `0`.  Token 0 must therefore exist in the dictionary.
    #  In the dictionary-builder (`build_12bit_dict_from_corpus`) the first
    #  code (code 0) is always taken from the most frequent 4-byte token,
    #  so the decoder will simply emit that token when it sees the pad.
    # --------------------------------------------------------------------
    pad_len = (-len(codes)) % 2
    codes.extend([0] * pad_len)

    # Pack into 3-byte words (2 x 12-bit codes per word)
    out = bytearray()
    for i in range(0, len(codes), 2):
        c1, c2 = codes[i:i+2]
        word = (c1 << 12) | c2
        out += word.to_bytes(3, "big")

    return bytes(out)

# Deploy the contract that decodes a blob, including decompressing
def deploy_decoder(w3, acct, DICT_BYTES):
    # Deploy the Vyper decoder with the 10240-byte dictionary blob
    from pathlib import Path
    source = (CONTRACTS_DIR / "decoder.vy").read_text()
    compiled = compile_code(source, output_formats=["abi", "bytecode"])
    factory = w3.eth.contract(abi=compiled["abi"], bytecode=compiled["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(
        factory.constructor(DICT_BYTES).transact({"from": acct})
    )
    c = w3.eth.contract(address=receipt.contractAddress, abi=compiled["abi"])
    return c

# ------------------------------------------------------------------------------
#  Example usage ---------------------------------------------------------------
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    token_to_code, DICT_BYTES, _, _ = build_12bit_dict_from_corpus(str(CORPUS_PATH))
    msg = b"Hello, world! This is a test message."
    comp = encode_msg(msg, token_to_code)

    print(f"Original message length {len(msg)}, compressed to {len(comp)}")
    ratio = len(comp) / len(msg) if len(msg) > 0 else 0
    print(f"Compression ratio: {ratio:.2f}x ({100*(1-ratio):.1f}% savings)")

    w3 = Web3(EthereumTesterProvider())
    acct = w3.eth.accounts[0]
    c = deploy_decoder(w3, acct, DICT_BYTES)

    print('------- DEPLOYMENT PASSED -------')

    # Perform the round-trip
    decoded = c.functions.decompress(comp).call()
    assert decoded == msg, f"Round-trip failed: decoded message does not match: {decoded} vs expected {msg}"
    print("Round-trip succeeded: decoded matches original message")
