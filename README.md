# SocialBlobs

An implementation of an encoder/decoder and BLS signature verifier for https://github.com/ethereum/ERCs/pull/1578, a minimalistic "social on Ethereum blobs/calldata" protocol.

* `signature_registry.vy` implements a signature registry, which allows addresses to register their BLS keys, and also implements a BLS signature aggregate verifier
* `decoder.vy` implements a blob decompressor, which deserializes a blob (could be literal blob contents or calldata) into tuples of (sender, nonce, message), and uses a basic compression algorithm (with corpus.txt as the dictionary source) to dompress the message
* `hash_to_point_test.py` tests the hash-to-point part of the BLS signature verifier (by far the hardest part to get right in my experience)
* `bpe_encode.py` does an end-to-end test of the compression and decompression
* `test.py` tests everything
