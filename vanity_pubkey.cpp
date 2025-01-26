#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include <cassert>

#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

//-----------------------------------------------------------
//  CONFIGURATION
//-----------------------------------------------------------

// Desired prefix in HEX (e.g., "20d45a" means 3 bytes: 0x20, 0xd4, 0x5a)
static const std::string TARGET_PREFIX = "20d45a";

// Starting compressed public key in hex
// Example: "039cd99959584e36732e46c9e297c2e918e0a83dff7adb4e5a9b1f54b90d36ece5"
static const std::string START_PUBKEY_HEX =
    "039cd99959584e36732e46c9e297c2e918e0a83dff7adb4e5a9b1f54b90d36ece5";

// How many increments each thread should perform before re-checking global stop.
static const int BATCH_SIZE = 10000;  // tune this as you like

//-----------------------------------------------------------
//  GLOBALS
//-----------------------------------------------------------

// Once a thread finds a match, set this to true so all threads stop
static std::atomic<bool> g_found(false);

//-----------------------------------------------------------
//  HEX / BYTE UTILS
//-----------------------------------------------------------
static std::vector<unsigned char> hex_to_bytes(const std::string &hex) {
    // Assumes `hex` length is even
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        sscanf(hex.substr(i, 2).c_str(), "%x", &byte);
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    static const char* hexdig = "0123456789abcdef";
    std::string hex;
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        hex.push_back(hexdig[c >> 4]);
        hex.push_back(hexdig[c & 0xF]);
    }
    return hex;
}

//-----------------------------------------------------------
//  HASH160 = RIPEMD160( SHA256(data) )
//-----------------------------------------------------------
static void hash160(const unsigned char* data, size_t data_len,
                    unsigned char out20[20]) {
    // 1) SHA256
    unsigned char sha256_out[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, sha256_out);

    // 2) RIPEMD160
    RIPEMD160(sha256_out, SHA256_DIGEST_LENGTH, out20);
}

//-----------------------------------------------------------
//  CHECK PREFIX
//-----------------------------------------------------------
// Return true if the first TARGET_PREFIX.size() hex chars match
static bool check_prefix(const unsigned char out20[20]) {
    // Convert to hex
    std::string hash_hex = bytes_to_hex(out20, 20);
    // Compare prefix
    // We only compare exactly TARGET_PREFIX.length() chars
    return hash_hex.compare(0, TARGET_PREFIX.size(), TARGET_PREFIX) == 0;
}

//-----------------------------------------------------------
//  CREATE SECP256K1 CONTEXT (ONE GLOBAL INSTANCE)
//-----------------------------------------------------------
static secp256k1_context* g_ctx = nullptr;

static void init_secp256k1() {
    if (!g_ctx) {
        // Create a context for verification + signing (or "none" if you prefer).
        // Flags can be (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY).
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        // Optionally, randomize the context (this is recommended).
        unsigned char seed[32] = {0};
        // Some random seed, if you wish. For deterministic usage, keeping zero is perfect.
        secp256k1_context_randomize(g_ctx, seed);
    }
}

//-----------------------------------------------------------
//  PARSE A COMPRESSED PUBKEY FROM HEX INTO A secp256k1_pubkey
//-----------------------------------------------------------
static bool parse_pubkey(const std::string &hex, secp256k1_pubkey &pubkey) {
    std::vector<unsigned char> data = hex_to_bytes(hex);
    if (data.size() != 33) {
        std::cerr << "Invalid compressed pubkey length: " << data.size() << "\n";
        return false;
    }
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pubkey, data.data(), data.size())) {
        std::cerr << "Error parsing pubkey\n";
        return false;
    }
    return true;
}

//-----------------------------------------------------------
//  SERIALIZE A PUBKEY TO COMPRESSED HEX
//-----------------------------------------------------------
static std::string serialize_pubkey(const secp256k1_pubkey &pubkey) {
    unsigned char out[33];
    size_t outlen = 33;
    unsigned int flags = SECP256K1_EC_COMPRESSED;
    secp256k1_ec_pubkey_serialize(g_ctx, out, &outlen, &pubkey, flags);
    return bytes_to_hex(out, outlen);
}

//-----------------------------------------------------------
//  TWEAK ADD: pubkey = pubkey + tweak*G
//-----------------------------------------------------------
static bool pubkey_tweak_add(secp256k1_pubkey &pubkey, const unsigned char tweak[32]) {
    // This modifies `pubkey` in place, computing P := P + tweak*G
    // Returns false if P + tweak*G is invalid (point at infinity).
    int ret = secp256k1_ec_pubkey_tweak_add(g_ctx, &pubkey, tweak);
    return (ret != 0);
}

//-----------------------------------------------------------
//  MAKE 32-BYTE TWEAK FROM AN INTEGER
//-----------------------------------------------------------
static void int_to_32bytes(uint64_t v, unsigned char out[32]) {
    // Zero out
    memset(out, 0, 32);
    // Put 'v' little-endian at end of out[32]
    // (though secp256k1 doesn't enforce endianness strictly for the tweak)
    for (int i = 0; i < 8; i++) {
        out[31 - i] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

//-----------------------------------------------------------
//  WORKER THREAD FUNCTION
//-----------------------------------------------------------
static void worker_thread(int thread_id, int num_threads,
                          const secp256k1_pubkey &start_pubkey) {
    // Each thread: start at P_i = P + i*G
    // Then keep doing P_i += num_threads*G each iteration,
    // but now we do it in batches (BATCH_SIZE) before checking again.

    // 1) Copy start_pubkey into local, so we can tweak it
    secp256k1_pubkey pubkey_i = start_pubkey;

    // 2) Make tweak for "i" to get initial offset
    unsigned char tweak_init[32];
    int_to_32bytes(thread_id, tweak_init);

    if (!pubkey_tweak_add(pubkey_i, tweak_init)) {
        // If the resulting point is invalid, skip (rare but possible).
        std::cerr << "[Thread " << thread_id << "] pubkey_tweak_add(i) failed.\n";
        return;
    }

    // 3) Make a tweak for each iteration: step = num_threads
    unsigned char tweak_step[32];
    int_to_32bytes(num_threads, tweak_step);

    // 4) Main loop
    while (!g_found.load(std::memory_order_relaxed)) {
        // Process BATCH_SIZE increments in a row
        for (int b = 0; b < BATCH_SIZE; b++) {
            // Check again inside the loop in case another thread found a match
            if (g_found.load(std::memory_order_relaxed)) {
                return;  // Exit this thread
            }

            // a) Serialize pubkey_i to get 33-byte compressed form
            unsigned char compressed[33];
            size_t clen = 33;
            secp256k1_ec_pubkey_serialize(
                g_ctx, compressed, &clen, &pubkey_i, SECP256K1_EC_COMPRESSED);

            // b) Compute HASH160
            unsigned char h160[20];
            hash160(compressed, clen, h160);

            // c) Check prefix
            if (check_prefix(h160)) {
                // Found a match!
                g_found.store(true, std::memory_order_relaxed);

                // Print results
                std::string pubkey_hex = bytes_to_hex(compressed, clen);
                std::string hash_hex   = bytes_to_hex(h160, 20);

                std::cout << "\n[Thread " << thread_id << "] MATCH FOUND!\n"
                          << "  PubKey:  " << pubkey_hex << "\n"
                          << "  HASH160: " << hash_hex << "\n";
                return;
            }

            // d) Increment: P_i += num_threads * G
            if (!pubkey_tweak_add(pubkey_i, tweak_step)) {
                // Extremely unlikely: indicates P_i reached point at infinity
                // or something invalid. We can break or return.
                std::cerr << "[Thread " << thread_id
                          << "] pubkey_tweak_add(step) failed.\n";
                return;
            }
        }
        // After finishing the batch, we loop again if not found
    }
}

//-----------------------------------------------------------
//  MAIN
//-----------------------------------------------------------
int main() {
    // 1) Initialize secp256k1 context
    init_secp256k1();

    // 2) Parse the start pubkey
    secp256k1_pubkey start_pubkey;
    if (!parse_pubkey(START_PUBKEY_HEX, start_pubkey)) {
        std::cerr << "Failed to parse START_PUBKEY_HEX\n";
        return 1;
    }

    // 3) Number of threads = hardware concurrency
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) {
        num_threads = 1; // fallback
    }

    std::cout << "Starting vanity search:\n"
              << "  Start PubKey: " << START_PUBKEY_HEX << "\n"
              << "  Target prefix: " << TARGET_PREFIX << "\n"
              << "  Using " << num_threads << " threads.\n"
              << "  Batch size:    " << BATCH_SIZE << "\n";

    // 4) Launch threads
    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    for (unsigned int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker_thread, i, num_threads, start_pubkey);
    }

    // 5) Join threads
    for (auto &th : threads) {
        th.join();
    }

    std::cout << "Done.\n";
    // Cleanup
    if (g_ctx) {
        secp256k1_context_destroy(g_ctx);
        g_ctx = nullptr;
    }

    return 0;
}
