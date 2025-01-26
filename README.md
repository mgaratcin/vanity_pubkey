Usage requires libsecp256k1 and OpenSSL isntalls.

sudo apt-get install libssl-dev

sudo apt-get update
sudo apt-get install git automake libtool pkg-config build-essential

git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery # Recovery is optional, but often useful
make
sudo make install

# Generic Information

libsecp256k1 Context

We create a global secp256k1 context (g_ctx) for all threads to share.

Parse the Starting Compressed Pubkey

We convert the hex string (e.g. "0345f3...") into 33 bytes and call secp256k1_ec_pubkey_parse.

Thread Start Points

The main point is 𝑃 Each thread 𝑖 starts at 𝑃 + 𝑖 ⋅ 𝐺 We do this by calling secp256k1_ec_pubkey_tweak_add with a tweak that represents integer i.

Iteration

On each loop, the thread serializes the current point to a 33‐byte compressed form, does HASH160 on it, and checks the hex prefix.
If it doesn’t match, it adds NUM_THREADS ⋅ 𝐺 to jump to the next candidate for that thread.

Stop Condition

We have a global atomic boolean g_found. If any thread finds a match, it sets g_found = true.
All other threads will see that and stop looping.
