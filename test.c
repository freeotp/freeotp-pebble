#include "src/hash/hmac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct {
  hash_type type;
  const char *input;
  const char *output;
} tests[] = {
  { HASH_TYPE_MD5,
      "",
      "d41d8cd98f00b204e9800998ecf8427e" },
  { HASH_TYPE_MD5,
      "a",
      "0cc175b9c0f1b6a831c399e269772661" },
  { HASH_TYPE_MD5,
      "abc",
      "900150983cd24fb0d6963f7d28e17f72" },
  { HASH_TYPE_MD5,
      "message digest",
      "f96b697d7cb7938d525a2f31aaf161d0" },
  { HASH_TYPE_MD5,
      "abcdefghijklmnopqrstuvwxyz",
      "c3fcd3d76192e4007dfb496cca67e13b" },
  { HASH_TYPE_MD5,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "d174ab98d277d9f5a5611c2c9f419d9f" },
  { HASH_TYPE_MD5,
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a" },
  { HASH_TYPE_MD5,
      NULL,
      "7707d6ae4e027c70eea2a935c2296f21" },

  { HASH_TYPE_SHA1,
      "abc",
      "a9993e364706816aba3e25717850c26c9cd0d89d" },
  { HASH_TYPE_SHA1,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
  { HASH_TYPE_SHA1,
      NULL,
      "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },

  { HASH_TYPE_SHA224,
      "abc",
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
  { HASH_TYPE_SHA224,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
  { HASH_TYPE_SHA224,
      NULL,
      "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67" },

  { HASH_TYPE_SHA256,
      "abc",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  { HASH_TYPE_SHA256,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
  { HASH_TYPE_SHA256,
      NULL,
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },

  { HASH_TYPE_SHA384,
      "abc",
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
  { HASH_TYPE_SHA384,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },
  { HASH_TYPE_SHA384,
      NULL,
      "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985" },

  { HASH_TYPE_SHA512,
      "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
  { HASH_TYPE_SHA512,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
  { HASH_TYPE_SHA512,
      NULL,
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" },
  {}
};

struct {
  hash_type type;
  const char *key;
  const char *message;
  const char *output;
} hmac_tests[] = {
  { HASH_TYPE_MD5, "", "",
      "74e6f7298a9c2d168935f58c001bad88" },
  { HASH_TYPE_MD5, "key",
      "The quick brown fox jumps over the lazy dog",
      "80070713463e7749b90c2dc24911e275" },

  { HASH_TYPE_SHA1, "", "",
      "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d" },
  { HASH_TYPE_SHA1, "key",
      "The quick brown fox jumps over the lazy dog",
      "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" },

  { HASH_TYPE_SHA256, "", "",
      "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad" },
  { HASH_TYPE_SHA256, "key",
      "The quick brown fox jumps over the lazy dog",
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" },

  {}
};

static char a[1000000];

bool
test_hash(__typeof__(*tests) *test)
{
  const hash_spec *spec = hash_spec_get(test->type);
  hash_ctx *ctx = alloca(spec->ctx);
  char hex[spec->hash * 2 + 1];
  uint8_t hash[spec->hash];

  spec->init(ctx);
  if (test->input)
    spec->update(ctx, test->input, strlen(test->input));
  else
    spec->update(ctx, a, sizeof(a));
  spec->finish(ctx, hash);
  memset(hex, 0, sizeof(hex));
  hash_to_hex(hash, sizeof(hash), hex);

  if (strcmp(hex, test->output) != 0) {
    fprintf(stderr, "%12s: %s\n", hash_type_name(test->type), test->input);
    fprintf(stderr, "%12s: %s\n", "Expected", test->output);
    fprintf(stderr, "%12s: %s\n\n", "Received", hex);
    return false;
  }

  return true;
}

bool
test_hmac(__typeof__(*hmac_tests) *test)
{
  uint8_t *hash;
  size_t len;

  if (!hmac(test->type,
            test->key, strlen(test->key),
            test->message, strlen(test->message),
            &hash, &len))
    return false;

  char hex[len * 2 + 1];
  memset(hex, 0, sizeof(hex));
  hash_to_hex(hash, len, hex);
  free(hash);

  if (strcmp(hex, test->output) != 0) {
    fprintf(stderr, "%12s: '%s' / '%s'\n",
            hash_type_name(test->type),
            test->key, test->message);
    fprintf(stderr, "%12s: %s\n", "Expected", test->output);
    fprintf(stderr, "%12s: %s\n\n", "Received", hex);
    return false;
  }

  return true;
}

int
main()
{
  int ret = 0;

  memset(a, 'a', sizeof(a));

  for (size_t i = 0; tests[i].output; i++)
    if (!test_hash(&tests[i]))
      ret++;

  for (size_t i = 0; hmac_tests[i].output; i++)
    if (!test_hmac(&hmac_tests[i]))
      ret++;

  return ret;
}
