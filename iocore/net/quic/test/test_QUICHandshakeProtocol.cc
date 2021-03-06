/** @file
 *
 *  A brief file description
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "catch.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/base.h>
#endif

#include <openssl/ssl.h>

// #include "Mock.h"
#include "QUICPacketHeaderProtector.h"
#include "QUICPacketPayloadProtector.h"
#include "QUICPacketProtectionKeyInfo.h"
#include "QUICTLS.h"

// depends on size of cert
static constexpr uint32_t MAX_HANDSHAKE_MSG_LEN = 8192;

#include "./server_cert.h"

static void
print_hex(const uint8_t *v, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(v[i]) << " ";

    if (i != 0 && (i + 1) % 32 == 0 && i != len - 1) {
      std::cout << std::endl;
    }
  }

  std::cout << std::endl;

  return;
}

static const uint8_t original[] = {
  0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x20, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x20, 0x53,
  0x65, 0x72, 0x76, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint64_t pkt_num = 0x123456789;
static const uint8_t ad[]     = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

TEST_CASE("QUICHandshakeProtocol")
{
  // Client
  SSL_CTX *client_ssl_ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(client_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(client_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_clear_options(client_ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#ifdef SSL_MODE_QUIC_HACK
  SSL_CTX_set_mode(client_ssl_ctx, SSL_MODE_QUIC_HACK);
#endif

  // Server
  SSL_CTX *server_ssl_ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(server_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(server_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_clear_options(server_ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#ifdef SSL_MODE_QUIC_HACK
  SSL_CTX_set_mode(server_ssl_ctx, SSL_MODE_QUIC_HACK);
#endif
  BIO *crt_bio(BIO_new_mem_buf(server_crt, sizeof(server_crt)));
  X509 *x509 = PEM_read_bio_X509(crt_bio, nullptr, nullptr, nullptr);
  SSL_CTX_use_certificate(server_ssl_ctx, x509);
  BIO *key_bio(BIO_new_mem_buf(server_key, sizeof(server_key)));
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
  SSL_CTX_use_PrivateKey(server_ssl_ctx, pkey);

  SECTION("Full Handshake", "[quic]")
  {
    QUICPacketProtectionKeyInfo pp_key_info_client;
    QUICPacketProtectionKeyInfo pp_key_info_server;
    QUICHandshakeProtocol *client = new QUICTLS(pp_key_info_client, client_ssl_ctx, NET_VCONNECTION_OUT);
    QUICHandshakeProtocol *server = new QUICTLS(pp_key_info_server, server_ssl_ctx, NET_VCONNECTION_IN);
    QUICPacketPayloadProtector ppp_client(pp_key_info_client);
    QUICPacketPayloadProtector ppp_server(pp_key_info_server);

    CHECK(client->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));
    CHECK(server->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));

    // CH
    QUICHandshakeMsgs msg1;
    uint8_t msg1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg1.buf                                = msg1_buf;
    msg1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(client->handshake(&msg1, nullptr) == 1);
    std::cout << "### Messages from client" << std::endl;
    print_hex(msg1.buf, msg1.offsets[4]);

    // SH, EE, CERT, CV, FIN
    QUICHandshakeMsgs msg2;
    uint8_t msg2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2.buf                                = msg2_buf;
    msg2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg2, &msg1) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg2.buf, msg2.offsets[4]);

    // FIN
    QUICHandshakeMsgs msg3;
    uint8_t msg3_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg3.buf                                = msg3_buf;
    msg3.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

#ifdef SSL_MODE_QUIC_HACK
    // -- Hacks for OpenSSL with SSL_MODE_QUIC_HACK --
    // SH
    QUICHandshakeMsgs msg2_1;
    uint8_t msg2_1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2_1.buf                                = msg2_1_buf;
    msg2_1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    memcpy(msg2_1.buf, msg2.buf, msg2.offsets[1]);
    msg2_1.offsets[0] = 0;
    msg2_1.offsets[1] = msg2.offsets[1];
    msg2_1.offsets[2] = msg2.offsets[1];
    msg2_1.offsets[3] = msg2.offsets[1];
    msg2_1.offsets[4] = msg2.offsets[1];

    // EE - FIN
    QUICHandshakeMsgs msg2_2;
    uint8_t msg2_2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2_2.buf                                = msg2_2_buf;
    msg2_2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    size_t len = msg2.offsets[3] - msg2.offsets[2];
    memcpy(msg2_2.buf, msg2.buf + msg2.offsets[1], len);
    msg2_2.offsets[0] = 0;
    msg2_2.offsets[1] = 0;
    msg2_2.offsets[2] = 0;
    msg2_2.offsets[3] = len;
    msg2_2.offsets[4] = len;

    REQUIRE(client->handshake(&msg3, &msg2_1) == 1);
    REQUIRE(client->handshake(&msg3, &msg2_2) == 1);
#else
    REQUIRE(client->handshake(&msg3, &msg2) == 1);
#endif
    std::cout << "### Messages from client" << std::endl;
    print_hex(msg3.buf, msg3.offsets[4]);

    // NS
    QUICHandshakeMsgs msg4;
    uint8_t msg4_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg4.buf                                = msg4_buf;
    msg4.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg4, &msg3) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg4.buf, msg4.offsets[4]);

    QUICHandshakeMsgs msg5;
    uint8_t msg5_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg5.buf                                = msg5_buf;
    msg5.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;
    REQUIRE(client->handshake(&msg5, &msg4) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg4.buf, msg4.offsets[4]);

    // encrypt - decrypt
    // client (encrypt) - server (decrypt)
    std::cout << "### Original Text" << std::endl;
    print_hex(original, sizeof(original));

    Ptr<IOBufferBlock> original_ibb = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    original_ibb->set_internal(const_cast<uint8_t *>(original), sizeof(original), BUFFER_SIZE_NOT_ALLOCATED);
    Ptr<IOBufferBlock> header_ibb = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    header_ibb->set_internal(const_cast<uint8_t *>(ad), sizeof(ad), BUFFER_SIZE_NOT_ALLOCATED);
    Ptr<IOBufferBlock> cipher = ppp_client.protect(header_ibb, original_ibb, pkt_num, QUICKeyPhase::PHASE_0);
    CHECK(cipher);

    std::cout << "### Encrypted Text" << std::endl;
    print_hex(reinterpret_cast<uint8_t *>(cipher->buf()), cipher->size());

    Ptr<IOBufferBlock> plain = ppp_server.unprotect(header_ibb, cipher, pkt_num, QUICKeyPhase::PHASE_0);
    CHECK(plain);

    std::cout << "### Decrypted Text" << std::endl;
    print_hex(reinterpret_cast<uint8_t *>(plain->buf()), plain->size());

    CHECK(sizeof(original) == (plain->size()));
    CHECK(memcmp(original, plain->buf(), plain->size()) == 0);

    // Teardown
    delete client;
    delete server;
  }

  SECTION("Full Handshake with HRR", "[quic]")
  {
    // client key_share will be X25519 (default of OpenSSL)
    if (SSL_CTX_set1_groups_list(server_ssl_ctx, "P-521:P-384:P-256") != 1) {
      REQUIRE(false);
    }

    QUICPacketProtectionKeyInfo pp_key_info_client;
    QUICPacketProtectionKeyInfo pp_key_info_server;
    QUICHandshakeProtocol *client = new QUICTLS(pp_key_info_client, client_ssl_ctx, NET_VCONNECTION_OUT);
    QUICHandshakeProtocol *server = new QUICTLS(pp_key_info_server, server_ssl_ctx, NET_VCONNECTION_IN);
    QUICPacketPayloadProtector ppp_client(pp_key_info_client);
    QUICPacketPayloadProtector ppp_server(pp_key_info_server);

    CHECK(client->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));
    CHECK(server->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));

    // CH
    QUICHandshakeMsgs msg1;
    uint8_t msg1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg1.buf                                = msg1_buf;
    msg1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(client->handshake(&msg1, nullptr) == 1);
    std::cout << "### Messages from client" << std::endl;
    print_hex(msg1.buf, msg1.offsets[4]);

    // HRR
    QUICHandshakeMsgs msg2;
    uint8_t msg2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2.buf                                = msg2_buf;
    msg2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg2, &msg1) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg2.buf, msg2.offsets[4]);

    // CH
    QUICHandshakeMsgs msg3;
    uint8_t msg3_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg3.buf                                = msg3_buf;
    msg3.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(client->handshake(&msg3, &msg2) == 1);
    std::cout << "### Messages from client" << std::endl;
    print_hex(msg3.buf, msg3.offsets[4]);

    // SH, EE, CERT, CV, FIN
    QUICHandshakeMsgs msg4;
    uint8_t msg4_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg4.buf                                = msg4_buf;
    msg4.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg4, &msg3) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg4.buf, msg4.offsets[4]);

    // FIN
    QUICHandshakeMsgs msg5;
    uint8_t msg5_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg5.buf                                = msg5_buf;
    msg5.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

#ifdef SSL_MODE_QUIC_HACK
    // -- Hacks for OpenSSL with SSL_MODE_QUIC_HACK --
    // SH
    QUICHandshakeMsgs msg4_1;
    uint8_t msg4_1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg4_1.buf                                = msg4_1_buf;
    msg4_1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    memcpy(msg4_1.buf, msg4.buf, msg4.offsets[1]);
    msg4_1.offsets[0] = 0;
    msg4_1.offsets[1] = msg4.offsets[1];
    msg4_1.offsets[2] = msg4.offsets[1];
    msg4_1.offsets[3] = msg4.offsets[1];
    msg4_1.offsets[4] = msg4.offsets[1];

    // EE - FIN
    QUICHandshakeMsgs msg4_2;
    uint8_t msg4_2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg4_2.buf                                = msg4_2_buf;
    msg4_2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    size_t len = msg4.offsets[3] - msg4.offsets[2];
    memcpy(msg4_2.buf, msg4.buf + msg4.offsets[1], len);
    msg4_2.offsets[0] = 0;
    msg4_2.offsets[1] = 0;
    msg4_2.offsets[2] = 0;
    msg4_2.offsets[3] = len;
    msg4_2.offsets[4] = len;

    REQUIRE(client->handshake(&msg5, &msg4_1) == 1);
    REQUIRE(client->handshake(&msg5, &msg4_2) == 1);
#else
    REQUIRE(client->handshake(&msg5, &msg4) == 1);
#endif
    std::cout << "### Messages from client" << std::endl;
    print_hex(msg5.buf, msg5.offsets[4]);

    // NS
    QUICHandshakeMsgs msg6;
    uint8_t msg6_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg6.buf                                = msg6_buf;
    msg6.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg6, &msg5) == 1);
    std::cout << "### Messages from server" << std::endl;
    print_hex(msg6.buf, msg6.offsets[4]);

    Ptr<IOBufferBlock> original_ibb = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    original_ibb->set_internal(const_cast<uint8_t *>(original), sizeof(original), BUFFER_SIZE_NOT_ALLOCATED);
    Ptr<IOBufferBlock> header_ibb = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    header_ibb->set_internal(const_cast<uint8_t *>(ad), sizeof(ad), BUFFER_SIZE_NOT_ALLOCATED);

    // encrypt - decrypt
    // client (encrypt) - server (decrypt)
    std::cout << "### Original Text" << std::endl;
    print_hex(original, sizeof(original));

    Ptr<IOBufferBlock> cipher = ppp_client.protect(header_ibb, original_ibb, pkt_num, QUICKeyPhase::PHASE_0);
    CHECK(cipher);

    std::cout << "### Encrypted Text" << std::endl;
    print_hex(reinterpret_cast<uint8_t *>(cipher->buf()), cipher->size());

    Ptr<IOBufferBlock> plain = ppp_server.unprotect(header_ibb, cipher, pkt_num, QUICKeyPhase::PHASE_0);
    CHECK(plain);

    std::cout << "### Decrypted Text" << std::endl;
    print_hex(reinterpret_cast<uint8_t *>(plain->buf()), plain->size());

    CHECK(sizeof(original) == plain->size());
    CHECK(memcmp(original, plain->buf(), plain->size()) == 0);

    // Teardown
    // Make it back to the default settings
    if (SSL_CTX_set1_groups_list(server_ssl_ctx, "X25519:P-521:P-384:P-256") != 1) {
      REQUIRE(false);
    }

    delete client;
    delete server;
  }

  SECTION("Alert", "[quic]")
  {
    QUICPacketProtectionKeyInfo pp_key_info_server;
    QUICHandshakeProtocol *server = new QUICTLS(pp_key_info_server, server_ssl_ctx, NET_VCONNECTION_IN);
    CHECK(server->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));

    // Malformed CH (finished)
    uint8_t msg1_buf[] = {0x14, 0x00, 0x00, 0x30, 0x35, 0xb9, 0x82, 0x9d, 0xb9, 0x14, 0x70, 0x03, 0x60,
                          0xd2, 0x5a, 0x03, 0x12, 0x12, 0x3d, 0x17, 0xc2, 0x13, 0x8c, 0xd7, 0x8b, 0x6e,
                          0xc5, 0x4e, 0x50, 0x0a, 0x78, 0x6e, 0xa8, 0x54, 0x5f, 0x74, 0xfb, 0xf5, 0x6e,
                          0x09, 0x90, 0x07, 0x58, 0x5a, 0x30, 0x5a, 0xe9, 0xcb, 0x1b, 0xa0, 0x69, 0x35};
    size_t msg1_len    = sizeof(msg1_buf);

    QUICHandshakeMsgs msg1;
    msg1.buf         = msg1_buf;
    msg1.max_buf_len = MAX_HANDSHAKE_MSG_LEN;
    msg1.offsets[0]  = 0;
    msg1.offsets[1]  = msg1_len;
    msg1.offsets[2]  = msg1_len;
    msg1.offsets[3]  = msg1_len;
    msg1.offsets[4]  = msg1_len;

    QUICHandshakeMsgs msg2;
    uint8_t msg2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2.buf                                = msg2_buf;
    msg2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    CHECK(server->handshake(&msg2, &msg1) != 1);
    CHECK(msg2.error_code == 0x10a); //< 0x100 + unexpected_message(10)

    // Teardown
    delete server;
  }

  SECTION("Full Handshake + Packet Number Protection", "[quic]")
  {
    QUICPacketProtectionKeyInfo pp_key_info_client;
    QUICPacketProtectionKeyInfo pp_key_info_server;
    QUICHandshakeProtocol *client = new QUICTLS(pp_key_info_client, client_ssl_ctx, NET_VCONNECTION_OUT);
    QUICHandshakeProtocol *server = new QUICTLS(pp_key_info_server, server_ssl_ctx, NET_VCONNECTION_IN);

    CHECK(client->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));
    CHECK(server->initialize_key_materials({reinterpret_cast<const uint8_t *>("\x83\x94\xc8\xf0\x3e\x51\x57\x00"), 8}));

    // # Start Handshake

    // CH
    QUICHandshakeMsgs msg1;
    uint8_t msg1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg1.buf                                = msg1_buf;
    msg1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(client->handshake(&msg1, nullptr) == 1);

    // SH, EE, CERT, CV, FIN
    QUICHandshakeMsgs msg2;
    uint8_t msg2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2.buf                                = msg2_buf;
    msg2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg2, &msg1) == 1);

    // FIN
    QUICHandshakeMsgs msg3;
    uint8_t msg3_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg3.buf                                = msg3_buf;
    msg3.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

#ifdef SSL_MODE_QUIC_HACK
    // -- Hacks for OpenSSL with SSL_MODE_QUIC_HACK --
    // SH
    QUICHandshakeMsgs msg2_1;
    uint8_t msg2_1_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2_1.buf                                = msg2_1_buf;
    msg2_1.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    memcpy(msg2_1.buf, msg2.buf, msg2.offsets[1]);
    msg2_1.offsets[0] = 0;
    msg2_1.offsets[1] = msg2.offsets[1];
    msg2_1.offsets[2] = msg2.offsets[1];
    msg2_1.offsets[3] = msg2.offsets[1];
    msg2_1.offsets[4] = msg2.offsets[1];

    // EE - FIN
    QUICHandshakeMsgs msg2_2;
    uint8_t msg2_2_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg2_2.buf                                = msg2_2_buf;
    msg2_2.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    size_t len = msg2.offsets[3] - msg2.offsets[2];
    memcpy(msg2_2.buf, msg2.buf + msg2.offsets[1], len);
    msg2_2.offsets[0] = 0;
    msg2_2.offsets[1] = 0;
    msg2_2.offsets[2] = 0;
    msg2_2.offsets[3] = len;
    msg2_2.offsets[4] = len;

    REQUIRE(client->handshake(&msg3, &msg2_1) == 1);
    REQUIRE(client->handshake(&msg3, &msg2_2) == 1);
#else
    REQUIRE(client->handshake(&msg3, &msg2) == 1);
#endif

    // NS
    QUICHandshakeMsgs msg4;
    uint8_t msg4_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg4.buf                                = msg4_buf;
    msg4.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;

    REQUIRE(server->handshake(&msg4, &msg3) == 1);

    QUICHandshakeMsgs msg5;
    uint8_t msg5_buf[MAX_HANDSHAKE_MSG_LEN] = {0};
    msg5.buf                                = msg5_buf;
    msg5.max_buf_len                        = MAX_HANDSHAKE_MSG_LEN;
    REQUIRE(client->handshake(&msg5, &msg4) == 1);

    // # End Handshake

    // Teardown
    delete client;
    delete server;
  }

  BIO_free(crt_bio);
  BIO_free(key_bio);

  X509_free(x509);
  EVP_PKEY_free(pkey);

  SSL_CTX_free(server_ssl_ctx);
  SSL_CTX_free(client_ssl_ctx);
}
