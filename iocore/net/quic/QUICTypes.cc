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

#include <algorithm>
#include "QUICTypes.h"
#include "QUICIntUtil.h"
#include "tscore/CryptoHash.h"
#include "I_EventSystem.h"
#include <openssl/hmac.h>

uint8_t QUICConnectionId::SCID_LEN = 0;

// TODO: move to somewhere in lib/ts/
int
to_hex_str(char *dst, size_t dst_len, const uint8_t *src, size_t src_len)
{
  if (dst_len < src_len * 2 + 1) {
    return -1;
  }

  static char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (size_t i = 0; i < src_len; ++i) {
    *dst       = hex_digits[src[i] >> 4];
    *(dst + 1) = hex_digits[src[i] & 0xf];
    dst += 2;
  }
  *dst = '\0';

  return 0;
}

bool
QUICTypeUtil::is_supported_version(QUICVersion version)
{
  for (auto v : QUIC_SUPPORTED_VERSIONS) {
    if (v == version) {
      return true;
    }
  }
  return false;
}

QUICStreamType
QUICTypeUtil::detect_stream_type(QUICStreamId id)
{
  uint8_t type = (id & 0x03);
  return static_cast<QUICStreamType>(type);
}

QUICEncryptionLevel
QUICTypeUtil::encryption_level(QUICPacketType type)
{
  switch (type) {
  case QUICPacketType::INITIAL:
    return QUICEncryptionLevel::INITIAL;
  case QUICPacketType::ZERO_RTT_PROTECTED:
    return QUICEncryptionLevel::ZERO_RTT;
  case QUICPacketType::HANDSHAKE:
    return QUICEncryptionLevel::HANDSHAKE;
  case QUICPacketType::PROTECTED:
    return QUICEncryptionLevel::ONE_RTT;
  default:
    ink_assert(false);
    return QUICEncryptionLevel::NONE;
  }
}

QUICPacketType
QUICTypeUtil::packet_type(QUICEncryptionLevel level)
{
  switch (level) {
  case QUICEncryptionLevel::INITIAL:
    return QUICPacketType::INITIAL;
  case QUICEncryptionLevel::ZERO_RTT:
    return QUICPacketType::ZERO_RTT_PROTECTED;
  case QUICEncryptionLevel::HANDSHAKE:
    return QUICPacketType::HANDSHAKE;
  case QUICEncryptionLevel::ONE_RTT:
    return QUICPacketType::PROTECTED;
  default:
    ink_assert(false);
    return QUICPacketType::UNINITIALIZED;
  }
}

// TODO: clarify QUICKeyPhase and QUICEncryptionlevel mapping
QUICKeyPhase
QUICTypeUtil::key_phase(QUICPacketType type)
{
  switch (type) {
  case QUICPacketType::INITIAL:
    return QUICKeyPhase::INITIAL;
  case QUICPacketType::ZERO_RTT_PROTECTED:
    return QUICKeyPhase::ZERO_RTT;
  case QUICPacketType::HANDSHAKE:
    return QUICKeyPhase::HANDSHAKE;
  case QUICPacketType::PROTECTED:
    // XXX assuming Long Header Packet
    return QUICKeyPhase::PHASE_0;
  default:
    return QUICKeyPhase::INITIAL;
  }
}

// 0-RTT and 1-RTT use same Packet Number Space
int
QUICTypeUtil::pn_space_index(QUICEncryptionLevel level)
{
  if (level == QUICEncryptionLevel::ONE_RTT) {
    level = QUICEncryptionLevel::ZERO_RTT;
  }

  return static_cast<int>(level);
}

QUICConnectionId
QUICTypeUtil::read_QUICConnectionId(const uint8_t *buf, uint8_t len)
{
  return {buf, len};
}

int
QUICTypeUtil::read_QUICPacketNumberLen(const uint8_t *buf)
{
  return (buf[0] & 0x03) + 1;
}

void
QUICTypeUtil::write_QUICPacketNumberLen(int len, uint8_t *buf)
{
  buf[0] |= len - 1;
}

QUICPacketNumber
QUICTypeUtil::read_QUICPacketNumber(const uint8_t *buf, int encoded_length)
{
  return QUICIntUtil::read_nbytes_as_uint(buf, encoded_length);
}

QUICVersion
QUICTypeUtil::read_QUICVersion(const uint8_t *buf)
{
  return static_cast<QUICVersion>(QUICIntUtil::read_nbytes_as_uint(buf, 4));
}

QUICStreamId
QUICTypeUtil::read_QUICStreamId(const uint8_t *buf)
{
  return static_cast<QUICStreamId>(QUICIntUtil::read_QUICVariableInt(buf));
}

QUICOffset
QUICTypeUtil::read_QUICOffset(const uint8_t *buf)
{
  return static_cast<QUICOffset>(QUICIntUtil::read_QUICVariableInt(buf));
}

uint16_t
QUICTypeUtil::read_QUICTransErrorCode(const uint8_t *buf)
{
  return QUICIntUtil::read_nbytes_as_uint(buf, 2);
}

QUICAppErrorCode
QUICTypeUtil::read_QUICAppErrorCode(const uint8_t *buf)
{
  return static_cast<QUICAppErrorCode>(QUICIntUtil::read_nbytes_as_uint(buf, 2));
}

uint64_t
QUICTypeUtil::read_QUICMaxData(const uint8_t *buf)
{
  return QUICIntUtil::read_QUICVariableInt(buf);
}

void
QUICTypeUtil::write_QUICConnectionId(QUICConnectionId connection_id, uint8_t *buf, size_t *len)
{
  memcpy(buf, connection_id, connection_id.length());
  *len = connection_id.length();
}

void
QUICTypeUtil::write_QUICPacketNumber(QUICPacketNumber packet_number, uint8_t n, uint8_t *buf, size_t *len)
{
  uint64_t pn = static_cast<uint64_t>(packet_number);
  QUICIntUtil::write_uint_as_nbytes(static_cast<uint64_t>(pn), n, buf, len);
}

void
QUICTypeUtil::write_QUICVersion(QUICVersion version, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_uint_as_nbytes(static_cast<uint64_t>(version), 4, buf, len);
}

void
QUICTypeUtil::write_QUICStreamId(QUICStreamId stream_id, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_QUICVariableInt(stream_id, buf, len);
}

void
QUICTypeUtil::write_QUICOffset(QUICOffset offset, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_QUICVariableInt(offset, buf, len);
}

void
QUICTypeUtil::write_QUICTransErrorCode(uint16_t error_code, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_uint_as_nbytes(static_cast<uint64_t>(error_code), 2, buf, len);
}

void
QUICTypeUtil::write_QUICAppErrorCode(QUICAppErrorCode error_code, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_uint_as_nbytes(static_cast<uint64_t>(error_code), 2, buf, len);
}

void
QUICTypeUtil::write_QUICMaxData(uint64_t max_data, uint8_t *buf, size_t *len)
{
  QUICIntUtil::write_QUICVariableInt(max_data, buf, len);
}

QUICStatelessResetToken::QUICStatelessResetToken(QUICConnectionId conn_id, uint32_t instance_id)
{
  uint64_t data = conn_id ^ instance_id;
  CryptoHash _hash;
  static constexpr char STATELESS_RESET_TOKEN_KEY[] = "stateless_token_reset_key";
  CryptoContext ctx;
  ctx.update(STATELESS_RESET_TOKEN_KEY, strlen(STATELESS_RESET_TOKEN_KEY));
  ctx.update(reinterpret_cast<void *>(&data), 8);
  ctx.finalize(_hash);

  size_t dummy;
  QUICIntUtil::write_uint_as_nbytes(_hash.u64[0], 8, _token, &dummy);
  QUICIntUtil::write_uint_as_nbytes(_hash.u64[1], 8, _token + 8, &dummy);
}

QUICResumptionToken::QUICResumptionToken(const IpEndpoint &src, QUICConnectionId cid, ink_hrtime expire_time)
{
  // TODO: read cookie secret from file like SSLTicketKeyConfig
  static constexpr char stateless_retry_token_secret[] = "stateless_cookie_secret";
  size_t dummy;

  uint8_t data[1 + INET6_ADDRPORTSTRLEN + QUICConnectionId::MAX_LENGTH + 4] = {0};
  size_t data_len                                                           = 0;
  ats_ip_nptop(src, reinterpret_cast<char *>(data), sizeof(data));
  data_len = strlen(reinterpret_cast<char *>(data));

  size_t cid_len;
  QUICTypeUtil::write_QUICConnectionId(cid, data + data_len, &cid_len);
  data_len += cid_len;

  QUICIntUtil::write_uint_as_nbytes(expire_time >> 30, 4, data + data_len, &dummy);
  data_len += 4;

  this->_token[0] = static_cast<uint8_t>(Type::RESUMPTION);
  HMAC(EVP_sha1(), stateless_retry_token_secret, sizeof(stateless_retry_token_secret), data, data_len, this->_token + 1,
       &this->_token_len);
  ink_assert(this->_token_len == 20);
  this->_token_len += 1;

  QUICIntUtil::write_uint_as_nbytes(expire_time >> 30, 4, this->_token + this->_token_len, &dummy);
  this->_token_len += 4;

  QUICTypeUtil::write_QUICConnectionId(cid, this->_token + this->_token_len, &cid_len);
  this->_token_len += cid_len;
}

bool
QUICResumptionToken::is_valid(const IpEndpoint &src) const
{
  QUICResumptionToken x(src, this->cid(), this->expire_time() << 30);
  return *this == x && this->expire_time() >= (Thread::get_hrtime() >> 30);
}

const QUICConnectionId
QUICResumptionToken::cid() const
{
  // Type uses 1 byte and output of EVP_sha1() should be 160 bits
  return QUICTypeUtil::read_QUICConnectionId(this->_token + (1 + 20 + 4), this->_token_len - (1 + 20 + 4));
}

const ink_hrtime
QUICResumptionToken::expire_time() const
{
  return QUICIntUtil::read_nbytes_as_uint(this->_token + (1 + 20), 4);
}

QUICRetryToken::QUICRetryToken(const IpEndpoint &src, QUICConnectionId original_dcid)
{
  // TODO: read cookie secret from file like SSLTicketKeyConfig
  static constexpr char stateless_retry_token_secret[] = "stateless_cookie_secret";

  uint8_t data[1 + INET6_ADDRPORTSTRLEN + QUICConnectionId::MAX_LENGTH] = {0};
  size_t data_len                                                       = 0;
  ats_ip_nptop(src, reinterpret_cast<char *>(data), sizeof(data));
  data_len = strlen(reinterpret_cast<char *>(data));

  size_t cid_len;
  QUICTypeUtil::write_QUICConnectionId(original_dcid, data + data_len, &cid_len);
  data_len += cid_len;

  this->_token[0] = static_cast<uint8_t>(Type::RETRY);
  HMAC(EVP_sha1(), stateless_retry_token_secret, sizeof(stateless_retry_token_secret), data, data_len, this->_token + 1,
       &this->_token_len);
  ink_assert(this->_token_len == 20);
  this->_token_len += 1;

  QUICTypeUtil::write_QUICConnectionId(original_dcid, this->_token + this->_token_len, &cid_len);
  this->_token_len += cid_len;
}

bool
QUICRetryToken::is_valid(const IpEndpoint &src) const
{
  return *this == QUICRetryToken(src, this->original_dcid());
}

const QUICConnectionId
QUICRetryToken::original_dcid() const
{
  // Type uses 1 byte and output of EVP_sha1() should be 160 bits
  return QUICTypeUtil::read_QUICConnectionId(this->_token + (1 + 20), this->_token_len - (1 + 20));
}

QUICFrameType
QUICConnectionError::frame_type() const
{
  ink_assert(this->cls != QUICErrorClass::APPLICATION);
  return _frame_type;
}

//
// QUICPreferredAddress
//

QUICPreferredAddress::QUICPreferredAddress(const uint8_t *buf, uint16_t len)
{
  if (len < QUICPreferredAddress::MIN_LEN || buf == nullptr) {
    return;
  }

  const uint8_t *p = buf;

  // ipv4Address
  in_addr_t addr_ipv4;
  memcpy(&addr_ipv4, p, 4);
  p += 4;

  // ipv4Port
  in_port_t port_ipv4;
  memcpy(&port_ipv4, p, 2);
  p += 2;

  ats_ip4_set(&this->_endpoint_ipv4, addr_ipv4, port_ipv4);

  // ipv6Address
  in6_addr addr_ipv6;
  memcpy(&addr_ipv6, p, 16);
  p += TS_IP6_SIZE;

  // ipv6Port
  in_port_t port_ipv6;
  memcpy(&port_ipv6, p, 2);
  p += 2;

  ats_ip6_set(&this->_endpoint_ipv6, addr_ipv6, port_ipv6);

  // CID
  uint16_t cid_len = QUICIntUtil::read_nbytes_as_uint(p, 1);
  p += 1;
  this->_cid = QUICTypeUtil::read_QUICConnectionId(p, cid_len);
  p += cid_len;

  // Token
  this->_token = {p};

  this->_valid = true;
}

bool
QUICPreferredAddress::is_available() const
{
  return this->_valid;
}

bool
QUICPreferredAddress::has_ipv4() const
{
  return this->_endpoint_ipv4.isValid();
}

bool
QUICPreferredAddress::has_ipv6() const
{
  return this->_endpoint_ipv6.isValid();
}

const IpEndpoint
QUICPreferredAddress::endpoint_ipv4() const
{
  return this->_endpoint_ipv4;
}

const IpEndpoint
QUICPreferredAddress::endpoint_ipv6() const
{
  return this->_endpoint_ipv6;
}

const QUICConnectionId
QUICPreferredAddress::cid() const
{
  return this->_cid;
}

const QUICStatelessResetToken
QUICPreferredAddress::token() const
{
  return this->_token;
}

void
QUICPreferredAddress::store(uint8_t *buf, uint16_t &len) const
{
  size_t dummy;
  uint8_t *p = buf;

  if (this->_endpoint_ipv4.isValid()) {
    // ipv4Address
    memcpy(p, &ats_ip4_addr_cast(this->_endpoint_ipv4), 4);
    p += 4;

    // ipv4Port
    memcpy(p, &ats_ip_port_cast(this->_endpoint_ipv4), 2);
    p += 2;
  } else {
    memset(p, 0, 6);
    p += 6;
  }

  if (this->_endpoint_ipv6.isValid()) {
    // ipv6Address
    memcpy(p, &ats_ip6_addr_cast(this->_endpoint_ipv6), 16);
    p += 16;

    // ipv6Port
    memcpy(p, &ats_ip_port_cast(this->_endpoint_ipv6), 2);
    p += 2;
  } else {
    memset(p, 0, 18);
    p += 18;
  }

  // CID
  uint8_t cid_len = this->_cid.length();
  p[0]            = cid_len;
  p += 1;
  QUICTypeUtil::write_QUICConnectionId(this->_cid, p, &dummy);
  p += cid_len;

  // Token
  memcpy(p, this->_token.buf(), 16);
  p += 16;

  len = p - buf;
}

//
// QUICFiveTuple
//
QUICFiveTuple::QUICFiveTuple(IpEndpoint src, IpEndpoint dst, int protocol) : _source(src), _destination(dst), _protocol(protocol)
{
  // FIXME Generate a hash code
  this->_hash_code = src.port() + dst.port() + protocol;
}
void
QUICFiveTuple::update(IpEndpoint src, IpEndpoint dst, int protocol)
{
  this->_source      = src;
  this->_destination = dst;
  this->_protocol    = protocol;

  // FIXME Generate a hash code
  this->_hash_code = src.port() + dst.port() + protocol;
}

IpEndpoint
QUICFiveTuple::source() const
{
  return this->_source;
}

IpEndpoint
QUICFiveTuple::destination() const
{
  return this->_destination;
}

int
QUICFiveTuple::protocol() const
{
  return this->_protocol;
}

//
// QUICConnectionId
//
QUICConnectionId
QUICConnectionId::ZERO()
{
  uint8_t zero[MAX_LENGTH] = {0};
  return QUICConnectionId(zero, sizeof(zero));
}

QUICConnectionId::QUICConnectionId()
{
  this->randomize();
}

QUICConnectionId::QUICConnectionId(const uint8_t *buf, uint8_t len) : _len(len)
{
  memcpy(this->_id, buf, len);
}

uint8_t
QUICConnectionId::length() const
{
  return this->_len;
}

bool
QUICConnectionId::is_zero() const
{
  for (int i = sizeof(this->_id) - 1; i >= 0; --i) {
    if (this->_id[i]) {
      return false;
    }
  }
  return true;
}

void
QUICConnectionId::randomize()
{
  std::random_device rnd;
  uint32_t x = rnd();
  for (int i = QUICConnectionId::SCID_LEN - 1; i >= 0; --i) {
    if (i % 4 == 0) {
      x = rnd();
    }
    this->_id[i] = (x >> (8 * (i % 4))) & 0xFF;
  }
  this->_len = QUICConnectionId::SCID_LEN;
}

uint64_t
QUICConnectionId::_hashcode() const
{
  return (static_cast<uint64_t>(this->_id[0]) << 56) + (static_cast<uint64_t>(this->_id[1]) << 48) +
         (static_cast<uint64_t>(this->_id[2]) << 40) + (static_cast<uint64_t>(this->_id[3]) << 32) + (this->_id[4] << 24) +
         (this->_id[5] << 16) + (this->_id[6] << 8) + this->_id[7];
}

uint32_t
QUICConnectionId::h32() const
{
  return static_cast<uint32_t>(QUICIntUtil::read_nbytes_as_uint(this->_id, 4));
}

int
QUICConnectionId::hex(char *buf, size_t len) const
{
  return to_hex_str(buf, len, this->_id, this->_len);
}

//
// QUICInvariants
//
bool
QUICInvariants::is_long_header(const uint8_t *buf)
{
  return (buf[0] & 0x80) != 0;
}

bool
QUICInvariants::is_version_negotiation(QUICVersion v)
{
  return v == 0x0;
}

bool
QUICInvariants::version(QUICVersion &dst, const uint8_t *buf, uint64_t buf_len)
{
  if (!QUICInvariants::is_long_header(buf) || buf_len < QUICInvariants::LH_CIL_OFFSET) {
    return false;
  }

  dst = QUICTypeUtil::read_QUICVersion(buf + QUICInvariants::LH_VERSION_OFFSET);

  return true;
}

bool
QUICInvariants::dcil(uint8_t &dst, const uint8_t *buf, uint64_t buf_len)
{
  ink_assert(QUICInvariants::is_long_header(buf));

  if (buf_len < QUICInvariants::LH_CIL_OFFSET) {
    return false;
  }

  dst = buf[QUICInvariants::LH_CIL_OFFSET] >> 4;

  return true;
}

bool
QUICInvariants::scil(uint8_t &dst, const uint8_t *buf, uint64_t buf_len)
{
  ink_assert(QUICInvariants::is_long_header(buf));

  if (buf_len < QUICInvariants::LH_CIL_OFFSET) {
    return false;
  }

  dst = buf[QUICInvariants::LH_CIL_OFFSET] & 0x0F;

  return true;
}

bool
QUICInvariants::dcid(QUICConnectionId &dst, const uint8_t *buf, uint64_t buf_len)
{
  uint8_t dcid_offset = 0;
  uint8_t dcid_len    = 0;

  if (QUICInvariants::is_long_header(buf)) {
    uint8_t dcil = 0;
    if (!QUICInvariants::dcil(dcil, buf, buf_len)) {
      return false;
    }

    if (dcil) {
      dcid_len = dcil + QUICInvariants::CIL_BASE;
    } else {
      dst = QUICConnectionId::ZERO();
      return true;
    }

    dcid_offset = QUICInvariants::LH_DCID_OFFSET;
  } else {
    // remote dcil is local scil
    dcid_len    = QUICConnectionId::SCID_LEN;
    dcid_offset = QUICInvariants::SH_DCID_OFFSET;
  }

  if (dcid_offset + dcid_len > buf_len) {
    return false;
  }

  dst = QUICTypeUtil::read_QUICConnectionId(buf + dcid_offset, dcid_len);

  return true;
}

bool
QUICInvariants::scid(QUICConnectionId &dst, const uint8_t *buf, uint64_t buf_len)
{
  ink_assert(QUICInvariants::is_long_header(buf));

  if (buf_len < QUICInvariants::LH_CIL_OFFSET) {
    return false;
  }

  uint8_t scid_offset = QUICInvariants::LH_DCID_OFFSET;
  uint8_t scid_len    = 0;

  uint8_t dcil = 0;
  if (!QUICInvariants::dcil(dcil, buf, buf_len)) {
    return false;
  }

  if (dcil) {
    scid_offset += (dcil + QUICInvariants::CIL_BASE);
  }

  uint8_t scil = 0;
  if (!QUICInvariants::scil(scil, buf, buf_len)) {
    return false;
  }

  if (scil) {
    scid_len = scil + QUICInvariants::CIL_BASE;
  } else {
    dst = QUICConnectionId::ZERO();
    return true;
  }

  if (scid_offset + scid_len > buf_len) {
    return false;
  }

  dst = QUICTypeUtil::read_QUICConnectionId(buf + scid_offset, scid_len);

  return true;
}
