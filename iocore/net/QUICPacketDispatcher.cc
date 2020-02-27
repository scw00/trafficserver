
#include "QUICPacketDispatcher.h"
#include "quic/QUICPacketFactory.h"
#include "UDPProcessor.h"
#include "P_QUICNetProcessor.h"

static constexpr char debug_tag[] = "quic_dispatcher";

#define QUICDebugDS(dcid, scid, fmt, ...) \
  Debug(debug_tag, "[%08" PRIx32 "-%08" PRIx32 "] " fmt, dcid.h32(), scid.h32(), ##__VA_ARGS__)

QUICPacketDispatcher::QUICPacketDispatcher(const IpEndpoint &addr, EThread *t) : _from(addr)
{
  if (t == nullptr) {
    t = eventProcessor.assign_thread(ET_UDP2);
  }
  this->mutex = t->mutex;
  this->_con  = new UDP2ConnectionImpl(this, t);

  SET_HANDLER(&QUICPacketDispatcher::startEvent);
  t->schedule_imm(this);
}

EThread *
QUICPacketDispatcher::get_thread() const
{
  return this->_con->get_thread();
}

int
QUICPacketDispatcher::startEvent(int event, void *data)
{
  ink_release_assert(this->_from.isValid());
  ink_release_assert(this->_con->create_socket(AF_INET) == 0);
  ink_release_assert(this->_con->bind(&this->_from.sa) == 0);
  ink_release_assert(this->_con->start_io() >= 0);
  SET_HANDLER(&QUICPacketDispatcher::mainEvent);
  // this_ethread()->schedule_every(this, -100);
  return 0;
}

int
QUICPacketDispatcher::mainEvent(int event, void *data)
{
  switch (event) {
  case NET_EVENT_DATAGRAM_READ_READY:
    ink_release_assert(static_cast<UDP2ConnectionImpl *>(data) == this->_con);
    while (true) {
      auto p = this->_con->recv();
      if (p == nullptr) {
        return 0;
      }

      this->_recv_packet(std::move(p));
    }
    break;
  case NET_EVENT_DATAGRAM_WRITE_READY:
    break;
  default:
    Error("unknown event: %d", event);
    ink_release_assert(0);
    break;
  }
  return 0;
}

void
QUICPacketDispatcher::_recv_packet(UDP2PacketUPtr p)
{
  const uint8_t *buf = reinterpret_cast<uint8_t *>(p->chain->start());
  uint64_t buf_len   = p->chain->read_avail();

  if (buf_len == 0) {
    Debug("quic_dispatcher", "Ignore packet - payload is too small");
    return;
  }

  QUICConnectionId dcid = QUICConnectionId::ZERO();
  QUICConnectionId scid = QUICConnectionId::ZERO();

  if (is_debug_tag_set("quic_dispatcher")) {
    ip_port_text_buffer ipb_from;
    ip_port_text_buffer ipb_to;
    QUICDebugDS(scid, dcid, "recv LH packet from %s to %s size=%" PRId64, ats_ip_nptop(&p->from.sa, ipb_from, sizeof(ipb_from)),
                ats_ip_nptop(&p->to.sa, ipb_to, sizeof(ipb_to)), buf_len);
  }

  if (!QUICInvariants::dcid(dcid, buf, buf_len)) {
    Debug("quic_dispatcher", "Ignore packet - payload is too small");
    return;
  }

  if (QUICInvariants::is_long_header(buf)) {
    if (!QUICInvariants::scid(scid, buf, buf_len)) {
      Debug("quic_dispatcher", "Ignore packet - payload is too small");
      return;
    }

    QUICVersion v;
    if (unlikely(!QUICInvariants::version(v, buf, buf_len))) {
      Debug("quic_dispatcher", "Ignore packet - payload is too small");
      return;
    }

    if (!QUICInvariants::is_version_negotiation(v) && !QUICTypeUtil::is_supported_version(v)) {
      QUICDebugDS(scid, dcid, "Unsupported version: 0x%x", v);

      QUICPacketUPtr vn = QUICPacketFactory::create_version_negotiation_packet(scid, dcid);
      this->send_quic_packet(std::move(vn), p->from);
      return;
    }

    QUICPacketType type = QUICPacketType::UNINITIALIZED;
    QUICLongHeaderPacketR::type(type, buf, buf_len);
    if (type == QUICPacketType::INITIAL) {
      // [draft-18] 7.2.
      // When an Initial packet is sent by a client which has not previously received a Retry packet from the server, it populates
      // the Destination Connection ID field with an unpredictable value. This MUST be at least 8 bytes in length.
      if (dcid != QUICConnectionId::ZERO() && dcid.length() < QUICConnectionId::MIN_LENGTH_FOR_INITIAL) {
        Debug("quic_dispatcher", "Ignore packet - DCIL is too small for Initial packet");
        return;
      }
    }
  }

  quic_NetProcessor.dispatch(std::move(p), dcid);
}

void
QUICPacketDispatcher::send_quic_packet(QUICPacketUPtr p, const IpEndpoint &to, bool flush)
{
  size_t udp_len;
  Ptr<IOBufferBlock> udp_payload(new_IOBufferBlock());
  udp_payload->alloc(iobuffer_size_to_index(1200));
  p->store(reinterpret_cast<uint8_t *>(udp_payload->end()), &udp_len);
  udp_payload->fill(udp_len);

  this->send_udp_packet(std::make_unique<UDP2Packet>(nullptr, &to.sa, udp_payload), flush);
}

void
QUICPacketDispatcher::send_udp_packet(UDP2PacketUPtr p, bool flush)
{
  this->_con->send(std::move(p), flush);
}
