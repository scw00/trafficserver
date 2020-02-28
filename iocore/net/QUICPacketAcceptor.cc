
#include "UDPConnection.h"
#include "quic/QUICPacket.h"
#include "QUICPacketAcceptor.h"
#include "P_QUICNetVConnection.h"
#include "P_QUICNetProcessor.h"
#include "QUICMultiCertConfigLoader.h"
#include "QUICTLS.h"

static constexpr char debug_tag[] = "quic_acceptor";

#define QUICDebugDS(dcid, scid, fmt, ...) \
  Debug(debug_tag, "[%08" PRIx32 "-%08" PRIx32 "] " fmt, dcid.h32(), scid.h32(), ##__VA_ARGS__)

#define QUICDebug(fmt, ...) Debug(debug_tag, fmt, ##__VA_ARGS__)

QUICUDPConnectionWrapper::~QUICUDPConnectionWrapper()
{
  this->_udp_con.close();
  if (is_debug_tag_set("quic_conw")) {
    char buff[INET6_ADDRPORTSTRLEN * 2] = {0};
    auto from                           = this->_udp_con.from();
    auto to                             = this->_udp_con.to();
    Debug("quic_conw", "close udp connection %s -> %s", ats_ip_nptop(&from.sa, buff, sizeof(buff) - INET6_ADDRPORTSTRLEN),
          ats_ip_nptop(&to.sa, buff + INET6_ADDRPORTSTRLEN, sizeof(buff) - INET6_ADDRPORTSTRLEN));
  }
}

void
QUICUDPConnectionWrapper::bind(QUICNetVConnection *qvc)
{
  this->_bond_connections.emplace(qvc, qvc);
}

void
QUICUDPConnectionWrapper::close(QUICNetVConnection *qvc)
{
  this->_bond_connections.erase(qvc);
}

void
QUICUDPConnectionWrapper::send(UDP2PacketUPtr packet, bool flush)
{
  this->_udp_con.send(std::move(packet), flush);
}

void
QUICUDPConnectionWrapper::signal(int event)
{
  for (auto it : this->_bond_connections) {
    it.second->handleEvent(event, this);
  }
}

IpEndpoint
QUICUDPConnectionWrapper::from() const
{
  return this->_udp_con.from();
}

IpEndpoint
QUICUDPConnectionWrapper::to() const
{
  return this->_udp_con.to();
}

//
// QUICPacketAcceptor
//
QUICPacketAcceptor::QUICPacketAcceptor(EThread *t, int id) : Continuation(t->mutex), _cid_manager(id), _thread(t)
{
  t->schedule_every(this, -100);
  SET_HANDLER(&QUICPacketAcceptor::mainEvent);
}

Action *
QUICPacketAcceptor::connectUp(Continuation *c, sockaddr const *addr, const NetVCOptions &opt)
{
  IpEndpoint local{};
  if (NetVCOptions::FOREIGN_ADDR == opt.addr_binding || NetVCOptions::INTF_ADDR == opt.addr_binding) {
    // Same for now, transparency for foreign addresses must be handled
    // *after* the socket is created, and we need to do this calculation
    // before the socket to get the IP family correct.
    ink_release_assert(opt.local_ip.isValid());
    local.assign(opt.local_ip, htons(opt.local_port));
  }

  auto udp_con = this->create_udp_connection(local, {});
  ink_release_assert(udp_con != nullptr);
  auto udpw = std::make_shared<QUICUDPConnectionWrapper>(*udp_con);

  auto cid = this->_cid_manager.generate_id();
  auto qvc = new QUICNetVConnection(cid, cid, this->_cid_manager, this->_rtable, udpw);
  // Connection ID will be changed
  qvc->id = net_next_connection_number();
  qvc->set_context(NET_VCONNECTION_OUT);
  qvc->con.setRemote(addr);
  qvc->submit_time = Thread::get_hrtime();
  qvc->mutex       = c->mutex;
  qvc->action_     = c;
  qvc->ep.syscall  = false;

  this->_cid_manager.add_route(qvc->connection_id(), qvc);

  MUTEX_TRY_LOCK(lock, qvc->mutex, this_ethread());
  MUTEX_TRY_LOCK(lock2, get_NetHandler(this_ethread())->mutex, this_ethread());
  ink_release_assert(lock.is_locked());
  ink_release_assert(lock2.is_locked());
  qvc->connectUp(this_ethread(), -1);
  return ACTION_RESULT_DONE;
}

int
QUICPacketAcceptor::mainEvent(int event, void *data)
{
  switch (event) {
  case EVENT_POLL: {
    SList(UDP2Packet, link) sq(this->_external_recv_list.popall());
    Queue<UDP2Packet> tmp;
    UDP2Packet *p;
    while ((p = sq.pop())) {
      tmp.push(p);
    }

    while ((p = tmp.pop())) {
      this->_process_recv_udp_packet(UDP2PacketUPtr(p));
    }
    break;
  }
  case NET_EVENT_DATAGRAM_CONNECT_SUCCESS:
  case NET_EVENT_DATAGRAM_READ_READY: {
    UDP2ConnectionImpl *con = static_cast<UDP2ConnectionImpl *>(data);
    ink_release_assert(con != nullptr);
    while (true) {
      auto p = con->recv();
      if (p == nullptr) {
        return 0;
      }

      this->_process_recv_udp_packet(std::move(p), con);
    }

    break;
  }
  case NET_EVENT_DATAGRAM_WRITE_READY:
    break;
  default:
    Error("unknown events %d", event);
    ink_release_assert(0);
  }
  return 0;
}

void
QUICPacketAcceptor::_process_recv_udp_packet(UDP2PacketUPtr p, UDP2ConnectionImpl *udp_con)
{
  // Assumption: udp_packet has only one IOBufferBlock
  const uint8_t *buf = reinterpret_cast<uint8_t *>(p->chain->start());
  uint64_t buf_len   = p->chain->read_avail();

  QUICConnectionId dcid = QUICConnectionId::ZERO();
  QUICConnectionId scid = QUICConnectionId::ZERO();

  if (!QUICInvariants::dcid(dcid, buf, buf_len)) {
    Debug("quic_acceptor", "Ignore packet - payload is too small");
    return;
  }

  if (QUICInvariants::is_long_header(buf) && !QUICInvariants::scid(scid, buf, buf_len)) {
    Debug("quic_acceptor", "Ignore packet - payload is too small");
    return;
  }

  QUICPacketType type = QUICPacketType::UNINITIALIZED;
  QUICLongHeaderPacketR::type(type, buf, buf_len);

  QUICNetVConnection *vc = nullptr;
  auto qc                = this->_cid_manager.get_route(dcid);
  if (qc != nullptr) {
    vc = static_cast<QUICNetVConnection *>(qc);
  }

  // Server Stateless Retry
  QUICConfig::scoped_config params;
  QUICConnectionId cid_in_retry_token = QUICConnectionId::ZERO();
  if (!vc && params->stateless_retry() && QUICInvariants::is_long_header(buf) && type == QUICPacketType::INITIAL) {
    int ret = this->_send_stateless_retry(buf, buf_len, p->from, p->to, dcid, scid, cid_in_retry_token);
    if (ret < 0) {
      return;
    }
  }

  // [draft-12] 6.1.2.  Server Packet Handling
  // Servers MUST drop incoming packets under all other circumstances. They SHOULD send a Stateless Reset (Section 6.10.4) if a
  // connection ID is present in the header.
  if ((!vc && !QUICInvariants::is_long_header(buf)) || (vc && vc->in_closed_queue)) {
    if (is_debug_tag_set("quic_acceptor")) {
      if (!vc && !QUICInvariants::is_long_header(buf)) {
        auto connection = static_cast<QUICNetVConnection *>(this->_check_stateless_reset(buf, buf_len));
        if (connection) {
          QUICDebug("Stateless Reset has been received");
          connection->thread->schedule_imm(connection, QUIC_EVENT_STATELESS_RESET);
          return;
        }
        QUICDebugDS(scid, dcid, "sent Stateless Reset : connection not found, dcid=%s", dcid.hex().c_str());
      } else if (vc && vc->in_closed_queue) {
        QUICDebugDS(scid, dcid, "sent Stateless Reset : connection is already closed, dcid=%s", dcid.hex().c_str());
      }
    }

    this->_send_stateless_reset(dcid, params->instance_id(), p->to, p->from, buf_len - 1);
    return;
  }

  if (is_debug_tag_set("quic_acceptor")) {
    Debug("quic_acceptor", " [%08" PRIx64 "-%08" PRIx64 "] client initial dcid=%s", scid.hash(), dcid.hash(), dcid.hex().c_str());
  }

  if (!vc) {
    QUICConnectionId original_cid = dcid;
    QUICConnectionId peer_cid     = scid;

    vc = this->_create_qvc(peer_cid, original_cid, cid_in_retry_token, p->to, p->from, udp_con);
  }

  vc->handle_received_packet(std::move(p));
  MUTEX_TRY_LOCK(lock, vc->mutex, this_ethread());
  if (!lock.is_locked()) {
    this_ethread()->schedule_imm(this, QUIC_EVENT_PACKET_READ_READY);
    return;
  }

  vc->handleEvent(QUIC_EVENT_PACKET_READ_READY, nullptr);
}

QUICConnection *
QUICPacketAcceptor::_check_stateless_reset(const uint8_t *buf, size_t buf_len)
{
  return this->_rtable.lookup({buf + (buf_len - 16)});
}

int
QUICPacketAcceptor::_send_stateless_retry(const uint8_t *buf, uint64_t buf_len, const IpEndpoint &from, const IpEndpoint &peer,
                                          const QUICConnectionId &dcid, const QUICConnectionId &scid,
                                          QUICConnectionId &original_cid)
{
  // TODO: refine packet parsers in here, QUICPacketLongHeader, and QUICPacketReceiveQueue
  size_t token_length              = 0;
  uint8_t token_length_field_len   = 0;
  size_t token_length_field_offset = 0;
  if (!QUICInitialPacketR::token_length(token_length, token_length_field_len, token_length_field_offset, buf, buf_len)) {
    return -1;
  }

  if (token_length == 0) {
    QUICRetryToken token(from, dcid);
    QUICConnectionId local_cid;
    local_cid.randomize();
    QUICPacketUPtr retry_packet = QUICPacketFactory::create_retry_packet(scid, local_cid, token);

    this->_send_quic_packet(std::move(retry_packet), from, peer);
    return -2;
  } else {
    size_t token_offset = token_length_field_offset + token_length_field_len;

    if (QUICAddressValidationToken::type(buf + token_offset) == QUICAddressValidationToken::Type::RETRY) {
      QUICRetryToken token(buf + token_offset, token_length);
      if (token.is_valid(peer)) {
        original_cid = token.original_dcid();
        return 0;
      } else {
        QUICDebug("Retry token is invalid: ODCID=%" PRIx64 "token_length=%u token=%02x%02x%02x%02x...",
                  static_cast<uint64_t>(token.original_dcid()), token.length(), token.buf()[0], token.buf()[1], token.buf()[2],
                  token.buf()[3]);
        this->_send_invalid_token_error(buf, buf_len, from, peer);
        return -3;
      }
    } else {
      // TODO Handle ResumptionToken
      return -4;
    }
  }

  return 0;
}

bool
QUICPacketAcceptor::_send_stateless_reset(QUICConnectionId dcid, uint32_t instance_id, const IpEndpoint &from, const IpEndpoint &to,
                                          size_t maximum_size)
{
  QUICStatelessResetToken token(dcid, instance_id);
  auto packet = QUICPacketFactory::create_stateless_reset_packet(token, maximum_size);
  if (packet) {
    this->_send_quic_packet(std::move(packet), from, to);
    return true;
  }
  return false;
}

void
QUICPacketAcceptor::_send_invalid_token_error(const uint8_t *initial_packet, uint64_t initial_packet_len, const IpEndpoint &from,
                                              const IpEndpoint &to)
{
  QUICConnectionId scid_in_initial;
  QUICConnectionId dcid_in_initial;
  QUICInvariants::scid(scid_in_initial, initial_packet, initial_packet_len);
  QUICInvariants::dcid(dcid_in_initial, initial_packet, initial_packet_len);

  // Create CONNECTION_CLOSE frame
  auto error = std::make_unique<QUICConnectionError>(QUICTransErrorCode::INVALID_TOKEN);
  uint8_t frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  QUICFrame *frame         = QUICFrameFactory::create_connection_close_frame(frame_buf, *error);
  Ptr<IOBufferBlock> block = frame->to_io_buffer_block(1200);
  size_t block_len         = 0;
  for (Ptr<IOBufferBlock> tmp = block; tmp; tmp = tmp->next) {
    block_len += tmp->size();
  }
  frame->~QUICFrame();

  // Prepare for packet protection
  QUICPacketProtectionKeyInfo ppki;
  ppki.set_context(QUICPacketProtectionKeyInfo::Context::SERVER);
  QUICPacketFactory pf(ppki);
  QUICPacketHeaderProtector php(ppki);
  QUICCertConfig::scoped_config server_cert;
  QUICTLS tls(ppki, server_cert->ssl_default.get(), NET_VCONNECTION_IN, {}, "", "");
  tls.initialize_key_materials(dcid_in_initial);

  // Create INITIAL packet
  QUICConnectionId scid = this->_cid_manager.generate_id();
  uint8_t packet_buf[QUICPacket::MAX_INSTANCE_SIZE];
  QUICPacketUPtr cc_packet = pf.create_initial_packet(packet_buf, scid_in_initial, scid, 0, block, block_len, 0, 0, 1);

  this->_send_quic_packet(std::move(cc_packet), from, to);
}

void
QUICPacketAcceptor::_send_quic_packet(QUICPacketUPtr p, const IpEndpoint &from, const IpEndpoint &to)
{
  size_t udp_len;
  Ptr<IOBufferBlock> udp_payload(new_IOBufferBlock());
  udp_payload->alloc(iobuffer_size_to_index(1299));
  p->store(reinterpret_cast<uint8_t *>(udp_payload->end()), &udp_len);
  udp_payload->fill(udp_len);

  quic_NetProcessor.send(std::make_unique<UDP2Packet>(from, to, udp_payload));
}

QUICNetVConnection *
QUICPacketAcceptor::_create_qvc(QUICConnectionId peer_cid, QUICConnectionId original_cid, QUICConnectionId first_cid,
                                const IpEndpoint &from, const IpEndpoint &to, UDP2ConnectionImpl *udp_con)
{
  Connection c;
  c.setRemote(&from.sa);

  std::shared_ptr<QUICUDPConnectionWrapper> udpw;
  if (udp_con != nullptr) {
    auto udp_tmp = static_cast<QUICUDPConnectionWrapper *>(udp_con->get_data());
    udpw         = udp_tmp->shared_from_this();
  } else {
    udp_con = this->create_udp_connection(from, to);
    udpw    = std::make_shared<QUICUDPConnectionWrapper>(*udp_con);
    udp_con->set_data(udpw.get());
  }

  auto vc         = new QUICNetVConnection(peer_cid, original_cid, first_cid, this->_cid_manager, this->_rtable, udpw);
  vc->ep.syscall  = false;
  vc->id          = net_next_connection_number();
  vc->submit_time = Thread::get_hrtime();
  vc->thread      = this_ethread();
  vc->action_     = quic_NetProcessor.get_action();
  vc->mutex       = new_ProxyMutex();
  vc->set_is_transparent(false);
  vc->set_context(NET_VCONNECTION_IN);
  vc->con.move(c);

  this->_cid_manager.add_route(vc->connection_id(), vc);
  this->_cid_manager.add_route(original_cid, vc);
  Debug("quic_acceptor", "can not find qvc, create new one %lx %lx", vc->connection_id().hash(), original_cid.hash());

  return vc;
}

UDP2ConnectionImpl *
QUICPacketAcceptor::create_udp_connection(const IpEndpoint &from, const IpEndpoint &to)
{
  auto con = new UDP2ConnectionImpl(this, this->_thread);
  // TODO reuse socket
  ink_release_assert(con->create_socket(AF_INET) >= 0);
  if (from.isValid()) {
    ink_release_assert(con->bind(&from.sa) >= 0);
  }
  if (to.isValid()) {
    ink_release_assert(con->connect(&to.sa) >= 0);
  }
  ink_release_assert(con->start_io() >= 0);
  return con;
}

void
QUICPacketAcceptor::dispatch(UDP2PacketUPtr p)
{
  this->_external_recv_list.push(p.get());
  p.release();
}
