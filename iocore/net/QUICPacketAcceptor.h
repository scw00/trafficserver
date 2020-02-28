#pragma once

#include "I_EventSystem.h"
#include "UDPPacket.h"
#include "UDPConnection.h"
#include "quic/QUICTypes.h"
#include "quic/QUICConnectionManager.h"
#include "QUICResetTokenTable.h"

class QUICNetVConnection;
class UDP2ConnectionImpl;

class QUICUDPConnectionWrapper : public std::enable_shared_from_this<QUICUDPConnectionWrapper>
{
public:
  QUICUDPConnectionWrapper(UDP2ConnectionImpl &udp_con) : _udp_con(udp_con) {}
  ~QUICUDPConnectionWrapper();

  void bind(QUICNetVConnection *qvc);
  void close(QUICNetVConnection *qvc);
  void send(UDP2PacketUPtr, bool flush = true);
  void signal(int event);
  IpEndpoint from() const;
  IpEndpoint to() const;

private:
  std::unordered_map<void *, QUICNetVConnection *> _bond_connections;

  UDP2ConnectionImpl &_udp_con;
};

class QUICPacketAcceptor : public Continuation
{
public:
  QUICPacketAcceptor(EThread *t, int id);
  // recv packet from other threads.
  void dispatch(UDP2PacketUPtr p);
  int mainEvent(int event, void *data);

  UDP2ConnectionImpl *create_udp_connection(const IpEndpoint &from, const IpEndpoint &to);
  Action *connectUp(Continuation *c, sockaddr const *addr, const NetVCOptions &opt);

private:
  void _process_recv_udp_packet(UDP2PacketUPtr p, UDP2ConnectionImpl *udp_con = nullptr);
  int _send_stateless_retry(const uint8_t *buf, uint64_t buf_len, const IpEndpoint &from, const IpEndpoint &peer,
                            const QUICConnectionId &dcid, const QUICConnectionId &scid, QUICConnectionId &cid_in_retry_token);
  void _send_quic_packet(QUICPacketUPtr p, const IpEndpoint &from, const IpEndpoint &to);
  QUICNetVConnection *_create_qvc(QUICConnectionId peer_cid, QUICConnectionId original_cid, QUICConnectionId first_cid,
                                  const IpEndpoint &from, const IpEndpoint &to, UDP2ConnectionImpl *udp_con = nullptr);
  void _send_invalid_token_error(const uint8_t *initial_packet, uint64_t initial_packet_len, const IpEndpoint &from,
                                 const IpEndpoint &to);
  bool _send_stateless_reset(QUICConnectionId dcid, uint32_t instance_id, const IpEndpoint &from, const IpEndpoint &to,
                             size_t maximum_size);
  QUICConnection *_check_stateless_reset(const uint8_t *buf, size_t buf_len);

  ASLL(UDP2Packet, link) _external_recv_list;

  QUICConnectionManager _cid_manager;
  QUICResetTokenTable _rtable;
  EThread *_thread = nullptr;
};
