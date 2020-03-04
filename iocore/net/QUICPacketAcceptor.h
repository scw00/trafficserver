#pragma once

#include "I_EventSystem.h"
#include "UDPPacket.h"
#include "UDPConnection.h"
#include "quic/QUICTypes.h"
#include "QUICResetTokenTable.h"
#include "QUICUDPConnectionWrapper.h"

class QUICNetVConnection;

class QUICPacketAcceptor : public Continuation
{
public:
  QUICPacketAcceptor(QUICConnectionTable &ctable, EThread *t, int id);
  // recv packet from other threads.
  void dispatch(UDP2PacketUPtr p);
  int mainEvent(int event, void *data);

  Action *connectUp(Continuation *c, sockaddr const *addr, const NetVCOptions &opt);

private:
  void _process_recv_udp_packet(UDP2PacketUPtr p, UDP2ConnectionImpl *udp_con = nullptr);
  int _send_stateless_retry(const uint8_t *buf, uint64_t buf_len, const IpEndpoint &from, const IpEndpoint &peer,
                            const QUICConnectionId &dcid, const QUICConnectionId &scid, QUICConnectionId &cid_in_retry_token);
  void _send_quic_packet(QUICPacketUPtr p, const IpEndpoint &from, const IpEndpoint &to);
  QUICNetVConnection *_create_qvc(QUICConnectionId peer_cid, QUICConnectionId original_cid, QUICConnectionId first_cid,
                                  const IpEndpoint &from, const IpEndpoint &to);
  void _send_invalid_token_error(const uint8_t *initial_packet, uint64_t initial_packet_len, const IpEndpoint &from,
                                 const IpEndpoint &to);
  bool _send_stateless_reset(QUICConnectionId dcid, uint32_t instance_id, const IpEndpoint &from, const IpEndpoint &to,
                             size_t maximum_size);
  QUICConnection *_check_stateless_reset(const uint8_t *buf, size_t buf_len);

  ASLL(UDP2Packet, link) _external_recv_list;

  EThread *_thread = nullptr;

  QUICResetTokenTable _rtable;
  QUICConnectionTable &_ctable;
  QUICUDPConnectionFactory _udp_con_factory;
};
