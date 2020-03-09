#pragma once

#include "I_EventSystem.h"

#include "UDPConnection.h"
#include "UDPPacket.h"

#include "quic/QUICPacket.h"

class UDP2ConnectionImpl;

class QUICPacketDispatcher : public Continuation
{
public:
  QUICPacketDispatcher(const IpEndpoint &addr, EThread *t = nullptr, int fd = -1);

  int startEvent(int event, void *data);
  int mainEvent(int event, void *data);

  void flush();

  EThread *get_thread() const;
  void send_udp_packet(UDP2PacketUPtr packet, bool flush = true);
  void send_quic_packet(QUICPacketUPtr p, const IpEndpoint &to, bool flush = true);

private:
  void _recv_packet(UDP2PacketUPtr p);

  IpEndpoint _from{};
  UDP2ConnectionImpl *_con = nullptr;
};
