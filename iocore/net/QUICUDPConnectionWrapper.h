#pragma once

#include <memory>

#include "QUICTypes.h"
#include "UDPConnection.h"
#include "P_QUICNetVConnection.h"

class QUICUDPConnectionWrapper : public std::enable_shared_from_this<QUICUDPConnectionWrapper>
{
public:
  QUICUDPConnectionWrapper(UDP2ConnectionImpl &con) : _udp_con(con) {}
  ~QUICUDPConnectionWrapper();

  void bind(QUICNetVConnection *qvc);
  void close(QUICNetVConnection *qvc);
  void send(UDP2PacketUPtr packet, bool flush = true);
  void signal(int event);
  IpEndpoint from() const;
  IpEndpoint to() const;

private:
  std::map<void *, QUICNetVConnection *> _bond_connections;
  UDP2ConnectionImpl &_udp_con;
};
