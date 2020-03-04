#pragma once

#include <memory>

#include "QUICTypes.h"
#include "UDPConnection.h"
// #include "P_QUICNetVConnection.h"
class QUICNetVConnection;
class UDP2ConnectionImpl;

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

using QUICUDPConnectionWrapperSPtr = std::shared_ptr<QUICUDPConnectionWrapper>;

class QUICUDPConnectionFactory
{
public:
  QUICUDPConnectionFactory(Continuation &acceptor) : _acceptor(acceptor) {}

  QUICUDPConnectionWrapperSPtr create_udp_connection(const IpEndpoint &from, const IpEndpoint &to, EThread *thread);

private:
  Continuation &_acceptor;
};
