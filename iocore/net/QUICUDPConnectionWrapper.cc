#include "QUICUDPConnectionWrapper.h"

//
// QUICUDPConnectionWrapper
//
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
