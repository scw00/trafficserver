/** @file

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "tscore/ink_config.h"
#include "tscore/I_Layout.h"

#include "P_Net.h"
#include "records/I_RecHttp.h"

#include "QUICGlobals.h"
#include "QUICConfig.h"
#include "QUICMultiCertConfigLoader.h"
#include "QUICResetTokenTable.h"
#include "QUICPacketAcceptor.h"

//
// Global Data
//

QUICNetProcessor quic_NetProcessor;

QUICNetProcessor::QUICNetProcessor() {}

QUICNetProcessor::~QUICNetProcessor()
{
  // TODO: clear all values before destory the table.
  delete this->_ctable;
}

void
QUICNetProcessor::init()
{
  // first we allocate a QUICPollCont.
  this->quicPollCont_offset = eventProcessor.allocate(sizeof(QUICPollCont));

  // schedule event
  eventProcessor.schedule_spawn(&initialize_thread_for_quic_net, ET_NET);
}

int
QUICNetProcessor::start(int, size_t stacksize)
{
  QUIC::init();
  // This initialization order matters ...
  // QUICInitializeLibrary();
  QUICConfig::startup();
  QUICCertConfig::startup();

#ifdef TLS1_3_VERSION_DRAFT_TXT
  // FIXME: remove this when TLS1_3_VERSION_DRAFT_TXT is removed
  Debug("quic_ps", "%s", TLS1_3_VERSION_DRAFT_TXT);
#endif

  return 0;
}

NetAccept *
QUICNetProcessor::createNetAccept(const NetProcessor::AcceptOptions &opt)
{
  return (NetAccept *)new QUICPacketHandlerIn(opt, *this->_ctable, *this->_rtable);
}

NetVConnection *
QUICNetProcessor::allocate_vc(EThread *t)
{
  QUICNetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC(quicNetVCAllocator, t);
    new (vc) QUICNetVConnection();
  } else {
    if (likely(vc = quicNetVCAllocator.alloc())) {
      new (vc) QUICNetVConnection();
      vc->from_accept_thread = true;
    }
  }

  vc->ep.syscall = false;
  return vc;
}

Action *
QUICNetProcessor::connect_re(Continuation *cont, sockaddr const *remote_addr, NetVCOptions *opt)
{
  return this->create_acceptor(this_ethread())->connectUp(cont, remote_addr, *opt);
}

Action *
QUICNetProcessor::main_accept(Continuation *cont, SOCKET fd, AcceptOptions const &opt)
{
  // UnixNetProcessor *this_unp = static_cast<UnixNetProcessor *>(this);
  Debug("iocore_net_processor", "NetProcessor::main_accept - port %d,recv_bufsize %d, send_bufsize %d, sockopt 0x%0x",
        opt.local_port, opt.recv_bufsize, opt.send_bufsize, opt.sockopt_flags);

  if (this->_action = nullptr) {
    this->_action  = new NetAcceptAction();
    *this->_action = cont;
  }

  if (this->_ctable == nullptr) {
    QUICConfig::scoped_config params;
    this->_ctable = new QUICConnectionTable(params->connection_table_size());
    this->_rtable = new QUICResetTokenTable();
  }

  ProxyMutex *mutex  = this_ethread()->mutex.get();
  int accept_threads = opt.accept_threads; // might be changed.
  IpEndpoint accept_ip;                    // local binding address.
  // char thr_name[MAX_THREAD_NAME_LENGTH];

  if (accept_threads < 0) {
    REC_ReadConfigInteger(accept_threads, "proxy.config.accept_threads");
  }
  NET_INCREMENT_DYN_STAT(net_accepts_currently_open_stat);

  if (opt.localhost_only) {
    accept_ip.setToLoopback(opt.ip_family);
  } else if (opt.local_ip.isValid()) {
    accept_ip.assign(opt.local_ip);
  } else {
    accept_ip.setToAnyAddr(opt.ip_family);
  }
  ink_assert(0 < opt.local_port && opt.local_port < 65536);
  accept_ip.port() = htons(opt.local_port);

  // na->accept_fn = net_accept;
  // na->server.fd = fd;
  // ats_ip_copy(&na->server.accept_addr, &accept_ip);

  this->_action  = new NetAcceptAction();
  *this->_action = cont;
  // na->action_->server = &na->server;
  // na->init_accept();

  // SCOPED_MUTEX_LOCK(lock, na->mutex, this_ethread());
  // udpNet.UDPBind((Continuation *)na, &na->server.accept_addr.sa, 1048576, 1048576);

  auto dispatcher = std::make_unique<QUICPacketDispatcher>(accept_ip, fd);
  this->_dispatchers.emplace(accept_ip.host_order_port(), std::move(dispatcher));
  return this->_action.get();
}

void
QUICNetProcessor::send(UDP2PacketUPtr p)
{
  auto it = this->_dispatchers.find(p->from.host_order_port());
  if (it == this->_dispatchers.end()) {
    Debug("quic_processor", "unknown local addresss ignore");
    return;
  }

  it->second->send_udp_packet(std::move(p));
  p.release();
  return;
}

void
QUICNetProcessor::send(QUICPacketUPtr p, const IpEndpoint &to)
{
  auto it = this->_dispatchers.find(to.host_order_port());
  if (it == this->_dispatchers.end()) {
    Debug("quic_processor", "unknown local addresss ignore");
    return;
  }
>>>>>>> QUIC: compile success

  it->second->send_quic_packet(std::move(p), to);
  p.release();
  return;
}

void
QUICNetProcessor::dispatch(UDP2PacketUPtr p, QUICConnectionId dcid)
{
  const uint8_t *buf = reinterpret_cast<uint8_t *>(p->chain->start());

  if (!QUICInvariants::is_long_header(buf)) {
    // short header and migration happen
    auto qc = this->_ctable->lookup(dcid);
    if (qc != nullptr) {
      auto it = this->_acceptor_route_map.find(qc->get_thread());
      ink_release_assert(it != this->_acceptor_route_map.end());
      it->second->dispatch(std::move(p));
    } else {
      // can not find corresponding qc discard
      Debug("quic_processor", "dispatch failed. unknown dcid [%s] discard", dcid.hex().c_str());
    }
    return;
  }

  ink_release_assert(QUICInvariants::is_long_header(buf));
  this->_acceptors[dcid.hash() % this->_acceptors.size()]->dispatch(std::move(p));
  return;
}

QUICPacketAcceptor *
QUICNetProcessor::create_acceptor(EThread *t)
{
  static Ptr<ProxyMutex> mutex = Ptr<ProxyMutex>(new_ProxyMutex());
  ink_release_assert(t == this_ethread());
  // ink_release_assert(this->_ctable != nullptr);
  SCOPED_MUTEX_LOCK(lock, mutex, t);
  if (this->_ctable == nullptr) {
    QUICConfig::scoped_config params;
    this->_ctable = new QUICConnectionTable(params->connection_table_size());
    this->_rtable = new QUICResetTokenTable();
  }

  auto acceptor =
    std::make_shared<QUICPacketAcceptor>(*this->_ctable, t, this->_acceptors.size() == 0 ? 0 : this->_acceptors.size() - 1);
  this->_acceptor_route_map.insert({t, acceptor});
  this->_acceptors.push_back(acceptor);
  return this->_acceptors.back().get();
}

Continuation *
QUICNetProcessor::get_action() const
{
  return this->_action->continuation;
}

QUICPacketAcceptor *
QUICNetProcessor::get_acceptor(EThread *t)
{
  auto it = this->_acceptor_route_map.find(t);
  if (it == this->_acceptor_route_map.end()) {
    return nullptr;
  }

  return it->second.get();
}

void
initialize_thread_for_quic_net(EThread *thread)
{
  thread->schedule_every(quic_NetProcessor.create_acceptor(thread), -HRTIME_MSECONDS(UDP_PERIOD));
}
