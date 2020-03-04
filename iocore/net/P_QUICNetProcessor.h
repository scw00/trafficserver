/** @file

  A brief file description

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

 */

/****************************************************************************

  P_QUICNetProcessor.h

  The QUIC version of the UnixNetProcessor class.  The majority of the logic
  is in UnixNetProcessor.  The QUICNetProcessor provides the following:

  * QUIC library initialization through the start() method.
  * Allocation of a QUICNetVConnection through the allocate_vc virtual method.

  Possibly another pass through could simplify the allocate_vc logic too, but
  I think I will stop here for now.

 ****************************************************************************/
#pragma once

#include "UDPConnection.h"
#include "UDPProcessor.h"
#include "tscore/ink_platform.h"
#include "P_Net.h"
#include "quic/QUICConnectionTable.h"

#include "QUICPacketDispatcher.h"
#include "QUICPacketAcceptor.h"

class UnixNetVConnection;
class QUICResetTokenTable;
struct NetAccept;
class QUICPacketDispatcher;

//////////////////////////////////////////////////////////////////
//
//  class QUICNetProcessor
//
//////////////////////////////////////////////////////////////////
class QUICNetProcessor : public UnixNetProcessor
{
public:
  QUICNetProcessor();
  virtual ~QUICNetProcessor();

  void init() override;
  virtual int start(int, size_t stacksize) override;
  // TODO: refactoring NetProcessor::connect_re and UnixNetProcessor::connect_re_internal
  // Action *connect_re(Continuation *cont, sockaddr const *addr, NetVCOptions *opts) override;
  Action *connect_re(Continuation *cont, sockaddr const *addr, NetVCOptions *opts);

  virtual NetAccept *createNetAccept(const NetProcessor::AcceptOptions &opt) override;
  virtual NetVConnection *allocate_vc(EThread *t) override;
  virtual QUICPacketAcceptor *create_acceptor(EThread *t);

  void send(UDP2PacketUPtr p);
  void send(QUICPacketUPtr p, const IpEndpoint &to);
  void dispatch(UDP2PacketUPtr p, QUICConnectionId dcid);

  Action *main_accept(Continuation *cont, SOCKET fd, AcceptOptions const &opt) override;

  Continuation *get_action() const;

  off_t quicPollCont_offset;

private:
  QUICNetProcessor(const QUICNetProcessor &);
  QUICNetProcessor &operator=(const QUICNetProcessor &);

  Ptr<NetAcceptAction> _action;

  QUICResetTokenTable *_rtable = nullptr;
  QUICConnectionTable *_ctable = nullptr;

  std::unordered_map<uint64_t, std::unique_ptr<QUICPacketDispatcher>> _dispatchers;
  std::vector<std::unique_ptr<QUICPacketAcceptor>> _acceptors;
};

extern QUICNetProcessor quic_NetProcessor;
