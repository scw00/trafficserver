#pragma once

#include "QUICTypes.h"
#include "QUICConnection.h"

#include "I_Net.h"

class QUICConnectionManager
{
public:
  QUICConnectionManager(int magic) : _magic(magic) {}
  QUICConnectionManager();

  QUICConnectionId
  generate_id()
  {
    QUICConnectionId id;
    id.randomize();

    int add = id.hash() % eventProcessor.thread_group[ET_NET]._count;
    if (add == this->_magic) {
      return id;
    }

    id += (this->_magic + eventProcessor.thread_group[ET_NET]._count - add);
    ink_release_assert(static_cast<int>(id.hash() % eventProcessor.thread_group[ET_NET]._count) == this->_magic);
    return id;
  }

  void
  add_route(const QUICConnectionId &id, QUICConnection *vc)
  {
    this->_qvcs.emplace(id, vc);
    Debug("quic_con_m", "add route %s, qvc: %p", id.hex().c_str(), vc);
  }

  QUICConnection *
  get_route(const QUICConnectionId &id)
  {
    auto it = this->_qvcs.find(id);
    if (it == this->_qvcs.end()) {
      return nullptr;
    }

    return it->second;
  }

  void
  remove_route(const QUICConnectionId &id)
  {
    Debug("quic_con_m", "delete route %s", id.hex().c_str());
    this->_qvcs.erase(id);
  }

private:
  std::unordered_map<QUICConnectionId, QUICConnection *, QUICConnectionId::Hash> _qvcs;

  int _magic = 0;
};
