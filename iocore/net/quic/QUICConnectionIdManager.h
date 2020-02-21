#pragma once

#include "QUICTypes.h"
#include "QUICConnection.h"

#include "I_Net.h"

class QUICConnectionIdManager
{
public:
  QUICConnectionIdManager(int magic) : _magic(magic) {}
  QUICConnectionIdManager();

  QUICConnectionId
  generate_id()
  {
    QUICConnectionId id;
    id.randomize();

    int16_t add = id.hash() % eventProcessor.thread_group[ET_NET]._count;
    id          = id + static_cast<int16_t>(add - this->_magic);
    return id;
  }

  void
  add_route(const QUICConnectionId &id, QUICConnection *vc)
  {
    this->_qvcs.emplace(id, vc);
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
    this->_qvcs.erase(id);
  }

private:
  std::unordered_map<QUICConnectionId, QUICConnection *, QUICConnectionId::Hash> _qvcs;

  int _magic = 0;
};
