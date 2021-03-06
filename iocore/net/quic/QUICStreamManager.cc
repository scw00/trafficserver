/** @file
 *
 *  A brief file description
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "QUICStreamManager.h"

#include "QUICApplication.h"
#include "QUICTransportParameters.h"

static constexpr char tag[]                     = "quic_stream_manager";
static constexpr QUICStreamId QUIC_STREAM_TYPES = 4;

ClassAllocator<QUICStreamManager> quicStreamManagerAllocator("quicStreamManagerAllocator");
ClassAllocator<QUICBidirectionalStream> quicBidiStreamAllocator("quicStreamAllocator");

QUICStreamManager::QUICStreamManager(QUICConnectionInfoProvider *info, QUICRTTProvider *rtt_provider, QUICApplicationMap *app_map)
  : _info(info), _rtt_provider(rtt_provider), _app_map(app_map)
{
  if (this->_info->direction() == NET_VCONNECTION_OUT) {
    this->_next_stream_id_bidi = static_cast<uint32_t>(QUICStreamType::CLIENT_BIDI);
    this->_next_stream_id_uni  = static_cast<uint32_t>(QUICStreamType::CLIENT_UNI);
  } else {
    this->_next_stream_id_bidi = static_cast<uint32_t>(QUICStreamType::SERVER_BIDI);
    this->_next_stream_id_uni  = static_cast<uint32_t>(QUICStreamType::SERVER_UNI);
  }
}

std::vector<QUICFrameType>
QUICStreamManager::interests()
{
  return {
    QUICFrameType::STREAM,          QUICFrameType::RESET_STREAM, QUICFrameType::STOP_SENDING,
    QUICFrameType::MAX_STREAM_DATA, QUICFrameType::MAX_STREAMS,
  };
}

void
QUICStreamManager::init_flow_control_params(const std::shared_ptr<const QUICTransportParameters> &local_tp,
                                            const std::shared_ptr<const QUICTransportParameters> &remote_tp)
{
  this->_local_tp  = local_tp;
  this->_remote_tp = remote_tp;

  if (this->_local_tp) {
    this->_local_max_streams_bidi = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAMS_BIDI);
    this->_local_max_streams_uni  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAMS_UNI);
  }
  if (this->_remote_tp) {
    this->_remote_max_streams_bidi = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAMS_BIDI);
    this->_remote_max_streams_uni  = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAMS_UNI);
  }
}

void
QUICStreamManager::set_max_streams_bidi(uint64_t max_streams)
{
  if (this->_local_max_streams_bidi <= max_streams) {
    this->_local_max_streams_bidi = max_streams;
  }
}

void
QUICStreamManager::set_max_streams_uni(uint64_t max_streams)
{
  if (this->_local_max_streams_uni <= max_streams) {
    this->_local_max_streams_uni = max_streams;
  }
}

QUICConnectionErrorUPtr
QUICStreamManager::create_stream(QUICStreamId stream_id)
{
  // TODO: check stream_id
  QUICConnectionErrorUPtr error    = nullptr;
  QUICStreamVConnection *stream_vc = this->_find_or_create_stream_vc(stream_id);
  if (!stream_vc) {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }

  QUICApplication *application = this->_app_map->get(stream_id);

  if (!application->is_stream_set(stream_vc)) {
    application->set_stream(stream_vc);
  }

  return error;
}

QUICConnectionErrorUPtr
QUICStreamManager::create_uni_stream(QUICStreamId &new_stream_id)
{
  QUICConnectionErrorUPtr error = this->create_stream(this->_next_stream_id_uni);
  if (error == nullptr) {
    new_stream_id = this->_next_stream_id_uni;
    this->_next_stream_id_uni += QUIC_STREAM_TYPES;
  }

  return error;
}

QUICConnectionErrorUPtr
QUICStreamManager::create_bidi_stream(QUICStreamId &new_stream_id)
{
  QUICConnectionErrorUPtr error = this->create_stream(this->_next_stream_id_bidi);
  if (error == nullptr) {
    new_stream_id = this->_next_stream_id_bidi;
    this->_next_stream_id_bidi += QUIC_STREAM_TYPES;
  }

  return error;
}

void
QUICStreamManager::reset_stream(QUICStreamId stream_id, QUICStreamErrorUPtr error)
{
  auto stream = this->_find_stream_vc(stream_id);
  stream->reset(std::move(error));
}

QUICConnectionErrorUPtr
QUICStreamManager::handle_frame(QUICEncryptionLevel level, const QUICFrame &frame)
{
  QUICConnectionErrorUPtr error = nullptr;

  switch (frame.type()) {
  case QUICFrameType::MAX_STREAM_DATA:
    error = this->_handle_frame(static_cast<const QUICMaxStreamDataFrame &>(frame));
    break;
  case QUICFrameType::STREAM_DATA_BLOCKED:
    // STREAM_DATA_BLOCKED frame is for debugging. Just propagate to streams
    error = this->_handle_frame(static_cast<const QUICStreamDataBlockedFrame &>(frame));
    break;
  case QUICFrameType::STREAM:
    error = this->_handle_frame(static_cast<const QUICStreamFrame &>(frame));
    break;
  case QUICFrameType::STOP_SENDING:
    error = this->_handle_frame(static_cast<const QUICStopSendingFrame &>(frame));
    break;
  case QUICFrameType::RESET_STREAM:
    error = this->_handle_frame(static_cast<const QUICRstStreamFrame &>(frame));
    break;
  case QUICFrameType::MAX_STREAMS:
    error = this->_handle_frame(static_cast<const QUICMaxStreamsFrame &>(frame));
    break;
  default:
    Debug(tag, "Unexpected frame type: %02x", static_cast<unsigned int>(frame.type()));
    ink_assert(false);
    break;
  }

  return error;
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICMaxStreamDataFrame &frame)
{
  QUICStreamVConnection *stream = this->_find_or_create_stream_vc(frame.stream_id());
  if (stream) {
    return stream->recv(frame);
  } else {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICStreamDataBlockedFrame &frame)
{
  QUICStreamVConnection *stream = this->_find_or_create_stream_vc(frame.stream_id());
  if (stream) {
    return stream->recv(frame);
  } else {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICStreamFrame &frame)
{
  QUICStreamVConnection *stream = this->_find_or_create_stream_vc(frame.stream_id());
  if (!stream) {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }

  QUICApplication *application = this->_app_map->get(frame.stream_id());

  if (application && !application->is_stream_set(stream)) {
    application->set_stream(stream);
  }

  return stream->recv(frame);
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICRstStreamFrame &frame)
{
  QUICStream *stream = this->_find_or_create_stream_vc(frame.stream_id());
  if (stream) {
    return stream->recv(frame);
  } else {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICStopSendingFrame &frame)
{
  QUICStream *stream = this->_find_or_create_stream_vc(frame.stream_id());
  if (stream) {
    return stream->recv(frame);
  } else {
    return std::make_unique<QUICConnectionError>(QUICTransErrorCode::STREAM_ID_ERROR);
  }
}

QUICConnectionErrorUPtr
QUICStreamManager::_handle_frame(const QUICMaxStreamsFrame &frame)
{
  QUICStreamType type = QUICTypeUtil::detect_stream_type(frame.maximum_streams());
  if (type == QUICStreamType::SERVER_BIDI || type == QUICStreamType::CLIENT_BIDI) {
    this->_remote_max_streams_bidi = frame.maximum_streams();
  } else {
    this->_remote_max_streams_uni = frame.maximum_streams();
  }
  return nullptr;
}

QUICStreamVConnection *
QUICStreamManager::_find_stream_vc(QUICStreamId id)
{
  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    if (s->id() == id) {
      return s;
    }
  }
  return nullptr;
}

QUICStreamVConnection *
QUICStreamManager::_find_or_create_stream_vc(QUICStreamId stream_id)
{
  QUICStreamVConnection *stream = this->_find_stream_vc(stream_id);
  if (!stream) {
    if (!this->_local_tp) {
      return nullptr;
    }

    ink_assert(this->_local_tp);
    ink_assert(this->_remote_tp);

    uint64_t local_max_stream_data  = 0;
    uint64_t remote_max_stream_data = 0;

    switch (QUICTypeUtil::detect_stream_type(stream_id)) {
    case QUICStreamType::CLIENT_BIDI:
      if (this->_local_max_streams_bidi == 0 || stream_id > this->_local_max_streams_bidi) {
        return nullptr;
      }

      if (this->_info->direction() == NET_VCONNECTION_OUT) {
        // client
        local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
        remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
      } else {
        // server
        local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
        remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
      }

      break;
    case QUICStreamType::CLIENT_UNI:
      if (this->_local_max_streams_uni == 0 || stream_id > this->_local_max_streams_uni) {
        return nullptr;
      }

      local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_UNI);
      remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_UNI);

      break;
    case QUICStreamType::SERVER_BIDI:
      if (this->_remote_max_streams_bidi == 0 || stream_id > this->_remote_max_streams_bidi) {
        return nullptr;
      }

      if (this->_info->direction() == NET_VCONNECTION_OUT) {
        // client
        local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
        remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
      } else {
        // server
        local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
        remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
      }

      break;
    case QUICStreamType::SERVER_UNI:
      if (this->_remote_max_streams_uni == 0 || stream_id > this->_remote_max_streams_uni) {
        return nullptr;
      }

      local_max_stream_data  = this->_local_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_UNI);
      remote_max_stream_data = this->_remote_tp->getAsUInt(QUICTransportParameterId::INITIAL_MAX_STREAM_DATA_UNI);

      break;
    }

    // TODO Free the stream somewhere
    stream = THREAD_ALLOC(quicBidiStreamAllocator, this_ethread());
    new (stream)
      QUICBidirectionalStream(this->_rtt_provider, this->_info, stream_id, local_max_stream_data, remote_max_stream_data);

    this->stream_list.push(stream);
  }

  return stream;
}

uint64_t
QUICStreamManager::total_reordered_bytes() const
{
  uint64_t total_bytes = 0;

  // FIXME Iterating all (open + closed) streams is expensive
  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    total_bytes += s->reordered_bytes();
  }
  return total_bytes;
}

uint64_t
QUICStreamManager::total_offset_received() const
{
  uint64_t total_offset_received = 0;

  // FIXME Iterating all (open + closed) streams is expensive
  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    total_offset_received += s->largest_offset_received();
  }
  return total_offset_received;
}

uint64_t
QUICStreamManager::total_offset_sent() const
{
  return this->_total_offset_sent;
}

void
QUICStreamManager::add_total_offset_sent(uint32_t sent_byte)
{
  // FIXME: use atomic increment
  this->_total_offset_sent += sent_byte;
}

uint32_t
QUICStreamManager::stream_count() const
{
  uint32_t count = 0;
  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    ++count;
  }
  return count;
}

void
QUICStreamManager::set_default_application(QUICApplication *app)
{
  this->_app_map->set_default(app);
}

bool
QUICStreamManager::will_generate_frame(QUICEncryptionLevel level, ink_hrtime timestamp)
{
  if (!this->_is_level_matched(level)) {
    return false;
  }

  // workaround fix until support 0-RTT on client
  if (level == QUICEncryptionLevel::ZERO_RTT) {
    return false;
  }

  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    if (s->will_generate_frame(level, timestamp)) {
      return true;
    }
  }

  return false;
}

QUICFrame *
QUICStreamManager::generate_frame(uint8_t *buf, QUICEncryptionLevel level, uint64_t connection_credit, uint16_t maximum_frame_size,
                                  ink_hrtime timestamp)
{
  QUICFrame *frame = nullptr;

  if (!this->_is_level_matched(level)) {
    return frame;
  }

  // workaround fix until support 0-RTT on client
  if (level == QUICEncryptionLevel::ZERO_RTT) {
    return frame;
  }

  // FIXME We should pick a stream based on priority
  for (QUICStreamVConnection *s = this->stream_list.head; s; s = s->link.next) {
    frame = s->generate_frame(buf, level, connection_credit, maximum_frame_size, timestamp);
    if (frame) {
      break;
    }
  }

  if (frame != nullptr && frame->type() == QUICFrameType::STREAM) {
    this->add_total_offset_sent(static_cast<QUICStreamFrame *>(frame)->data_length());
  }

  return frame;
}
