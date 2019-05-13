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

#include "QUICBidirectionalStream.h"

//
// QUICBidirectionalStream
//
QUICBidirectionalStream::QUICBidirectionalStream(QUICRTTProvider *rtt_provider, QUICConnectionInfoProvider *cinfo, QUICStreamId sid,
                                                 uint64_t recv_max_stream_data, uint64_t send_max_stream_data)
  : QUICStreamVConnection(cinfo, sid),
    _send_stream(cinfo, sid, send_max_stream_data),
    _recv_stream(rtt_provider, cinfo, sid, recv_max_stream_data)
{
  SET_HANDLER(&QUICBidirectionalStream::state_stream_open);
}

int
QUICBidirectionalStream::state_stream_open(int event, void *data)
{
  // QUICVStreamDebug("%s (%d)", get_vc_event_name(event), event);
  QUICErrorUPtr error = nullptr;

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE: {
    this->_recv_stream.handleEvent(event, data);
    break;
  }
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE: {
    this->_send_stream.handleEvent(event, data);
    break;
  }
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT: {
    // TODO
    ink_assert(false);
    break;
  }
  default:
    // QUICStreamDebug("unknown event");
    ink_assert(false);
  }

  return EVENT_DONE;
}

int
QUICBidirectionalStream::state_stream_closed(int event, void *data)
{
  // QUICVStreamDebug("%s (%d)", get_vc_event_name(event), event);

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE: {
    // ignore
    break;
  }
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE: {
    // ignore
    break;
  }
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT: {
    // TODO
    ink_assert(false);
    break;
  }
  default:
    ink_assert(false);
  }

  return EVENT_DONE;
}

QUICConnectionErrorUPtr
QUICBidirectionalStream::recv(const QUICStreamFrame &frame)
{
  return this->_recv_stream.recv(frame);
}

QUICConnectionErrorUPtr
QUICBidirectionalStream::recv(const QUICMaxStreamDataFrame &frame)
{
  return this->_send_stream.recv(frame);
}

QUICConnectionErrorUPtr
QUICBidirectionalStream::recv(const QUICStreamDataBlockedFrame &frame)
{
  return this->_recv_stream.recv(frame);
}

QUICConnectionErrorUPtr
QUICBidirectionalStream::recv(const QUICStopSendingFrame &frame)
{
  return this->_send_stream.recv(frame);
}

QUICConnectionErrorUPtr
QUICBidirectionalStream::recv(const QUICRstStreamFrame &frame)
{
  return this->_recv_stream.recv(frame);
}

VIO *
QUICBidirectionalStream::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  return this->_recv_stream.do_io_read(c, nbytes, buf);
}

VIO *
QUICBidirectionalStream::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  return this->_send_stream.do_io_write(c, nbytes, buf, owner);
}

void
QUICBidirectionalStream::do_io_close(int lerrno)
{
  this->_send_stream.do_io_close(lerrno);
  this->_recv_stream.do_io_close(lerrno);
}

void
QUICBidirectionalStream::do_io_shutdown(ShutdownHowTo_t howto)
{
  ink_assert(false); // unimplemented yet
  return;
}

void
QUICBidirectionalStream::reenable(VIO *vio)
{
  if (vio->op == VIO::READ) {
    this->_recv_stream.reenable(vio);
  } else if (vio->op == VIO::WRITE) {
    this->_send_stream.reenable(vio);
  }
}

bool
QUICBidirectionalStream::will_generate_frame(QUICEncryptionLevel level, ink_hrtime timestamp)
{
  return this->_recv_stream.will_generate_frame(level, timestamp) || this->_send_stream.will_generate_frame(level, timestamp);
}

QUICFrame *
QUICBidirectionalStream::generate_frame(uint8_t *buf, QUICEncryptionLevel level, uint64_t connection_credit,
                                        uint16_t maximum_frame_size, ink_hrtime timestamp)
{
  QUICFrame *frame = this->_recv_stream.generate_frame(buf, level, connection_credit, maximum_frame_size, timestamp);
  if (frame != nullptr) {
    return frame;
  }

  return this->_send_stream.generate_frame(buf, level, connection_credit, maximum_frame_size, timestamp);
}

void
QUICBidirectionalStream::stop_sending(QUICStreamErrorUPtr error)
{
  this->_recv_stream.stop_sending(std::move(error));
}

void
QUICBidirectionalStream::reset(QUICStreamErrorUPtr error)
{
  this->_send_stream.reset(std::move(error));
}

void
QUICBidirectionalStream::on_read()
{
  this->_recv_stream.on_read();
}

void
QUICBidirectionalStream::on_eos()
{
  this->_recv_stream.on_eos();
}

QUICOffset
QUICBidirectionalStream::largest_offset_received() const
{
  return this->_recv_stream.largest_offset_received();
}

QUICOffset
QUICBidirectionalStream::largest_offset_sent() const
{
  return this->_send_stream.largest_offset_sent();
}
