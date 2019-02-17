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

#include "catch.hpp"

#include <memory>

#include "quic/QUICFrame.h"
#include "quic/QUICStreamState.h"
#include "quic/Mock.h"

// Unidirectional (sending)
TEST_CASE("QUICSendStreamState", "[quic]")
{
  Ptr<IOBufferBlock> block_4 = make_ptr<IOBufferBlock>(new_IOBufferBlock());
  block_4->alloc();
  block_4->fill(4);
  CHECK(block_4->read_avail() == 4);

  uint8_t stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_frame_with_fin_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t rst_stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_data_blocked_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];

  auto stream_frame          = QUICFrameFactory::create_stream_frame(stream_frame_buf, block_4, 1, 0);
  auto stream_frame_with_fin = QUICFrameFactory::create_stream_frame(stream_frame_with_fin_buf, block_4, 1, 0, true);
  auto rst_stream_frame =
    QUICFrameFactory::create_rst_stream_frame(rst_stream_frame_buf, 0, static_cast<QUICAppErrorCode>(0x01), 0);
  auto stream_data_blocked_frame = QUICFrameFactory::create_stream_data_blocked_frame(stream_data_blocked_frame_buf, 0, 0);
  MockQUICTransferProgressProvider pp;

  SECTION("SendStreamState: Ready -> Send -> Data Sent -> Data Recvd")
  {
    // Case1. Create Stream (Sending)
    QUICSendStreamStateMachine ss;
    CHECK(ss.get() == QUICSendStreamState::Ready);

    // Case2. Send STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);

    // Case3. Send STREAM_DATA_BLOCKED
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM_DATA_BLOCKED));
    ss.update_with_sending_frame(*stream_data_blocked_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);

    // Case3. Send FIN in a STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICSendStreamState::DataSent);

    // Case4. STREAM is not allowed to send
    CHECK(!ss.is_allowed_to_send(QUICFrameType::STREAM));

    // Case5. Receive all ACKs
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICSendStreamState::DataRecvd);
  }

  SECTION("QUICSendStreamState: Ready -> Send")
  {
    // Case1. Create Stream (Sending)
    QUICSendStreamStateMachine ss;
    CHECK(ss.get() == QUICSendStreamState::Ready);

    // Case2. Send STREAM_DATA_BLOCKED
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM_DATA_BLOCKED));
    ss.update_with_sending_frame(*stream_data_blocked_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);
  }

  SECTION("Ready -> Reset Sent -> Reset Recvd")
  {
    // Case1. Create Stream (Sending)
    QUICSendStreamStateMachine ss;
    CHECK(ss.get() == QUICSendStreamState::Ready);

    // Case2. Send RESET_STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::RESET_STREAM));
    ss.update_with_sending_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case3. Receive ACK for STREAM
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case4. Receive ACK for RESET_STREAM
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICSendStreamState::ResetRecvd);
  }

  SECTION("QUICSendStreamState: Ready -> Send -> Reset Sent -> Reset Recvd")
  {
    // Case1. Create Stream (Sending)
    QUICSendStreamStateMachine ss;
    CHECK(ss.get() == QUICSendStreamState::Ready);

    // Case2. Send STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);

    // Case3. Send RESET_STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::RESET_STREAM));
    ss.update_with_sending_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case4. Receive ACK for STREAM
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case5. Receive ACK for RESET_STREAM
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICSendStreamState::ResetRecvd);
  }

  SECTION("QUICSendStreamState: Ready -> Send -> Data Sent -> Reset Sent -> Reset Recvd")
  {
    // Case1. Create Stream (Sending)
    QUICSendStreamStateMachine ss;
    CHECK(ss.get() == QUICSendStreamState::Ready);

    // Case2. Send STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);

    // Case3. Send STREAM_DATA_BLOCKED
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM_DATA_BLOCKED));
    ss.update_with_sending_frame(*stream_data_blocked_frame);
    CHECK(ss.get() == QUICSendStreamState::Send);

    // Case3. Send FIN in a STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICSendStreamState::DataSent);

    // Case4. STREAM is not allowed to send
    CHECK(!ss.is_allowed_to_send(QUICFrameType::STREAM));

    // Case4. Send RESET_STREAM
    CHECK(ss.is_allowed_to_send(QUICFrameType::RESET_STREAM));
    ss.update_with_sending_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case5. Receive ACK for STREAM
    CHECK(ss.get() == QUICSendStreamState::ResetSent);

    // Case6. Receive ACK for RESET_STREAM
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICSendStreamState::ResetRecvd);
  }
}

// Unidirectional (receiving)
TEST_CASE("QUICReceiveStreamState", "[quic]")
{
  Ptr<IOBufferBlock> block_4 = make_ptr<IOBufferBlock>(new_IOBufferBlock());
  block_4->alloc();
  block_4->fill(4);
  CHECK(block_4->read_avail() == 4);

  uint8_t stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_frame_delayed_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_frame_with_fin_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t rst_stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_data_blocked_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];

  auto stream_frame          = QUICFrameFactory::create_stream_frame(stream_frame_buf, block_4, 1, 0);
  auto stream_frame_delayed  = QUICFrameFactory::create_stream_frame(stream_frame_delayed_buf, block_4, 1, 1);
  auto stream_frame_with_fin = QUICFrameFactory::create_stream_frame(stream_frame_with_fin_buf, block_4, 1, 2, true);
  auto rst_stream_frame =
    QUICFrameFactory::create_rst_stream_frame(rst_stream_frame_buf, 0, static_cast<QUICAppErrorCode>(0x01), 0);
  auto stream_data_blocked_frame = QUICFrameFactory::create_stream_data_blocked_frame(stream_data_blocked_frame_buf, 0, 0);

  SECTION("Recv -> Size Known -> Data Recvd -> Data Read")
  {
    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_send(QUICFrameType::MAX_STREAM_DATA) == false);
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv STREAM_DATA_BLOCKED
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM_DATA_BLOCKED));
    ss.update_with_receiving_frame(*stream_data_blocked_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case3. Recv FIN in a STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICReceiveStreamState::SizeKnown);

    // Case4. Recv ALL data
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_delayed);
    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICReceiveStreamState::DataRecvd);

    // Case5. Read data
    ss.update_on_user_read_event();
    CHECK(ss.get() == QUICReceiveStreamState::DataRead);
  }

  SECTION("Recv -> Reset Recvd -> Reset Read")
  {
    MockQUICTransferProgressProvider in_progress;

    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv RESET_STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::RESET_STREAM));
    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::ResetRecvd);

    // Case3. Handle reset
    ss.update_on_user_read_event();
    CHECK(ss.get() == QUICReceiveStreamState::ResetRead);
  }

  SECTION("Recv -> Size Known -> Reset Recvd")
  {
    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv FIN in a STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICReceiveStreamState::SizeKnown);

    // Case3. Recv RESET_STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::RESET_STREAM));
    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::ResetRecvd);
  }

  SECTION("Recv -> Size Known -> Data Recvd !-> Reset Recvd")
  {
    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv FIN in a STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICReceiveStreamState::SizeKnown);

    // Case3. Recv ALL data
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_delayed);
    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICReceiveStreamState::DataRecvd);

    // Case4. Recv RESET_STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::RESET_STREAM) == false);
    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::DataRecvd);
  }

  SECTION("Recv -> Size Known -> Reset Recvd !-> Data Recvd")
  {
    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv FIN in a STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICReceiveStreamState::SizeKnown);
    CHECK(ss.is_allowed_to_send(QUICFrameType::STOP_SENDING));

    // Case3. Recv RESET_STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::RESET_STREAM));
    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::ResetRecvd);
    CHECK(ss.is_allowed_to_send(QUICFrameType::STOP_SENDING) == false);

    // Case4. Recv ALL data
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM) == false);
    ss.update_with_receiving_frame(*stream_frame_delayed);
    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICReceiveStreamState::ResetRecvd);
    ss.update_on_user_read_event();
    CHECK(ss.get() == QUICReceiveStreamState::ResetRead);
    CHECK(ss.is_allowed_to_send(QUICFrameType::STOP_SENDING) == false);
  }

  SECTION("Discard STREAM and RESET_STREAM in DataRecvd")
  {
    // Case1. Recv STREAM
    QUICReceiveStreamStateMachine ss;
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);
    CHECK(ss.get() == QUICReceiveStreamState::Recv);

    // Case2. Recv FIN in a STREAM
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICReceiveStreamState::SizeKnown);

    // Case3. Recv ALL data
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame_delayed);
    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICReceiveStreamState::DataRecvd);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::RESET_STREAM) == false);
    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM) == false);
    CHECK(ss.is_allowed_to_send(QUICFrameType::STOP_SENDING));
  }
}

TEST_CASE("QUICBidState", "[quic]")
{
  Ptr<IOBufferBlock> block_4 = make_ptr<IOBufferBlock>(new_IOBufferBlock());
  block_4->alloc();
  block_4->fill(4);
  CHECK(block_4->read_avail() == 4);

  uint8_t stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_frame_delayed_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t stream_frame_with_fin_buf[QUICFrame::MAX_INSTANCE_SIZE];
  uint8_t rst_stream_frame_buf[QUICFrame::MAX_INSTANCE_SIZE];

  auto stream_frame          = QUICFrameFactory::create_stream_frame(stream_frame_buf, block_4, 1, 0);
  auto stream_frame_delayed  = QUICFrameFactory::create_stream_frame(stream_frame_delayed_buf, block_4, 1, 1);
  auto stream_frame_with_fin = QUICFrameFactory::create_stream_frame(stream_frame_with_fin_buf, block_4, 1, 2, true);
  auto rst_stream_frame =
    QUICFrameFactory::create_rst_stream_frame(rst_stream_frame_buf, 0, static_cast<QUICAppErrorCode>(0x01), 0);

  SECTION("QUICBidState idle -> open -> HC_R 1")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);

    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICBidirectionalStreamState::Open);

    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_R);
  }

  SECTION("QUICBidState idle -> open -> HC_R 2")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);

    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_R);
  }

  SECTION("QUICBidState idle -> open -> HC_L 1")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);

    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_with_sending_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICBidirectionalStreamState::Open);

    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);

    ss.update_with_sending_frame(*stream_frame_delayed);
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);
  }

  SECTION("QUICBidState idle -> open -> HC_L 2")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);

    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_with_sending_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);
  }

  SECTION("QUICBidState idle -> open -> closed 1")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame);

    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_with_sending_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);

    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICBidirectionalStreamState::Closed);

    ss.update_on_user_read_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::Closed);
  }

  SECTION("QUICBidState idle -> open -> closed 2")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);

    ss.update_with_receiving_frame(*rst_stream_frame);
    CHECK(ss.get() == QUICBidirectionalStreamState::Closed);

    ss.update_on_user_read_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::Closed);
  }

  SECTION("QUICBidState idle -> open -> closed 3")
  {
    QUICBidirectionalStreamStateMachine ss;
    CHECK(ss.get() == QUICBidirectionalStreamState::Idle);

    CHECK(ss.is_allowed_to_send(QUICFrameType::STREAM));
    ss.update_with_sending_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICBidirectionalStreamState::Open);
    ss.update_on_transport_send_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);

    CHECK(ss.is_allowed_to_receive(QUICFrameType::STREAM));
    ss.update_with_receiving_frame(*stream_frame);

    ss.update_with_receiving_frame(*stream_frame_with_fin);
    CHECK(ss.get() == QUICBidirectionalStreamState::HC_L);

    ss.update_on_transport_recv_event();
    CHECK(ss.get() == QUICBidirectionalStreamState::Closed);
  }
}
