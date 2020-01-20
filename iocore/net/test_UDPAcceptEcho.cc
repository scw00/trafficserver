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
  limitations under the License.
 */

#include <iostream>
#include <cstdlib>
#include <cstring>

#include "tscore/I_Layout.h"
#include "tscore/TestBox.h"

#include "I_EventSystem.h"
#include "I_Net.h"
#include "UDPConnection.h"
#include "UDPProcessor.h"
#include "records/I_RecProcess.h"
#include "RecordsConfig.h"

#include "diags.i"

static pid_t pid;
const char payload[]  = "helloword";
const char payload1[] = "helloword1";
const char payload2[] = "helloword2";

void
signal_handler(int signum)
{
  std::exit(EXIT_SUCCESS);
}

in_port_t port = 0;
int pfd[2]; // Pipe used to signal client with transient port.

class AcceptServer : public Continuation
{
public:
  int
  mainEvent(int event, void *data)
  {
    switch (event) {
    case NET_EVENT_DATAGRAM_READ_READY: {
      ink_assert(this->_con == static_cast<UDP2ConnectionImpl *>(data));
      while (true) {
        auto p = this->_con->recv();
        if (p == nullptr) {
          return 0;
        }

        if (!this->_first) {
          this->_first = true;
          ink_release_assert(this->_con->connect(&p->from.sa) >= 0);
        }

        this->_closed = std::string(p->chain->start(), p->chain->read_avail()) == payload2;
        std::cout << "receive msg from accept: " << std::string(p->chain->start(), p->chain->read_avail()) << std::endl;
        auto tmp = p->from;
        p->from  = p->to;
        p->to    = tmp;
        this->_con->send(std::move(p));
      }
      break;
    }
    case NET_EVENT_DATAGRAM_WRITE_READY:
      if (this->_closed) {
        std::cout << "accept exit" << std::endl;
        signal_handler(0);
      }
      break;
    case NET_EVENT_DATAGRAM_CONNECT_SUCCESS:
      break;
    default:
      ink_release_assert(0);
      break;
    }
    return 0;
  }

  AcceptServer()
  {
    SET_HANDLER(&AcceptServer::mainEvent);
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    this->_con = new UDP2ConnectionImpl(this, eventProcessor.assign_thread(ET_UDP2));
    ink_release_assert(this->_con->create_socket(reinterpret_cast<sockaddr *const>(&addr)) >= 0);
    ink_release_assert(this->_con->start_io() >= 0);
    ink_release_assert(this->_con != nullptr);
    std::cout << "bind to port: " << ats_ip_port_host_order(this->_con->from()) << std::endl;
    int port = ats_ip_port_host_order(this->_con->from());
    ink_release_assert(write(pfd[1], &port, sizeof(port)) == sizeof(port));
    this->mutex = this->_con->mutex;
  }

private:
  UDP2ConnectionImpl *_con = nullptr;
  bool _first              = false;
  bool _closed             = false;
};

void
udp_client(TestBox &box)
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    std::cout << "Couldn't create socket" << std::endl;
    std::exit(EXIT_FAILURE);
  }

  struct timeval tv;
  tv.tv_sec  = 20;
  tv.tv_usec = 0;

  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&tv), sizeof(tv));

  sockaddr_in addr;
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port        = htons(port);

  auto bsend = [sock, addr](const char *payload) {
    ssize_t n = sendto(sock, payload, strlen(payload), 0,
                       reinterpret_cast<struct sockaddr *>(const_cast<struct sockaddr_in *>(&addr)), sizeof(addr));
    if (n < 0) {
      std::cout << "Couldn't send udp packet" << std::endl;
      close(sock);
      std::exit(EXIT_FAILURE);
    }
  };

  auto brecv = [sock, box](const char *expect) -> bool {
    char buf[128] = {0};
    ssize_t l     = recv(sock, buf, sizeof(buf), 0);
    if (l < 0) {
      std::cout << "Couldn't recv udp packet" << std::endl;
      close(sock);
      const_cast<TestBox *>(&box)->check(false, "errno recv");
      return false;
    }
    std::cout << "client recv payload: " << buf << std::endl;
    const_cast<TestBox *>(&box)->check(strncmp(buf, expect, sizeof(payload)) == 0, "echo doesn't match");
    if (strncmp(buf, expect, sizeof(payload))) {
      kill(pid, SIGINT);
    }
    return strncmp(buf, expect, sizeof(payload)) == 0;
  };

#define CHECK_RECV(statement) \
  do {                        \
    if (!statement) {         \
      return;                 \
    }                         \
  } while (0)

  std::cout << "client send payload" << std::endl;
  bsend(payload);             // send payload to accept;
  CHECK_RECV(brecv(payload)); // accept reply the payload
  // CHECK_RECV(brecv(payload)); // sub udp connection send another one.

  // send to accept udp connection since we are sleeping in one second.
  std::cout << "client send payload1" << std::endl;
  bsend(payload1); // send to accept udp connection since we are sleeping in one second.

  std::cout << "client send payload2" << std::endl;
  bsend(payload2); // send to accept udp again.

  // recv from sub udp connection
  CHECK_RECV(brecv(payload1));
  CHECK_RECV(brecv(payload2));

  std::cout << "client exit" << std::endl;
  close(sock);
  return;
}

void
udp_echo_server()
{
  Layout::create();
  RecModeT mode_type = RECM_STAND_ALONE;
  RecProcessInit(mode_type);

  Thread *main_thread = new EThread();
  main_thread->set_specific();
  net_config_poll_timeout = 10;
  RecProcessInit(RECM_STAND_ALONE);
  LibRecordsConfigInit();
  ink_net_init(ts::ModuleVersion(1, 0, ts::ModuleVersion::PRIVATE));

  // statPagesManager.init();
  init_diags("udp", nullptr);
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  netProcessor.init();
  eventProcessor.start(1);
  udp2Net.start(1, 1048576);

  initialize_thread_for_net(this_ethread());

  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, signal_handler);

  AcceptServer *server = new AcceptServer;
  (void)server;

  this_thread()->execute();
}

REGRESSION_TEST(UDPNet_echo)(RegressionTest *t, int /* atype ATS_UNUSED */, int *pstatus)
{
  TestBox box(t, pstatus);
  box = REGRESSION_TEST_PASSED;

  int z = pipe(pfd);
  if (z < 0) {
    std::cout << "Unable to create pipe" << std::endl;
    std::exit(EXIT_FAILURE);
  }

  pid = fork();
  if (pid < 0) {
    std::cout << "Couldn't fork" << std::endl;
    std::exit(EXIT_FAILURE);
  } else if (pid == 0) {
    close(pfd[0]);
    udp_echo_server();
  } else {
    close(pfd[1]);
    if (read(pfd[0], &port, sizeof(port)) <= 0) {
      std::cout << "Failed to get signal with port data [" << errno << ']' << std::endl;
      std::exit(EXIT_FAILURE);
    }
    Debug("udp_echo", "client get ports: %d", port);
    udp_client(box);

    // kill(pid, SIGTERM);
    int status;
    wait(&status);

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
      std::cout << "UDP Echo Server exit failure" << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }
}

int
main(int /* argc ATS_UNUSED */, const char ** /* argv ATS_UNUSED */)
{
  RegressionTest::run("UDPNet", REGRESSION_TEST_QUICK);
  return RegressionTest::final_status == REGRESSION_TEST_PASSED ? 0 : 1;
}
