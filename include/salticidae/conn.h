/**
 * Copyright (c) 2018 Cornell University.
 *
 * Author: Ted Yin <tederminant@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _SALTICIDAE_CONN_H
#define _SALTICIDAE_CONN_H

#include <cassert>
#include <cstdint>
#include <event2/event.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string>
#include <unordered_map>
#include <list>
#include <algorithm>
#include <exception>
#include <mutex>
#include <thread>
#include <fcntl.h>
#include <event2/thread.h>

#include "salticidae/type.h"
#include "salticidae/ref.h"
#include "salticidae/event.h"
#include "salticidae/util.h"
#include "salticidae/netaddr.h"
#include "salticidae/msg.h"
#include "salticidae/buffer.h"

namespace salticidae {

struct ConnPoolError: public SalticidaeError {
    using SalticidaeError::SalticidaeError;
};

/** Abstraction for connection management. */
class ConnPool {
    class Worker;
    public:
    class Conn;
    /** The handle to a bi-directional connection. */
    using conn_t = ArcObj<Conn>;
    /** The type of callback invoked when connection status is changed. */
    using conn_callback_t = std::function<void(Conn &, bool)>;
    /** Abstraction for a bi-directional connection. */
    class Conn {
        friend ConnPool;
        public:
        enum ConnMode {
            ACTIVE, /**< the connection is established by connect() */
            PASSIVE, /**< the connection is established by accept() */
        };
    
        protected:
        size_t seg_buff_size;
        conn_t self_ref;
        int fd;
        Worker *worker;
        ConnPool *cpool;
        ConnMode mode;
        NetAddr addr;

        MPSCWriteBuffer send_buffer;
        SegBuffer recv_buffer;

        Event ev_connect;
        Event ev_socket;
        /** does not need to wait if true */
        bool ready_send;
    
        void recv_data(int, int);
        void send_data(int, int);
        void conn_server(int, int);

        /** Terminate the connection. */
        void terminate();

        public:
        Conn(): ready_send(false) {}
        Conn(const Conn &) = delete;
        Conn(Conn &&other) = delete;
    
        virtual ~Conn() {
            SALTICIDAE_LOG_INFO("destroyed %s", std::string(*this).c_str());
        }

        /** Get the handle to itself. */
        conn_t self() { return self_ref; }
        operator std::string() const;
        const NetAddr &get_addr() const { return addr; }
        ConnMode get_mode() const { return mode; }
        ConnPool *get_pool() const { return cpool; }
        MPSCWriteBuffer &get_send_buffer() { return send_buffer; }

        /** Write data to the connection (non-blocking). The data will be sent
         * whenever I/O is available. */
        void write(bytearray_t &&data) {
            send_buffer.push(std::move(data));
        }

        protected:
        /** Close the IO and clear all on-going or planned events. */
        virtual void stop() {
            if (fd == -1) return;
            ev_connect.clear();
            ev_socket.clear();
            send_buffer.get_queue().unreg_handler();
            ::close(fd);
            fd = -1;
            self_ref = nullptr; /* remove the self-cycle */
        }

        /** Called when new data is available. */
        virtual void on_read() {}
        /** Called when the underlying connection is established. */
        virtual void on_setup() {}
        /** Called when the underlying connection breaks. */
        virtual void on_teardown() {}
    };

    protected:
    EventContext ec;
    EventContext disp_ec;
    ThreadCall* disp_tcall;
    /** Should be implemented by derived class to return a new Conn object. */
    virtual Conn *create_conn() = 0;

    private:
    const int max_listen_backlog;
    const double conn_server_timeout;
    const size_t seg_buff_size;

    /* owned by user loop */
    BoxObj<ThreadCall> user_tcall;
    conn_callback_t conn_cb; 

    /* owned by the dispatcher */
    Event ev_listen;
    std::unordered_map<int, conn_t> pool;
    int listen_fd;  /**< for accepting new network connections */

    void update_conn(const conn_t &conn, bool connected) {
        user_tcall->call([this, conn, connected](ThreadCall::Handle &) {
            if (conn_cb) conn_cb(*conn, connected);
        });
    }

    class Worker {
        EventContext ec;
        ThreadCall tcall;
        std::thread handle;

        public:
        Worker(): tcall(ec) {}

        /* the following functions are called by the dispatcher */
        void start() {
            handle = std::thread([this]() { ec.dispatch(); });
        }

        void feed(const conn_t &conn, int client_fd) {
            tcall.call([this, conn, client_fd](ThreadCall::Handle &) {
                SALTICIDAE_LOG_INFO("worker %x got %s",
                        std::this_thread::get_id(),
                        std::string(*conn).c_str());
                conn->get_send_buffer()
                        .get_queue()
                        .reg_handler(this->ec, [conn, client_fd]
                                    (MPSCWriteBuffer::queue_t &) {
                    if (conn->ready_send && conn->fd != -1)
                    {
                        conn->ev_socket.del();
                        conn->ev_socket.add(Event::READ | Event::WRITE);
                        conn->send_data(client_fd, Event::WRITE);
                    }
                    return false;
                });
                //auto conn_ptr = conn.get();
                conn->ev_socket = Event(ec, client_fd, [conn=conn](int fd, int what) {
                    if (what & Event::READ)
                        conn->recv_data(fd, what);
                    else
                        conn->send_data(fd, what);
                });

                //                        std::bind(&Conn::recv_data, conn_ptr, _1, _2));
                //conn->ev_write = Event(ec, client_fd, Event::WRITE,
                //                       std::bind(&Conn::send_data, conn_ptr, _1, _2));
                conn->ev_socket.add(Event::READ | Event::WRITE);
                //conn->ev_write.add();
            });
        }

        void stop() {
            tcall.call([this](ThreadCall::Handle &) { ec.stop(); });
        }

        std::thread &get_handle() { return handle; }
        const EventContext &get_ec() { return ec; }
        ThreadCall *get_tcall() { return &tcall; }
    };

    /* related to workers */
    size_t nworker;
    salticidae::BoxObj<Worker[]> workers;

    void accept_client(int, int);
    conn_t add_conn(const conn_t &conn);
    void remove_conn(int fd);

    protected:
    conn_t _connect(const NetAddr &addr);
    void _listen(NetAddr listen_addr);

    private:

    //class DspMulticast: public DispatchCmd {
    //    std::vector<conn_t> receivers;
    //    bytearray_t data;
    //    public:
    //    DspMulticast(std::vector<conn_t> &&receivers, bytearray_t &&data):
    //        receivers(std::move(receivers)),
    //        data(std::move(data)) {}
    //    void exec(ConnPool *) override {
    //        for (auto &r: receivers) r->write(bytearray_t(data));
    //    }
    //};

    Worker &select_worker() {
        return workers[1];
    }

    public:
    ConnPool(const EventContext &ec,
            int max_listen_backlog = 10,
            double conn_server_timeout = 2,
            size_t seg_buff_size = 4096,
            size_t nworker = 2):
            ec(ec),
            max_listen_backlog(max_listen_backlog),
            conn_server_timeout(conn_server_timeout),
            seg_buff_size(seg_buff_size),
            listen_fd(-1),
            nworker(std::max((size_t)1, nworker)) {
        workers = new Worker[nworker];
        user_tcall = new ThreadCall(ec);
        disp_ec = workers[0].get_ec();
        disp_tcall = workers[0].get_tcall();
    }

    ~ConnPool() {
        stop();
        for (auto it: pool)
        {
            conn_t conn = it.second;
            conn->stop();
        }
        if (listen_fd != -1) close(listen_fd);
    }

    ConnPool(const ConnPool &) = delete;
    ConnPool(ConnPool &&) = delete;

    void start() {
        SALTICIDAE_LOG_INFO("starting all threads...");
        for (size_t i = 0; i < nworker; i++)
            workers[i].start();
    }

    void stop() {
        SALTICIDAE_LOG_INFO("stopping all threads...");
        /* stop all workers */
        for (size_t i = 0; i < nworker; i++)
            workers[i].stop();
        /* join all worker threads */
        for (size_t i = 0; i < nworker; i++)
            workers[i].get_handle().join();
        nworker = 0;
    }

    /** Actively connect to remote addr. */
    conn_t connect(const NetAddr &addr, bool blocking = true) {
        if (blocking)
        {
            auto ret = static_cast<conn_t *>(disp_tcall->call(
                        [this, addr](ThreadCall::Handle &h) {
                auto ptr = new conn_t(_connect(addr));
                std::atomic_thread_fence(std::memory_order_release);
                h.set_result(ptr);
                h.set_deleter([](void *data) {
                    delete static_cast<conn_t *>(data);
                });
            }, true));
            auto conn = *ret;
            delete ret;
            return std::move(conn);
        }
        else
        {
            disp_tcall->call([this, addr](ThreadCall::Handle &) {
                _connect(addr);
            }, false);
            return nullptr;
        }
    }

    /** Listen for passive connections (connection initiated from remote).
     * Does not need to be called if do not want to accept any passive
     * connections. */
    void listen(NetAddr listen_addr) {
        disp_tcall->call([this, listen_addr](ThreadCall::Handle &) {
            _listen(listen_addr);
        }, true);
    }

    template<typename Func>
    void reg_conn_handler(Func cb) { conn_cb = cb; }

    void terminate(const conn_t &conn, bool blocking = true) {
        int fd = conn->fd;
        conn->worker->get_tcall()->call([conn](ThreadCall::Handle &) {
            conn->stop();
        }, blocking);
        remove_conn(fd);
    }
};

}

#endif
