#ifndef NANOMQ_BROKER_H
#define NANOMQ_BROKER_H
#define MQTT_VER 5

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>
#include <nng/protocol/mqtt/mqtt.h>

struct work {
	enum {
		INIT, RECV, WAIT, SEND
	} state;

	nng_aio        *aio;
	nng_msg        *msg;
	nng_ctx        ctx;
	nng_pipe       pid;
	nng_mtx        *mutex;
	struct db_tree *db;

	struct pipe_content       *pipe_ct;
	conn_param                *cparam;
	struct pub_packet_struct  *pub_packet;
	struct packet_subscribe   *sub_pkt;
	struct packet_unsubscribe *unsub_pkt;

};

struct client_ctx {
	nng_pipe                 pid;
	conn_param               *cparam;
	struct packet_subscribe   *sub_pkt;
};

typedef struct work emq_work;

int broker_start(int argc, char **argv);

int broker_dflt(int argc, char **argv);

#endif
