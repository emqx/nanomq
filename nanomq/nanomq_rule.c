#include "include/nanomq_rule.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nng/supplemental/nanolib/cvector.h"

#include "include/nanomq.h"

#if defined(SUPP_RULE_ENGINE)

static char *key_arr[] = {
	"Qos",
	"Id",
	"Topic",
	"Clientid",
	"Username",
	"Password",
	"Timestamp",
	"Payload",
};

static char *type_arr[] = {
	" INT",
	" INT",
	" TEXT",
	" TEXT",
	" TEXT",
	" TEXT",
	" INT",
	" TEXT",
};

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}

int
nano_client_publish(nng_socket *sock, const char *topic, uint8_t *payload,
    uint32_t len, uint8_t qos, property *props)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, true);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);
	if (props) {
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		debug_msg("nng_sendmsg failed %s", nng_strerror(rv));
	}

	return 0;
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	debug_msg("nano client disconnected! RC [%d] \n", reason);
}

// Connack message callback function
static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	debug_msg("nano client connected!\n");
}

int
nano_client(nng_socket *sock, repub_t *repub)
{
	int        rv;
	nng_dialer dialer;

	if (repub->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			fatal("nng_mqttv5_client_open", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			fatal("nng_mqtt_client_open", rv);
			return rv;
		}
	}

	if ((rv = nng_dialer_create(&dialer, *sock, repub->address))) {
		fatal("nng_dialer_create", rv);
		return rv;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, repub->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, repub->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, repub->clean_start);
	if (repub->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, repub->clientid);
	}
	if (repub->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, repub->username);
	}
	if (repub->password) {
		nng_mqtt_msg_set_connect_password(connmsg, repub->password);
	}

	repub->sock = (void *) sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, connect_cb, repub);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

int
nanomq_client_sqlite(conf_rule *cr, bool init_last)
{
	// TODO do all work in a loop
	if (cr->option & RULE_ENG_SDB) {
		sqlite3 *sdb;
		int      rc = 0;
		if (NULL == cr->rdb[0]) {
			char *sqlite_path = cr->sqlite_db_path
			    ? cr->sqlite_db_path
			    : "/tmp/rule_engine.db";
			rc                = sqlite3_open(sqlite_path, &sdb);
			if (rc != SQLITE_OK) {
				debug_msg("Cannot open database: %s\n",
				    sqlite3_errmsg(sdb));
				sqlite3_close(sdb);
				exit(1);
			}
			cr->rdb[0] = (void *) sdb;
		}

		char sqlite_table[1024];
		for (int i = 0; i < cvector_size(cr->rules); i++) {
			if (init_last && i != cvector_size(cr->rules) - 1) {
				continue;
			}
			if (RULE_FORWORD_SQLITE == cr->rules[i].forword_type) {
				int  index      = 0;
				char table[256] = { 0 };

				snprintf(table, 128,
				    "CREATE TABLE IF NOT EXISTS %s("
				    "RowId INTEGER PRIMARY KEY AUTOINCREMENT",
				    cr->rules[i].sqlite_table);
				char *err_msg = NULL;
				bool  first   = true;

				for (; index < 8; index++) {
					if (!cr->rules[i].flag[index])
						continue;

					strcat(table, ", ");
					strcat(table,
					    cr->rules[i].as[index]
					        ? cr->rules[i].as[index]
					        : key_arr[index]);
					strcat(table, type_arr[index]);
				}
				strcat(table, ");");
				// puts(table);
				rc = sqlite3_exec(cr->rdb[0], table, 0, 0, &err_msg);
				if (rc != SQLITE_OK) {
					debug_msg("SQL error: %s\n", err_msg);
					sqlite3_free(err_msg);
					sqlite3_close(sdb);
					return 1;
				}
			}
		}
	}

	return 0;
}

#endif