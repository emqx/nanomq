#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/mqtt_api.h"

#ifdef SUPP_QUIC
#include "nng/mqtt/mqtt_quic_client.h"
#endif

#ifdef NNG_SUPP_TLS
#include "nng/supplemental/tls/tls.h"
static int init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass);
#endif

static const char *quic_scheme = "mqtt-quic";
static const char *tcp_scheme  = "mqtt-tcp";
static const char *tls_scheme  = "tls+mqtt-tcp";

// lock is necessary for protecting nni_sock
static nng_mtx *reload_lock = NULL;

static void bridge_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
static void bridge_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);

#if defined(SUPP_QUIC)
static void bridge_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
static void bridge_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg);
#endif

static property *sub_property(conf_bridge_sub_properties *conf_prop);
static property *conn_property(conf_bridge_conn_properties *conf_prop);
static property *will_property(conf_bridge_conn_will_properties *will_prop);

static nng_thread *hybrid_thr;

static int execone = 0;

static int
apply_sqlite_config(
    nng_socket *sock, conf_bridge_node *config, const char *db_name)
{
#if defined(NNG_SUPP_SQLITE)
	int rv;
	// create sqlite option
	nng_mqtt_sqlite_option *opt;
	if ((rv = nng_mqtt_alloc_sqlite_opt(&opt)) != 0) {
		NANO_NNG_FATAL("Initializing SQLite with nng_mqtt_alloc_sqlite_opt", rv);
	}

	nng_mqtt_set_sqlite_conf(opt, config);
	// init sqlite db
	nng_mqtt_sqlite_db_init(opt, db_name);

	// set sqlite option pointer to socket
	return nng_socket_set_ptr(*sock, NNG_OPT_MQTT_SQLITE, opt);
#else
	return (0);
#endif
}
#if defined(SUPP_QUIC)
static void
nano_set_quic_config(nng_socket *sock, conf_bridge_node *node, nng_dialer *dialer)
{
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_BRIDGE_CONF, node)) {
		log_warn("Error in updating bridge config to socket");
	}
	nng_dialer_set_bool(*dialer, NNG_OPT_QUIC_ENABLE_0RTT, node->quic_0rtt);
	nng_dialer_set_bool(*dialer, NNG_OPT_QUIC_ENABLE_MULTISTREAM, node->multi_stream);
	nng_dialer_set_uint64(*dialer, NNG_OPT_QUIC_IDLE_TIMEOUT, node->qidle_timeout);
	nng_dialer_set_uint64(*dialer, NNG_OPT_QUIC_CONNECT_TIMEOUT, node->qconnect_timeout);
	nng_dialer_set_int(*dialer, NNG_OPT_QUIC_DISCONNECT_TIMEOUT, node->qdiscon_timeout);
	nng_dialer_set_int(*dialer, NNG_OPT_QUIC_KEEPALIVE, node->qkeepalive);
	nng_dialer_set_int(*dialer, NNG_OPT_QUIC_SEND_IDLE_TIMEOUT, node->qsend_idle_timeout);
	nng_dialer_set_int(*dialer, NNG_OPT_QUIC_INITIAL_RTT_MS, node->qinitial_rtt_ms);
	nng_dialer_set_int(*dialer, NNG_OPT_QUIC_MAX_ACK_DELAY_MS, node->qmax_ack_delay_ms);

	// NNG_OPT_QUIC_PRIORITY
	// TLS section
	if (!node->tls.enable)
		return;
	if (0 !=
	    nng_dialer_set_string(
	        *dialer, NNG_OPT_QUIC_TLS_KEY_PATH, node->tls.keyfile)) {
		log_warn("Error in updating NNG_OPT_QUIC_TLS_KEY_PATH");
	}
	if (0 !=
	    nng_dialer_set_string(
	        *dialer, NNG_OPT_QUIC_TLS_CACERT_PATH, node->tls.certfile)) {
		log_warn("Error in updating NNG_OPT_QUIC_TLS_CACERT_PATH");
	}
	if (0 !=
	    nng_dialer_set_string(*dialer, NNG_OPT_QUIC_TLS_KEY_PASSWORD,
	        node->tls.key_password)) {
		log_warn("Error in updating NNG_OPT_QUIC_TLS_KEY_PASSWORD");
	}
	if (0 !=
	    nng_dialer_set_string(
	        *dialer, NNG_OPT_QUIC_TLS_CA_PATH, node->tls.cafile)) {
		log_warn("Error in updating NNG_OPT_QUIC_TLS_CA_PATH");
	}
	if (0 !=
	    nng_dialer_set_bool(*dialer, NNG_OPT_QUIC_TLS_VERIFY_PEER,
	        node->tls.verify_peer)) {
		log_warn("Error in updating NNG_OPT_QUIC_TLS_VERIFY_PEER");
	}
}
#endif

nng_msg *
create_connect_msg(conf_bridge_node *node)
{
	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, node->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, node->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, node->clean_start);
	if (node->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, node->clientid);
	}
	if (node->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, node->username);
	}
	if (node->password) {
		nng_mqtt_msg_set_connect_password(connmsg, node->password);
	}
	if (node->will_flag) {
		nng_mqtt_msg_set_connect_will_topic(connmsg, node->will_topic);
		nng_mqtt_msg_set_connect_will_msg(connmsg,
		    (uint8_t *) node->will_payload,
		    strlen(node->will_payload));
		nng_mqtt_msg_set_connect_will_qos(connmsg, node->will_qos);
		nng_mqtt_msg_set_connect_will_retain(
		    connmsg, node->will_retain);
	}

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		property *properties = conn_property(node->conn_properties);
		nng_mqtt_msg_set_connect_property(connmsg, properties);
		if (node->will_flag) {
			property *will_properties =
			    will_property(node->will_properties);
			nng_mqtt_msg_set_connect_will_property(
			    connmsg, will_properties);
		}
		nng_mqttv5_msg_encode(connmsg);
	} else {
		nng_mqtt_msg_encode(connmsg);
	}
	return connmsg;
}

nng_msg *
create_disconnect_msg()
{
	nng_msg *msg;
	if (0 != nng_mqtt_msg_alloc(&msg, 0))
		return NULL;

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_DISCONNECT);
	nng_mqtt_msg_set_disconnect_reason_code(msg, NORMAL_DISCONNECTION);

	return msg;
}
// TODO move to RECV state of PROTO_BRIDGE, however we need to modify original msg
// duplicate msg
static inline void
bridge_handle_topic_sub_reflection(nano_work *work, conf_bridge_node *node)
{
	int rv = 0;
	mqtt_string *topic;
	topic = nng_zalloc(sizeof(*topic));
	for (size_t i = 0; i < node->sub_count; i++) {
		rv = 0;
		topic->body = work->pub_packet->var_header.publish.topic_name.body;
		topic->len  = work->pub_packet->var_header.publish.topic_name.len;
		if (topic->body != NULL && node->sub_list[i]->remote_topic != NULL) {
			// Reminder: We ignore the overlaping matches. only the very first one prevail
			// There is no way to know msg comes from which topic if we use overlaped wildcard
			// unless limit this to MQTT v5 sub id.
			if (topic_filter(node->sub_list[i]->remote_topic, topic->body)) {
				topics *sub_topic = node->sub_list[i];

				// No local topic change and keep it as it is if local topic == ""
				if (sub_topic->local_topic_len == 0) {
					goto fix;
				}
				topic->body = nng_strdup(sub_topic->local_topic);
				topic->len = strlen(topic->body);
				rv = NNG_STAT_STRING;
				if (topic->body == NULL) {
					log_error("bridge: alloc local_topic failed");
					nng_free(topic, sizeof(topic));
					return;
				}
fix:
				nng_mqtt_msg_set_bridge_bool(work->msg, true);
				// TODO replace bridge bool with sub retain bool
				// nng_mqtt_msg_set_sub_retain_bool(work->msg, true);
				/* check prefix/suffix */
				if (node->sub_list[i]->prefix != NULL) {
					char *tmp = topic->body;
					topic->body =
						nng_strnins(topic->body, node->sub_list[i]->prefix,
									topic->len, node->sub_list[i]->prefix_len);
					topic->len = strlen(topic->body);
					if (rv == NNG_STAT_STRING)
						nng_free(tmp, strlen(tmp));
					rv = NNG_STAT_STRING;	//mark it for free
				}
				if (node->sub_list[i]->suffix != NULL) {
					char *tmp = topic->body;
					topic->body =
						nng_strncat(topic->body, node->sub_list[i]->suffix,
									topic->len, node->sub_list[i]->suffix_len);
					topic->len = strlen(topic->body);
					if (rv == NNG_STAT_STRING)
						nng_free(tmp, strlen(tmp));
					rv = NNG_STAT_STRING;	//mark it for free
				}
				work->pub_packet->fixed_header.retain =
				    sub_topic->retain == NO_RETAIN
				    ? work->pub_packet->fixed_header.retain
				    : sub_topic->retain;
				/* release old topic area */
				if (rv != 0) {
					nng_strfree(work->pub_packet->var_header.publish.topic_name.body);
					work->pub_packet->var_header.publish.topic_name.body = topic->body;
					work->pub_packet->var_header.publish.topic_name.len = topic->len;
				}
				nng_free(topic, sizeof(topic));
				return;
			}
		}
	}
	nng_free(topic, sizeof(topic));
	return;
}

void
bridge_handle_topic_reflection(nano_work *work, conf_bridge *bridge)
{
	// for saving CPU
	if (work->flag == CMD_PUBLISH) {
		if (work->node != NULL)
			bridge_handle_topic_sub_reflection(work, work->node);
		else
			for (size_t i = 0; i < bridge->count; i++) {
				conf_bridge_node *node = bridge->nodes[i];
				if (node->enable) {
					bridge_handle_topic_sub_reflection(work, node);
				}
			}
	}
	return;
}

nng_msg *
bridge_publish_msg(const char *topic, uint8_t *payload, uint32_t len, bool dup,
    uint8_t qos, bool retain, property *props)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	// we dont check rv only because this is already a valid msg from another broker
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, dup);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, retain);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);
	if (props) {
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}
	log_debug("bridge: publish to '%s'", topic);

	return pubmsg;
}

static void
send_callback(nng_mqtt_client *client, nng_msg *msg, void *obj)
{
	nng_aio *aio = client->send_aio;
	uint32_t count;
	uint8_t *code;
	uint8_t  type;

	if (nng_aio_result(aio) != 0 || msg == NULL) {
		return;
	}
	type = nng_msg_get_type(msg);
	if (type == CMD_SUBACK) {
		code = nng_mqtt_msg_get_suback_return_codes(msg, &count);
		log_info("bridge: subscribe aio result %d", nng_aio_result(aio));
		for (int i=0; i<count; ++i) {
			log_info("bridge: suback code %d ", *(code + i));
		}
		nng_msg_free(msg);
	} else if(type == CMD_CONNECT) {
		log_debug("send bridge connect msg complete");
	} else if(type == CMD_SUBSCRIBE) {
		log_debug("send bridge sub msg complete");
	} else if(type == CMD_UNSUBSCRIBE) {
		log_debug("send bridge unsub msg complete");
	} else if(type == CMD_UNSUBACK) {
		code = nng_mqtt_msg_get_unsuback_return_codes(msg, &count);
		log_info("bridge: unsubscribe aio result %d", nng_aio_result(aio));
		for (int i=0; i<count; ++i) {
			log_info("bridge: unsuback code %d ", *(code + i));
		}
		nng_msg_free(msg);
	}
}

#ifdef NNG_SUPP_TLS
static int
init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if (cert != NULL && key != NULL) {
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, pass)) !=
		    0) {
			goto out;
		}
	}
	if (cacert != NULL) {
		if ((rv = nng_tls_config_ca_chain(cfg, cacert, NULL)) != 0) {
			goto out;
		}
	}

	rv = nng_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

#endif

static property *
sub_property(conf_bridge_sub_properties *conf_prop)
{
	if (conf_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;

		if (conf_prop->identifier != 0xffffffff) {
			prop = mqtt_property_set_value_varint(
			    SUBSCRIPTION_IDENTIFIER, conf_prop->identifier);
			mqtt_property_append(link_list, prop);
		}

		if (conf_prop->user_property_size > 0 &&
		    conf_prop->user_property) {
			for (size_t i = 0; i < conf_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    conf_prop->user_property[i]->key,
				    strlen(conf_prop->user_property[i]->key),
				    conf_prop->user_property[i]->value,
				    strlen(conf_prop->user_property[i]->value),
				    false);
				mqtt_property_append(link_list, prop);
			}
		}
		return link_list;
	}
	return NULL;
}

static property *
will_property(conf_bridge_conn_will_properties *will_prop)
{
	if (will_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;
		if (will_prop->payload_format_indicator != 0) {
			prop = mqtt_property_set_value_u8(
			    PAYLOAD_FORMAT_INDICATOR,
			    will_prop->payload_format_indicator);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->message_expiry_interval != 0) {
			prop = mqtt_property_set_value_u32(
			    MESSAGE_EXPIRY_INTERVAL,
			    will_prop->message_expiry_interval);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->content_type) {
			prop = mqtt_property_set_value_str(CONTENT_TYPE,
			    will_prop->content_type,
			    strlen(will_prop->content_type), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->response_topic) {
			prop = mqtt_property_set_value_str(RESPONSE_TOPIC,
			    will_prop->response_topic,
			    strlen(will_prop->response_topic), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->correlation_data) {
			prop = mqtt_property_set_value_str(CORRELATION_DATA,
			    will_prop->correlation_data,
			    strlen(will_prop->correlation_data), false);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->will_delay_interval != 0) {
			prop = mqtt_property_set_value_u32(WILL_DELAY_INTERVAL,
			    will_prop->will_delay_interval);
			mqtt_property_append(link_list, prop);
		}
		if (will_prop->user_property_size > 0 &&
		    will_prop->user_property) {
			for (size_t i = 0; i < will_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    will_prop->user_property[i]->key,
				    strlen(will_prop->user_property[i]->key),
				    will_prop->user_property[i]->value,
				    strlen(will_prop->user_property[i]->value),
				    false);
				mqtt_property_append(link_list, prop);
			}
		}
		return link_list;
	}
	return NULL;
}

static property *
conn_property(conf_bridge_conn_properties *conf_prop)
{
	if (conf_prop) {
		property *link_list = mqtt_property_alloc();
		property *prop;
		if (conf_prop->maximum_packet_size != 0) {
			prop = mqtt_property_set_value_u32(MAXIMUM_PACKET_SIZE,
			    conf_prop->maximum_packet_size);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->receive_maximum != 65535) {
			prop = mqtt_property_set_value_u16(
			    RECEIVE_MAXIMUM, conf_prop->receive_maximum);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->topic_alias_maximum != 0) {
			prop = mqtt_property_set_value_u16(TOPIC_ALIAS_MAXIMUM,
			    conf_prop->topic_alias_maximum);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->request_response_info != 0) {
			prop = mqtt_property_set_value_u8(
			    REQUEST_RESPONSE_INFORMATION,
			    conf_prop->request_response_info);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->request_problem_info != 1) {
			prop = mqtt_property_set_value_u8(
			    REQUEST_PROBLEM_INFORMATION,
			    conf_prop->request_problem_info);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->session_expiry_interval != 0) {
			prop = mqtt_property_set_value_u32(
			    SESSION_EXPIRY_INTERVAL,
			    conf_prop->session_expiry_interval);
			mqtt_property_append(link_list, prop);
		}
		if (conf_prop->user_property_size > 0 &&
		    conf_prop->user_property) {
			for (size_t i = 0; i < conf_prop->user_property_size;
			     i++) {
				prop = mqtt_property_set_value_strpair(
				    USER_PROPERTY,
				    conf_prop->user_property[i]->key,
				    strlen(conf_prop->user_property[i]->key),
				    conf_prop->user_property[i]->value,
				    strlen(conf_prop->user_property[i]->value),
				    false);
				mqtt_property_append(link_list, prop);
			}
		}
		return link_list;
	}
	return NULL;
}

static void
hybrid_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	bridge_tcp_connect_cb(p, ev, arg);
}

// Disconnect message callback function for hybrid bridging
static void
hybrid_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_warn("bridge client disconnected! RC [%d] \n", reason);
	bridge_param *bridge_arg = arg;

	nng_mtx_lock(bridge_arg->switch_mtx);
	nng_cv_wake1(bridge_arg->switch_cv);
	nng_mtx_unlock(bridge_arg->switch_mtx);
}

static int
hybrid_tcp_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));

	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));
	conf_bridge_node *node = bridge_arg->config;

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(new)) != 0) {
			nng_free(new, sizeof(nng_socket));
			log_error("Initializing mqttv5 client failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(new)) != 0) {
			nng_free(new, sizeof(nng_socket));
			log_error("Initializing mqtt client failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(new, node, "mqtt_client.db");
	nng_socket_set_string(*new, NNG_OPT_SOCKNAME, node->name);

	if ((rv = nng_dialer_create(dialer, *new, node->address))) {
		nng_free(new, sizeof(nng_socket));
		log_error("nng_dialer_create %d", rv);
		return rv;
	}
	node->dialer = dialer;

#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(*dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			nng_free(new, sizeof(nng_socket));
			log_error("init_dialer_tls %d", rv);
			return rv;
		}
	}
#endif

	bridge_arg->client = nng_mqtt_client_alloc(*new, &send_callback, true);

	nng_msg *connmsg   = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	nng_socket *tsock  = bridge_arg->sock;
	if (tsock) {
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
	}
	node->sock         = (void *) new;
	bridge_arg->sock   = new;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*new, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(*new, hybrid_tcp_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*new, hybrid_tcp_disconnect_cb, bridge_arg);

	if (node->enable) {
		if (0 != (rv = nng_dialer_start(*dialer, NNG_FLAG_ALLOC))) {
			log_error("nng dialer start failed %d", rv);
			return rv;
		}
	}
	return 0;
}

#if defined(SUPP_QUIC)
// Disconnect message callback function
static void
hybrid_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_warn("quic bridge client disconnected! RC [%d] \n", reason);
	bridge_param *bridge_arg = arg;

	nng_mtx_lock(bridge_arg->switch_mtx);
	nng_cv_wake1(bridge_arg->switch_cv);
	nng_mtx_unlock(bridge_arg->switch_mtx);
}

static void
hybrid_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	bridge_quic_connect_cb(p, ev, arg);
}

static int
hybrid_quic_client(bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));
	log_info("Quic hybrid service start.");

	// always alloc a new sock pointer in hybrid mode
	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));
	conf_bridge_node* node = bridge_arg->config;

	// keepalive here is for QUIC only
	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_quic_client_open(new)) != 0) {
			log_error("Initializing mqttv5 QUIC client failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_quic_client_open(new)) != 0) {
			log_error("Initializing mqtt quic client failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(new, node, "mqtt_quic_client.db");
	nng_socket_set_string(*new, NNG_OPT_SOCKNAME, node->name);

	if ((rv = nng_dialer_create(dialer, *new, node->address))) {
		log_error("dialer create failed %d", rv);
		return rv;
	}
	node->dialer = dialer;

	bridge_arg->client = nng_mqtt_client_alloc(*new, &send_callback, true);

	nng_msg *connmsg   = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	execone = 0;

	nng_socket *tsock  = bridge_arg->sock;
	if (tsock) {
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
	}
	node->sock         = (void *) new;
	bridge_arg->sock   = new;

	// TCP bridge does not support hot update of connmsg
	nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_socket_set_ptr(*new, NNG_OPT_MQTT_CONNMSG, connmsg);
	nano_set_quic_config(new, node, dialer);
	nng_mqtt_set_connect_cb(*new, hybrid_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*new, hybrid_quic_disconnect_cb, bridge_arg);

	if (node->enable) {
		rv = nng_dialer_start(*dialer, NNG_FLAG_ALLOC);
		if (rv != 0) {
			log_error("nng dialer start failed %d", rv);
			return rv;
		}
	}

	return 0;
}
#endif

static int
gen_fallback_url(char *url, char *new) {
	int pos_ip = 0;
	int len_ip = 0;
	for (int i=0; i<strlen(url)-1; ++i)
		if (url[i] == '/' && url[i+1] == '/')
			pos_ip = i+2;
	for (int i=pos_ip; i<strlen(url); ++i) {
		if (url[i] == ':')
			break;
		len_ip ++;
	}
	if (len_ip < 2)
		return -1;
	strncpy(new, "mqtt-tcp://", 11);
	strncpy(new+11, url+pos_ip, len_ip);
	strncpy(new+11+len_ip, ":1883", 5);
	return 0;
}

static void
hybrid_cb(void *arg)
{
	bridge_param *bridge_arg = arg;
	conf_bridge_node *node = bridge_arg->config;

	int rv = nng_mtx_alloc(&bridge_arg->switch_mtx);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_mtx_alloc mem error", rv);
		return;
	}
	rv = nng_cv_alloc(&bridge_arg->switch_cv, bridge_arg->switch_mtx);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_cv_alloc mem error", rv);
		return;
	}
	// uint32_t aio_cnt = bridge_arg->conf->parallel + node->parallel;
	// alloc an AIO for each ctx bridging use only
	node->bridge_aio = nng_alloc(bridge_arg->conf->total_ctx * sizeof(nng_aio *));

	for (uint32_t num = 0; num < bridge_arg->conf->total_ctx; num++) {
		if ((rv = nng_aio_alloc(&node->bridge_aio[num], NULL, node)) != 0) {
			NANO_NNG_FATAL("bridge_aio nng_aio_alloc", rv);
		}
	}
	char **addrs = node->hybrid_servers;
	cvector_insert(addrs, 0, strdup(node->address));
	int    addrslen = cvector_size(node->hybrid_servers);
	int    idx = -1;
	for (;;) {
		// Get next bridge node
		nng_socket *tsock = bridge_arg->sock;
		idx = (idx + 1) % addrslen;
		node->address = addrs[idx];
		log_warn("!! Bridge has switched to [%d]%s", idx, node->address);

		if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
		    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
			if (0 != hybrid_tcp_client(bridge_arg)) {
				continue;
			}
#if defined(SUPP_QUIC)
		} else if (0 ==
		    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
			if (0 != hybrid_quic_client(bridge_arg)) {
				continue;
			}
#endif
		} else {
			log_error("Unsupported bridge protocol.");
		}
		if (bridge_arg->exec_cv) {
			nng_mtx_lock(bridge_arg->exec_mtx);
			nng_cv_wake1(bridge_arg->exec_cv);
			nng_mtx_unlock(bridge_arg->exec_mtx);
		}
		nng_mtx_lock(bridge_arg->switch_mtx);
		nng_cv_wait(bridge_arg->switch_cv);
		nng_mtx_unlock(bridge_arg->switch_mtx);
		// Free bridge client
		if (bridge_arg->client) {
			nng_aio_finish_error(bridge_arg->client->send_aio, NNG_ECLOSED);
			nng_mqtt_client_free(bridge_arg->client, true);
			bridge_arg->client = NULL;
		}
	}

	log_warn("Hybrid thread is done");
	nng_cv_free(bridge_arg->switch_cv);
	nng_mtx_free(bridge_arg->switch_mtx);
	bridge_arg->switch_cv = NULL;
	bridge_arg->switch_mtx = NULL;
}

int
hybrid_bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	bridge_param *bridge_arg = NULL;
	if ((bridge_arg = nng_alloc(sizeof(bridge_param))) == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}
	bridge_arg->exec_mtx = NULL;
	bridge_arg->exec_cv  = NULL;

	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->conf   = config;
	if (reload_lock == NULL) {
		nng_mtx_alloc(&reload_lock);
	}

	int rv = nng_mtx_alloc(&bridge_arg->exec_mtx);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_mtx_alloc", rv);
		goto error;
	}
	rv = nng_cv_alloc(&bridge_arg->exec_cv, bridge_arg->exec_mtx);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_cv_alloc", rv);
		goto error;
	}

	rv = nng_thread_create(&hybrid_thr, hybrid_cb, (void *)bridge_arg);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_thread_create", rv);
		goto error;
	}

	nng_mtx_lock(bridge_arg->exec_mtx);
	nng_cv_wait(bridge_arg->exec_cv);
	nng_mtx_unlock(bridge_arg->exec_mtx);
	nng_cv_free(bridge_arg->exec_cv);
	bridge_arg->exec_cv = NULL;
	return 0;

error:
	if(bridge_arg->exec_cv != NULL) {
		nng_cv_free(bridge_arg->exec_cv);
	}
	if(bridge_arg->exec_mtx != NULL) {
		nng_mtx_free(bridge_arg->exec_mtx);
	}
	if(bridge_arg != NULL) {
		nng_free(bridge_arg, sizeof(bridge_param));
	}

	return rv;
}

#if defined(SUPP_QUIC)

// Connack message callback function
static void
bridge_quic_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	// Connected succeed
	bridge_param *param  = arg;
	int           reason = 0;
	char         *addr;
	uint16_t      port;

	if (execone > 0) {
		return;
	}

	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	addr = nano_pipe_get_local_address(p);
	port = nano_pipe_get_local_port(p);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Bridge client connected! RC [%d]", reason);
	log_info("Local ip4 address [%s] port [%d]", addr, port);

	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_client *client = param->client;
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos *topic_qos =
			    nng_mqtt_topic_qos_array_create(1);
			nng_mqtt_topic_qos_array_set(topic_qos, 0,
			    param->config->sub_list[i]->remote_topic,
			    param->config->sub_list[i]->qos, 1,
				param->config->sub_list[i]->retain_as_published,
			    param->config->sub_list[i]->retain_handling);
			log_info("Quic bridge client subscribe to "
			         "topic (QoS %d)%s.",
			    param->config->sub_list[i]->qos,
			    param->config->sub_list[i]->remote_topic);

			property *properties = NULL;
			if (param->config->proto_ver ==
			    MQTT_PROTOCOL_VERSION_v5) {
				properties = sub_property(
				    param->config->sub_properties);
			}
			nng_aio_set_timeout(client->send_aio, param->cancel_timeout);
			nng_mqtt_subscribe_async(
			    client, topic_qos, 1, properties);
			nng_mqtt_topic_qos_array_free(topic_qos, 1);
		}
		execone ++;
	}

	if (addr)
		free(addr);
}

// Disconnect message callback function
static void
bridge_quic_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_warn("bridge client disconnected! RC [%d] \n", reason);

	bridge_param *bridge_arg = arg;
	// Free cparam kept
	// void *cparam = nng_msg_get_conn_param(bridge_arg->connmsg);
	// if (cparam != NULL)
	//  conn_param_free(cparam);
	// nng_msg_free(bridge_arg->connmsg);
	// bridge_arg->connmsg = NULL;

	execone --;
}

static int
bridge_quic_reload(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_quic_client_open(sock)) != 0) {
			log_error("Initializing mqttv5 quic client failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_quic_client_open(sock)) != 0) {
			log_error("Initializing mqttv quic client failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_quic_client.db");

	if ((rv = nng_dialer_create(dialer, *sock, node->address))) {
		log_error("nng_dialer_create failed %d", rv);
		return rv;
	}
	node->dialer = dialer;

	nng_duration duration = (nng_duration) node->backoff_max * 1000;
	nng_dialer_set(*dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));

	bridge_arg->client->sock   = *sock;
	bridge_arg->cancel_timeout = node->cancel_timeout;

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	execone = 0;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nano_set_quic_config(sock, node, dialer);
	nng_mqtt_set_connect_cb(*sock, bridge_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_quic_disconnect_cb, bridge_arg);

	if (node->enable) {
		rv = nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK);
		if (rv != 0)
			log_error("nng dialer start failed %d", rv);
	}

	return 0;
}

static int
bridge_quic_client(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));
	log_debug("Quic bridge service start.\n");

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_quic_client_open(sock)) != 0) {
			log_error("Initializing mqttv5 quic client failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_quic_client_open(sock)) != 0) {
			log_error("Initializing mqtt quic client failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_quic_client.db");
	nng_socket_set_string(*sock, NNG_OPT_SOCKNAME, node->name);

	if ((rv = nng_dialer_create(dialer, *sock, node->address))) {
		log_error("nng_dialer_create failed %d", rv);
		return rv;
	}
	node->dialer = dialer;

	nng_duration duration = (nng_duration) node->backoff_max * 1000;
	nng_dialer_set(*dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));
	nng_dialer_set_bool(*dialer, NNG_OPT_QUIC_ENABLE_0RTT, true);
	if (node->multi_stream) {
		//better remove the option from dialer
		nng_dialer_set_bool(*dialer, NNG_OPT_QUIC_ENABLE_MULTISTREAM, true);
		nng_socket_set_bool(*sock, NNG_OPT_QUIC_ENABLE_MULTISTREAM, true);
	}
	bridge_arg->client = nng_mqtt_client_alloc(*sock, &send_callback, true);
	bridge_arg->cancel_timeout = node->cancel_timeout;

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// QUIC bridge does not support hot update of connmsg as well
	if (0 != nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nano_set_quic_config(sock, node, dialer);
	nng_mqtt_set_connect_cb(*sock, bridge_quic_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_quic_disconnect_cb, bridge_arg);

	if (node->enable) {
		rv = nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK);
		if (rv != 0)
			log_error("nng dialer start failed %d", rv);
	}

	return rv;
}
#endif

// Connack message callback function
static void
bridge_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	// Connected succeed
	bridge_param *param  = arg;
	int           reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("Bridge [%s] connected! RC [%d]", param->config->address, reason);

	/* MQTT SUBSCRIBE */
	if (reason == 0 && param->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i]->remote_topic,
			    param->config->sub_list[i]->qos, 1,
			    param->config->sub_list[i]->retain_as_published,
			    param->config->sub_list[i]->retain_handling);
			log_info("Bridge client subscribed topic %s (qos %d rap %d rh %d).",
			    param->config->sub_list[i]->remote_topic,
			    param->config->sub_list[i]->qos,
				param->config->sub_list[i]->retain_as_published,
				param->config->sub_list[i]->retain_handling);
		}
		nng_mqtt_client *client = param->client;

		// Property
		property *properties = NULL;
		if (param->config->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
			properties =
			    sub_property(param->config->sub_properties);
		}
		nng_aio_set_timeout(client->send_aio, param->cancel_timeout);
		nng_mqtt_subscribe_async(
		    client, topic_qos, param->config->sub_count, properties);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, param->config->sub_count);
	}
	if (param->config->sub_count == 0) {
		log_info("No subscriptions were set.");
	}
}

// Disconnect message callback function
static void
bridge_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_warn("bridge client disconnected! RC [%d] \n", reason);

	bridge_param *bridge_arg = arg;
	// Free cparam kept
	// void *cparam = nng_msg_get_conn_param(bridge_arg->connmsg);
	// if (cparam != NULL)
	//  conn_param_free(cparam);
	// nng_msg_free(bridge_arg->connmsg);
	// bridge_arg->connmsg = NULL;
}


static int
bridge_tcp_reload(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			log_error(" nng_mqttv5_client_open failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			log_error(" nng_mqtt_client_open failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_client.db");

	if ((rv = nng_dialer_create(dialer, *sock, node->address))) {
		log_error("nng_dialer_create failed %d", rv);
		return rv;
	}
	node->dialer = dialer;

	nng_duration duration = (nng_duration) node->backoff_max * 1000;
	nng_dialer_set(*dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));


#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(*dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			log_error("init_dialer_tls failed %d", rv);
			return rv;
		}
	}
#endif

	bridge_arg->client->sock   = *sock;
	bridge_arg->cancel_timeout = node->cancel_timeout;

	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_duration retry = node->resend_interval;
	nng_socket_set_ms(*sock, NNG_OPT_MQTT_RETRY_INTERVAL, retry);
	nng_time retry_wait = node->resend_wait;
	nng_socket_set_uint64(*sock, NNG_OPT_MQTT_RETRY_WAIT_TIME, retry_wait);
	nng_mqtt_set_connect_cb(*sock, NULL, NULL);
	nng_mqtt_set_disconnect_cb(*sock, bridge_tcp_disconnect_cb, bridge_arg);

	if (node->enable) {
		rv = nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK);
		if (rv != 0)
			log_warn("nng_dialer_start %d %s", rv, node->clientid);
	}

	if (bridge_arg->config->sub_count > 0) {
		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(
		        bridge_arg->config->sub_count);
		for (size_t i = 0; i < bridge_arg->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    bridge_arg->config->sub_list[i]->remote_topic,
			    bridge_arg->config->sub_list[i]->qos, 1,
			    bridge_arg->config->sub_list[i]->retain_as_published,
			    bridge_arg->config->sub_list[i]->retain_handling);
			log_info("Bridge client subscribed topic %s (qos %d rap %d rh %d).",
			    bridge_arg->config->sub_list[i]->remote_topic,
			    bridge_arg->config->sub_list[i]->qos,
				bridge_arg->config->sub_list[i]->retain_as_published,
				bridge_arg->config->sub_list[i]->retain_handling);
		}
		nng_mqtt_client *client = bridge_arg->client;

		// Property
		property *properties = NULL;
		if (bridge_arg->config->proto_ver ==
		    MQTT_PROTOCOL_VERSION_v5) {
			properties =
			    sub_property(bridge_arg->config->sub_properties);
		}
		nng_aio_set_timeout(client->send_aio, node->cancel_timeout);
		nng_mqtt_subscribe_async(client, topic_qos,
		    bridge_arg->config->sub_count, properties);
		nng_mqtt_topic_qos_array_free(
		    topic_qos, bridge_arg->config->sub_count);
	}
	return 0;
}


static int
bridge_tcp_client(nng_socket *sock, conf *config, conf_bridge_node *node, bridge_param *bridge_arg)
{
	int           rv;
	nng_dialer    *dialer = (nng_dialer *) nng_alloc(sizeof(nng_dialer));

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			log_error("nng_mqttv5_client_open failed %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			log_error("nng_mqtt_client_open failed %d", rv);
			return rv;
		}
	}

	apply_sqlite_config(sock, node, "mqtt_client.db");
	nng_socket_set_string(*sock, NNG_OPT_SOCKNAME, node->name);

	if ((rv = nng_dialer_create(dialer, *sock, node->address))) {
		log_error("nng_dialer_create failed %d", rv);
		return rv;
	}
	node->dialer = dialer;

	nng_duration duration = (nng_duration) node->backoff_max * 1000;
	nng_dialer_set(*dialer, NNG_OPT_MQTT_RECONNECT_BACKOFF_MAX, &duration, sizeof(nng_duration));

	if (node->tcp.enable) {
		// set bridge dialer tcp options
		bool nodelay   = node->tcp.nodelay == 1 ? true : false;
		bool keepalive = node->tcp.keepalive == 1 ? true : false;
		nng_dialer_set(
		    *dialer, NNG_OPT_TCP_NODELAY, &nodelay, sizeof(bool));
		nng_dialer_set(
		    *dialer, NNG_OPT_TCP_KEEPALIVE, &keepalive, sizeof(bool));
		if (node->tcp.keepalive == 1) {
			nng_dialer_set(*dialer, NNG_OPT_TCP_QUICKACK,
			    &(node->tcp.quickack), sizeof(int));
			nng_dialer_set(*dialer, NNG_OPT_TCP_KEEPIDLE,
			    &(node->tcp.keepidle), sizeof(int));
			nng_dialer_set(*dialer, NNG_OPT_TCP_KEEPINTVL,
			    &(node->tcp.keepintvl), sizeof(int));
			nng_dialer_set(*dialer, NNG_OPT_TCP_KEEPCNT,
			    &(node->tcp.keepcnt), sizeof(int));
			nng_dialer_set(*dialer, NNG_OPT_TCP_SENDTIMEO,
			    &(node->tcp.sendtimeo), sizeof(int));
			nng_dialer_set(*dialer, NNG_OPT_TCP_RECVTIMEO,
			    &(node->tcp.recvtimeo), sizeof(int));
		}
	}

#ifdef NNG_SUPP_TLS
	if (node->tls.enable) {
		if ((rv = init_dialer_tls(*dialer, node->tls.ca, node->tls.cert,
		         node->tls.key, node->tls.key_password)) != 0) {
			log_error("init_dialer_tls failed %d", rv);
			return rv;
		}
	}
#endif

	bridge_arg->client = nng_mqtt_client_alloc(*sock, &send_callback, true);
	// set retry interval
	nng_duration retry = node->resend_interval;
	nng_socket_set_ms(*sock, NNG_OPT_MQTT_RETRY_INTERVAL, retry);
	nng_time retry_wait = node->resend_wait;
	nng_socket_set_uint64(*sock, NNG_OPT_MQTT_RETRY_WAIT_TIME, retry_wait);
	// create a CONNECT message
	nng_msg *connmsg = create_connect_msg(node);
	bridge_arg->connmsg = connmsg;

	// TCP bridge does not support hot update of connmsg
	if (0 != nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	if (0 != nng_socket_set_ptr(*sock, NNG_OPT_MQTT_BRIDGE_CONF, node)) {
		log_warn("Error in updating bridge config to socket");
	}
	nng_mqtt_set_connect_cb(*sock, bridge_tcp_connect_cb, bridge_arg);
	nng_mqtt_set_disconnect_cb(*sock, bridge_tcp_disconnect_cb, bridge_arg);

	if (node->enable) {
		rv = nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK);
		if (rv != 0) {
			log_error("nng dialer start failed %d", rv);
			return rv;
		}
	}

	return 0;
}

/**
 * independent callback API for bridging aio
 * only deal with PUB msg
 */
void
bridge_send_cb(void *arg)
{
	int rv;
	nng_msg *msg = NULL;
	nng_aio          *aio;
	conf_bridge_node *node = arg;
	nng_mtx          *mtx  = node->mtx;
	nng_socket       *socket;

	log_debug("bridge to %s msg sent", node->address);
	nng_mtx_lock(mtx);
	socket = node->sock;
	if (!node->busy)
		if (nng_lmq_get(node->ctx_msgs, &msg) == 0) {
			log_debug("resending cached msg from broker ctx");
			nng_aio_set_msg(node->resend_aio, msg);
			nng_aio_set_timeout(node->resend_aio, node->cancel_timeout);
			nng_send_aio(*socket, node->resend_aio);
			node->busy = true;
		}
	nng_mtx_unlock(mtx);
}

void
bridge_resend_cb(void *arg)
{
	int rv;
	nng_msg *msg = NULL;
	nng_aio          *aio;
	conf_bridge_node *node = arg;
	nng_mtx          *mtx  = node->mtx;
	nng_socket       *socket;
	nng_mtx_lock(mtx);
	socket = node->sock;
	node->busy = false;
	if (nng_lmq_get(node->ctx_msgs, &msg) == 0) {
		log_debug("resending cached msg at resend cb");
		nng_aio_set_msg(node->resend_aio, msg);
		nng_aio_set_timeout(node->resend_aio, node->cancel_timeout);
		nng_send_aio(*socket, node->resend_aio);
		node->busy = true;
	} else {
		node->busy = false;
	}
	nng_mtx_unlock(mtx);
}

// let bridge client sub to topics according to config file
int
bridge_client(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	int rv;

	bridge_param *bridge_arg;
	bridge_arg = (bridge_param *) nng_alloc(sizeof(bridge_param));
	if (bridge_arg == NULL) {
		log_error("memory error in allocating bridge client");
		return NNG_ENOMEM;
	}
	bridge_arg->config = node;
	bridge_arg->sock   = sock;
	bridge_arg->conf   = config;
	if (node->address == NULL) {
		log_error("invalid bridging config! node address is null!");
		nng_free(bridge_arg, sizeof(bridge_param));
		return -1;
	}
	if (reload_lock == NULL) {
		nng_mtx_alloc(&reload_lock);
	}

	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		bridge_tcp_client(sock, config, node, bridge_arg);
#if defined(SUPP_QUIC)
	} else if (0 == strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		bridge_quic_client(sock, config, node, bridge_arg);
#endif
	} else {
		nng_free(bridge_arg, sizeof(bridge_param));
		log_error("Unsupported bridge protocol.\n");
	}

	// alloc an AIO for each ctx bridging use only
	node->bridge_aio = nng_alloc(config->total_ctx * sizeof(nng_aio *));
	if ((rv = nng_aio_alloc(
		         &node->resend_aio, bridge_resend_cb, node)) != 0) {
			NANO_NNG_FATAL("bridge_aio nng_aio_alloc", rv);
	}
	node->sock = (void *) sock;
	node->bridge_arg = (void *) bridge_arg;

	uint32_t num;
	for ( num = 0; num < config->total_ctx; num++ ) {
		if ((rv = nng_aio_alloc(
		         &node->bridge_aio[num], bridge_send_cb, node)) != 0) {
			NANO_NNG_FATAL("bridge_aio nng_aio_alloc", rv);
		} else {
		}
	}
	log_debug("parallel %d", num);
	return 0;
}

int
bridge_subscribe(nng_socket *sock, conf_bridge_node *node,
        nng_mqtt_topic_qos *topic_qos, size_t sub_count, property *properties)
{
	int rv = 0;
	nng_msg *msg = NULL;
	uint8_t *rc = NULL;
	uint32_t rcsz;

	if (sub_count < 1)
		return -1;

	for (size_t i = 0; i < sub_count; i++) {
		log_info("Bridge client subscribed topic %.*s (qos %d).",
		    topic_qos[i].topic.length, topic_qos[i].topic.buf, topic_qos[i].qos);
	}
	bridge_param *bridge_arg = (bridge_param *)node->bridge_arg;

	nng_mtx_lock(reload_lock);
	// create a SUBSCRIBE message
	nng_msg *submsg;
	if (nng_mqtt_msg_alloc(&submsg, 0) != 0)
		return NNG_ENOMEM;
	nng_mqtt_msg_set_packet_type(submsg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(submsg, topic_qos, sub_count);
	if (properties)
		nng_mqtt_msg_set_subscribe_property(submsg, properties);

	// Send message
	nng_aio *aio;
	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) {
		nng_mtx_unlock(reload_lock);
		return rv;
	}
	nng_aio_set_msg(aio, submsg);
	nng_send_aio(*sock, aio);

	// Hold to get suback
	nng_aio_wait(aio);
	nng_mtx_unlock(reload_lock);

	if (nng_aio_result(aio) != 0 || (msg = nng_aio_get_msg(aio)) == NULL) {
		// Connection losted
		log_warn("Can't get suback. Maybe connection of bridge was closed.");
		rv = -3;
		goto done;
	}

	if (nng_mqtt_msg_get_packet_type(msg) != NNG_MQTT_SUBACK) {
		log_warn("Unknown error in handle bridge subscribe");
		goto done;
	}
	rc = nng_mqtt_msg_get_suback_return_codes(msg, &rcsz);
	for (int i=0; i<rcsz; ++i) {
		log_info("SUBACK reason code %d", rc[i]);
		if (rc[i] == 0x80)
			rv = -2;
	}

done:
	nng_aio_free(aio);
	if (msg)
		nng_msg_free(msg);

	return rv;
}

int
bridge_unsubscribe(nng_socket *sock, conf_bridge_node *node,
        nng_mqtt_topic *topics, size_t unsub_count, property *properties)
{
	int rv = 0;
	nng_msg *msg = NULL;
	uint8_t *rc = NULL;
	uint32_t rcsz;

	if (unsub_count < 1)
		return -1;

	for (size_t i = 0; i < unsub_count; i++) {
		log_info("Bridge client unsubscribed topic %.*s.",
		    topics[i].length, topics[i].buf);
	}
	bridge_param *bridge_arg = (bridge_param *)node->bridge_arg;

	nng_mtx_lock(reload_lock);
	// create a UNSUBSCRIBE message
	nng_msg *unsubmsg;
	if (nng_mqtt_msg_alloc(&unsubmsg, 0) != 0)
		return NNG_ENOMEM;
	nng_mqtt_msg_set_packet_type(unsubmsg, NNG_MQTT_UNSUBSCRIBE);
	nng_mqtt_msg_set_unsubscribe_topics(unsubmsg, topics, unsub_count);
	if (properties)
		nng_mqtt_msg_set_unsubscribe_property(unsubmsg, properties);

	// Send message
	nng_aio *aio;
	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0){
		nng_mtx_unlock(reload_lock);
		return rv;
	}
	nng_aio_set_msg(aio, unsubmsg);
	nng_send_aio(*sock, aio);

	// Hold to get suback
	nng_aio_wait(aio);
	nng_mtx_unlock(reload_lock);

	if (nng_aio_result(aio) != 0 || (msg = nng_aio_get_msg(aio)) == NULL) {
		// Connection losted
		log_warn("Can't get unsuback. Maybe connection of bridge was closed.");
		rv = -3;
		goto done;
	}

	if (nng_mqtt_msg_get_packet_type(msg) != NNG_MQTT_UNSUBACK) {
		log_warn("Unknown error in handle bridge unsubscribe");
		goto done;
	}
	rc = nng_mqtt_msg_get_unsuback_return_codes(msg, &rcsz);
	for (int i=0; i<rcsz; ++i) {
		log_info("SUBACK reason code %d", rc[i]);
		if (rc[i] == 0x80)
			rv = -2;
	}

done:
	nng_aio_free(aio);
	if (msg)
		nng_msg_free(msg);

	return rv;
}

int
bridge_reload(nng_socket *sock, conf *config, conf_bridge_node *node)
{
	if (node->address == NULL)
		return -1;

	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		log_info("Hot update quic bridge is an experimental function so far.");
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
		return -2;
	}
#if defined(SUPP_QUIC)
	if (node->hybrid == true) {
		log_error("Not allow to reload if hybrid is turned on.");
		return -3;
	}
#endif

	nng_socket *tsock;
	nng_socket *new = (nng_socket *) nng_alloc(sizeof(nng_socket));
	if (new == NULL) {
		return -1;
	}

	bridge_param    *bridge_arg = (bridge_param *) node->bridge_arg;
	nng_mqtt_client *client     = bridge_arg->client;
	tsock                       = bridge_arg->sock;
	sock                        = tsock;

	// no point to wait for ACK from last aio send of previous socket.
	nng_aio_finish_error(client->send_aio, NNG_ECANCELED);

	nng_mtx_lock(reload_lock);
	bool _enable = node->enable;
	node->enable = false;
	// No need to Free the nng_mqtt_client, reuse it.

	// socket reuse and open a new mqtt connection
	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		bridge_tcp_reload(new, config, node, bridge_arg);
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		bridge_quic_reload(new, config, node, bridge_arg);
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
		nng_mtx_unlock(reload_lock);
		nng_free(new, sizeof(nng_socket));
		return -1;
	}
	if (0 == strncmp(node->address, tcp_scheme, strlen(tcp_scheme)) ||
	    0 == strncmp(node->address, tls_scheme, strlen(tls_scheme))) {
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
#if defined(SUPP_QUIC)
	} else if (0 ==
	    strncmp(node->address, quic_scheme, strlen(quic_scheme))) {
		nng_sock_replace(*tsock, *new);
		nng_close(*tsock);
		nng_free(tsock, sizeof(nng_socket));
#endif
	} else {
		log_error("Unsupported bridge protocol.\n");
	}
	// Update the sock in client due to it's a constant rather than pointer
	bridge_arg->client->sock = *new;
	node->sock               = new;
	node->enable             = _enable;
	bridge_arg->sock         = new;
	nng_mtx_unlock(reload_lock);

	return 0;
}

// for transparent bridging only, deal with sub/unsub
bool
bridge_sub_handler(nano_work *work)
{
	nng_mqtt_topic_qos *topic_qos;
	topic_node 		   *tnode;

	if (work->flag  == CMD_SUBSCRIBE) {
		tnode = work->sub_pkt->node;
	} else if (work->flag == CMD_UNSUBSCRIBE) {
		tnode = work->unsub_pkt->node;
	} else {
		return false;
	}

	while (tnode != NULL) {
		// keep no_local to 1, we dont want looping msg
		nng_mqtt_topic topic[] = {
			{
			    .buf    = (uint8_t *) tnode->topic.body,
			    .length = tnode->topic.len,
			},
		};
		nng_mqtt_topic_qos subscriptions[] = {
			{ .qos               = tnode->qos,
			    .rap             = tnode->rap,
			    .nolocal         = 1,
			    .retain_handling = tnode->retain_handling
			},
		};
		subscriptions->topic = topic[0];

		for (size_t t = 0; t < work->config->bridge.count; t++) {
			conf_bridge_node *node = work->config->bridge.nodes[t];
			bridge_param *param = node->bridge_arg;
			if (!node->enable || !node->transparent)// check transparent enabler
				continue;
			// TODO enhance performance, reuse same Subscribe msg
			// TODO carry the property as well
			if (work->flag  == CMD_SUBSCRIBE)
				nng_mqtt_subscribe_async(param->client, subscriptions, 1, NULL);
			else if (work->flag  == CMD_UNSUBSCRIBE)
				nng_mqtt_unsubscribe_async(param->client, topic, 1, NULL);
		}
		tnode = tnode->next;
	}

	return true;
}
