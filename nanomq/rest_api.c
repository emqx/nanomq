//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/rest_api.h"
#include "include/bridge.h"
#include "include/conf_api.h"
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/file.h"
#include "nng/supplemental/util/platform.h"
#include "include/broker.h"
#include "include/nanomq.h"
#include "include/nanomq_rule.h"
#include "include/sub_handler.h"
#include "include/version.h"

#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/log.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef SUPP_JWT
#include "l8w8jwt/decode.h"
#include "l8w8jwt/encode.h"
#endif

#if NANO_PLATFORM_WINDOWS
#define nano_localtime(t, pTm) localtime_s(pTm, t)
#define nano_strtok strtok_s
#else
#define nano_localtime(t, pTm) localtime_r(t, pTm)
#define nano_strtok strtok_r
#endif

#if NANO_PLATFORM_LINUX
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

typedef int (handle_mqtt_msg_cb) (cJSON *, nng_socket *);
#define METRICS_DATA_SIZE 2048

typedef struct {
	char *key;
	char *value;
} kv;

typedef struct {
	char *node;
	bool  end;
} tree;

struct uri_content {
	size_t sub_count;
	tree **sub_tree;
	size_t params_count;
	kv **  params;
};

typedef struct uri_content uri_content;

typedef struct {
	const char *path;
	const char *name;
	const char *method;
	const char *descr;
} endpoints;

static endpoints api_ep[] = {
	{
	    .path   = "/brokers/",
	    .name   = "list_brokers",
	    .method = "GET",
	    .descr  = "A list of brokers in the cluster",
	},
	{
	    .path   = "/nodes/",
	    .name   = "list_nodes",
	    .method = "GET",
	    .descr  = "A list of nodes in the cluster",
	},
	{
	    .path   = "/clients/",
	    .name   = "list_clients",
	    .method = "GET",
	    .descr  = "A list of clients on current node",
	},
	{
	    .path   = "/clients/:clientid",
	    .name   = "lookup_client",
	    .method = "GET",
	    .descr  = "Lookup a client in the cluster",
	},
	{
	    .path   = "/clients/username/:username",
	    .name   = "lookup_client_via_username",
	    .method = "GET",
	    .descr  = "Lookup a client via username in the cluster",
	},
	{
	    .path   = "/subscriptions/",
	    .name   = "list_subscriptions",
	    .method = "GET",
	    .descr  = "A list of subscriptions in the cluster",
	},
	{
	    .path   = "/subscriptions/:clientid",
	    .name   = "lookup_client_subscriptions",
	    .method = "GET",
	    .descr  = "A list of subscriptions of a client",
	},
	{
	    .path   = "/rules/",
	    .name   = "list_rules",
	    .method = "GET",
	    .descr  = "Get rule list",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "get_rule_details",
	    .method = "GET",
	    .descr  = "Get the details of a rule",
	},
	{
	    .path   = "/rules/",
	    .name   = "create_rule",
	    .method = "POST",
	    .descr  = "Create a rule and return the rule ID",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "update_rule",
	    .method = "PUT",
	    .descr  = "Update the rule and return the rule ID",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "delete_rule",
	    .method = "DELETE",
	    .descr  = "Delete the rule",
	},
	{
	    .path   = "/mqtt/subscribe",
	    .name   = "mqtt_subscribe",
	    .method = "POST",
	    .descr  = "Subscribe a topic",
	},
	{
		.path = "/bridges/:bridge_name",
		.name = "get_mqtt_bridges",
		.method = "GET",
		.descr = "Get the details of bridge",
	},
	// { TODO not supported
	// 	.path = "/bridges/",
	// 	.name = "post_mqtt_bridge",
	// 	.method = "POST",
	// 	.descr = "Create a bridge client",
	// },
	{
		.path = "/bridges/:bridge_name",
		.name = "put_mqtt_bridge",
		.method = "PUT",
		.descr = "Edit a bridge client",
	},
	{
		.path = "/bridges/:bridge_name",
		.name = "delete_mqtt_bridge",
		.method = "DELETE",
		.descr = "DELETE a bridge client",
	},
	{
	    .path   = "/mqtt/publish",
	    .name   = "mqtt_publish",
	    .method = "POST",
	    .descr  = "Publish a MQTT message",
	},
	{
	    .path   = "/mqtt/unsubscribe",
	    .name   = "mqtt_unsubscribe",
	    .method = "POST",
	    .descr  = "Unsubscribe a topic",
	},
	{
	    .path   = "/mqtt/subscribe_batch",
	    .name   = "mqtt_subscribe_batch",
	    .method = "POST",
	    .descr  = "Batch subscribes topics",
	},
	{
	    .path   = "/mqtt/publish_batch",
	    .name   = "mqtt_publish_batch",
	    .method = "POST",
	    .descr  = "Batch publish MQTT messages",
	},
	{
	    .path   = "/mqtt/unsubscribe_batch",
	    .name   = "mqtt_unsubscribe_batch",
	    .method = "POST",
	    .descr  = "Batch unsubscribes topics",
	},
	{
	    .path   = "/topic-tree/",
	    .name   = "list_topic-tree",
	    .method = "GET",
	    .descr  = "A list of topic-tree in the cluster",
	},
	{
	    .path   = "/reload/",
	    .name   = "get_hot_updatable_configuration",
	    .method = "GET",
	    .descr  = "show the configuration that can be hot updated",
	},
	{
	    .path   = "/reload/",
	    .name   = "set_hot_updatable_configuration",
	    .method = "POST",
	    .descr  = "set the configuration that can be hot updated",
	},
	{
	    .path   = "/configuration/",
	    .name   = "get_broker_configuration",
	    .method = "GET",
	    .descr  = "show all configuration of broker",
	},
	{
	    .path   = "/configuration/basic",
	    .name   = "get_basic_configuration",
	    .method = "GET",
	    .descr  = "set broker basic configuration",
	},
	{
	    .path   = "/configuration/tls",
	    .name   = "get_tls_configuration",
	    .method = "GET",
	    .descr  = "show broker tls configuration",
	},
	{
	    .path   = "/configuration/http_server",
	    .name   = "get_http_server_configuration",
	    .method = "GET",
	    .descr  = "show broker http_server configuration",
	},
	{
	    .path   = "/configuration/websocket",
	    .name   = "get_websocket_configuration",
	    .method = "GET",
	    .descr  = "show broker websocket configuration",
	},
	{
	    .path   = "/configuration/webhook",
	    .name   = "get_webhook_configuration",
	    .method = "GET",
	    .descr  = "show broker webhook configuration",
	},
	{
	    .path   = "/configuration/auth",
	    .name   = "get_auth_configuration",
	    .method = "GET",
	    .descr  = "show broker authorization configuration",
	},
	{
	    .path   = "/configuration/auth_http",
	    .name   = "get_auth_http_configuration",
	    .method = "GET",
	    .descr  = "show broker authorization by http configuration",
	},
	{
	    .path   = "/configuration/sqlite",
	    .name   = "get_sqlite_configuration",
	    .method = "GET",
	    .descr  = "show broker sqlite configuration",
	},
	{
	    .path   = "/configuration/bridge",
	    .name   = "get_bridge_configuration",
	    .method = "GET",
	    .descr  = "show broker bridge configuration",
	},
	{
	    .path   = "/configuration/aws_bridge",
	    .name   = "get_aws_bridge_configuration",
	    .method = "GET",
	    .descr  = "show broker aws_bridge configuration",
	},
	{
	    .path   = "/configuration/",
	    .name   = "set_broker_configuration",
	    .method = "POST",
	    .descr  = "set broker configuration",
	},
	{
	    .path   = "/ctrl/:action",
	    .name   = "ctrl_broker",
	    .method = "POST",
	    .descr  = "Control broker stop or restart",
	},
	{
	    .path   = "/metrics",
	    .name   = "metrics",
	    .method = "GET",
	    .descr  = "Returns all statistical metrics",
	},
};

static tree **      uri_parse_tree(const char *path, size_t *count);
static void         uri_tree_free(uri_content *ct);
static kv **        uri_param_parse(const char *path, size_t *count);
static void         uri_param_free(uri_content *ct);
static uri_content *uri_parse(const char *uri);
static void         uri_free(uri_content *ct);

static http_msg error_response(
    http_msg *msg, uint16_t status, enum result_code code);

static http_msg get_endpoints(http_msg *msg);
static http_msg get_brokers(http_msg *msg);
static http_msg get_nodes(http_msg *msg, nng_socket *broker_sock);
static http_msg get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_metrics(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_subscriptions(
    http_msg *msg, kv **params, size_t param_num, const char *client_id);
static http_msg  get_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg  put_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg  delete_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg post_rules(http_msg *msg);
static http_msg get_tree(http_msg *msg);
static http_msg post_ctrl(http_msg *msg, const char *type);
static http_msg show_reload_config(http_msg *msg);
static http_msg post_reload_config(http_msg *msg);
static http_msg get_config(http_msg *msg, const char *type);
static http_msg post_config(http_msg *msg, const char *type);
static http_msg post_mqtt_msg(
    http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb);
static http_msg post_mqtt_msg_batch(
    http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb);
static http_msg get_mqtt_bridge(http_msg *msg, const char *name);
static http_msg put_mqtt_bridge(http_msg *msg, const char *name);
static http_msg post_mqtt_bridge_sub(http_msg *msg, const char *name);
static http_msg post_mqtt_bridge_unsub(http_msg *msg, const char *name);

static int properties_parse(property **properties, cJSON *json);
static int handle_publish_msg(cJSON *pub_obj, nng_socket *sock);
static int handle_subscribe_msg(cJSON *sub_obj, nng_socket *sock);
static int handle_unsubscribe_msg(cJSON *sub_obj, nng_socket *sock);

static void
get_time_str(char *str, size_t str_len)
{
	if (str == NULL) {
		return;
	}
	const time_t now_seconds = time(NULL);
	struct tm    now;
	nano_localtime(&now_seconds, &now);
	strftime(str, str_len, "%Y-%m-%d %H:%M:%S", &now);
}

static tree **
uri_parse_tree(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = strstr(path, REST_URI_ROOT);

	size_t num  = 0;
	tree **root = NULL;
	int    len  = 0;

	if (str) {
		str += strlen(REST_URI_ROOT);
		while (NULL != (ret = strchr(str, '/'))) {
			num++;
			root      = realloc(root, sizeof(tree *) * num);
			len       = ret - str + 1;
			tree *sub = nng_zalloc(sizeof(tree));
			sub->node = nng_zalloc(len);
			strncpy(sub->node, str, len - 1);
			sub->end      = false;
			root[num - 1] = sub;
			str           = ret + 1;
		}
		if (num > 0) {
			if (strlen(str) > 0) {
				num++;
				root = realloc(root, sizeof(char *) * num);
				tree *sub     = nng_zalloc(sizeof(tree));
				sub->node     = nng_strdup(str);
				sub->end      = true;
				root[num - 1] = sub;
			} else {
				tree *sub = root[num - 1];
				sub->end  = true;
			}
		}
	}

	*count = num;
	return root;
}

static void
uri_tree_free(uri_content *ct)
{
	if (ct->sub_count > 0) {
		tree **node = ct->sub_tree;
		for (size_t i = 0; i < ct->sub_count; i++) {
			tree *sub = node[i];
			nng_strfree(sub->node);
			nng_free(sub, sizeof(tree));
		}
		nng_free(node, ct->sub_count * sizeof(tree *));
		ct->sub_count = 0;
	}
}

static kv **
uri_param_parse(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = (char *) path;

	size_t num    = 0;
	char **kv_str = NULL;
	int    len    = 0;

	while (NULL != (ret = strchr(str, '&'))) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		len             = ret - str + 1;
		kv_str[num - 1] = nng_zalloc(len);
		memcpy(kv_str[num - 1], str, len - 1);
		str = ret + 1;
	}
	if (num > 0) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		kv_str[num - 1] = nng_strdup(str);
	} else {
		return NULL;
	}

	kv **  params      = calloc(num, sizeof(kv *));
	size_t param_count = 0;

	for (size_t i = 0; i < num; i++) {
		char *key   = nng_zalloc(strlen(kv_str[i]));
		char *value = nng_zalloc(strlen(kv_str[i]));
		if (2 == sscanf(kv_str[i], "%[^=]=%s", key, value)) {
			params[i]        = nng_zalloc(sizeof(kv));
			params[i]->key   = key;
			params[i]->value = value;
			param_count++;
		} else {
			if (key) {
				free(key);
			}
			if (value) {
				free(value);
			}
		}
		free(kv_str[i]);
		kv_str[i] = NULL;
	}

	*count = param_count;
	return params;
}

static void
uri_param_free(uri_content *ct)
{
	if (ct->params_count > 0) {
		kv **params = ct->params;
		for (size_t i = 0; i < ct->params_count; i++) {
			nng_strfree(params[i]->key);
			nng_strfree(params[i]->value);
			nng_free(params[i], sizeof(kv));
		}
		nng_free(params, ct->params_count * sizeof(kv *));
		ct->params_count = 0;
	}
}

static uri_content *
uri_parse(const char *uri)
{
	uri_content *uri_ct  = nng_zalloc(sizeof(uri_content));
	uri_ct->params_count = 0;
	uri_ct->params       = NULL;
	char *path           = NULL;
	char *param          = NULL;
	int   len            = 0;

	if (strcmp(uri, REST_URI_ROOT) == 0 ||
	    strcmp(uri, REST_URI_ROOT "/") == 0) {
		return uri_ct;
	}

	char *p = strchr(uri, '?');
	if (p) {
		// Have parameters
		param = p + 1;
		if (strlen(param) >= 3) {
			uri_ct->params =
			    uri_param_parse(param, &uri_ct->params_count);
		}
		len  = p - uri + 1;
		path = nng_zalloc(len);
		memcpy(path, uri, len - 1);
	} else {
		path = nng_strdup(uri);
	}

	uri_ct->sub_tree = uri_parse_tree(path, &uri_ct->sub_count);
	nng_strfree(path);
	return uri_ct;
}

static void
uri_free(uri_content *ct)
{
	if (ct) {
		uri_tree_free(ct);
		uri_param_free(ct);
		nng_free(ct, sizeof(uri_content));
		ct = NULL;
	}
}

void
put_http_msg(http_msg *msg, const char *content_type, const char *method,
    const char *uri, const char *token, const char *data, size_t data_sz)
{
	if (content_type != NULL) {
		msg->content_type_len = strlen(content_type);
		msg->content_type     = nng_strdup(content_type);
	}

	if (method != NULL) {
		msg->method_len = strlen(method);
		msg->method     = nng_strdup(method);
	}

	if (uri != NULL) {
		msg->uri_len = strlen(uri);
		msg->uri     = nng_strdup(uri);
	}

	if (token != NULL) {
		msg->token_len = strlen(token);
		msg->token     = nng_strdup(token);
	}

	if (data != NULL) {
		msg->data_len = data_sz;
		msg->data     = nng_alloc(msg->data_len);
		memcpy(msg->data, data, msg->data_len);
	}
}

void
destory_http_msg(http_msg *msg)
{
	if (msg->content_type_len > 0) {
		nng_strfree(msg->content_type);
		msg->content_type_len = 0;
	}

	if (msg->method_len > 0) {
		nng_strfree(msg->method);
		msg->method_len = 0;
	}

	if (msg->token_len > 0) {
		nng_strfree(msg->token);
		msg->token_len = 0;
	}
	if (msg->data_len > 0) {
		nng_free(msg->data, msg->data_len);
		msg->data_len = 0;
	}
	if (msg->uri_len > 0) {
		nng_strfree(msg->uri);
		msg->uri_len = 0;
	}
}

#ifdef SUPP_JWT

static enum result_code
jwt_authorize(http_msg *msg)
{
	enum result_code result = SUCCEED;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Bearer %s", msg->token) != 1) {
		return EMPTY_USERNAME_OR_PASSWORD;
	}

	conf_http_server *server = get_http_server_conf();

	struct l8w8jwt_decoding_params params;
	l8w8jwt_decoding_params_init(&params);

	params.alg        = L8W8JWT_ALG_RS256;
	params.jwt        = msg->token;
	params.jwt_length = strlen(msg->token);

	if (server->jwt.iss) {
		params.validate_iss        = server->jwt.iss;
		params.validate_iss_length = strlen(server->jwt.iss);
	}

	params.verification_key        = (uint8_t *) server->jwt.public_key;
	params.verification_key_length = server->jwt.public_key_len;

	params.validate_aud        = NULL;
	params.validate_aud_length = 0;

	params.validate_iat          = 0;
	params.validate_exp          = 1;
	params.exp_tolerance_seconds = 200;

	enum l8w8jwt_validation_result validation_result = 0;

	struct l8w8jwt_claim *claim       = NULL;
	size_t                claim_count = 0;

	int rv =
	    l8w8jwt_decode(&params, &validation_result, &claim, &claim_count);

	if (rv == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID) {
		struct l8w8jwt_claim *body_claim = l8w8jwt_get_claim(
		    claim, claim_count, "bodyEncode", strlen("bodyEncode"));
		if (body_claim) {
			if (body_claim->type == 1) {
				msg->encrypt_data = true;
			} else {
				msg->encrypt_data = false;
			}
		}
	} else {
		log_error("decode jwt token failed: return %d, result: %d", rv,
		    validation_result);
		if (validation_result == L8W8JWT_EXP_FAILURE) {
			result = TOKEN_EXPIRED;
		} else {
			result = WRONG_USERNAME_OR_PASSWORD;
		}
	}

	if (claim_count > 0) {
		l8w8jwt_free_claims(claim, claim_count);
	}

	return result;
}
#else

static enum result_code
jwt_authorize(http_msg *msg)
{
	return REQ_PARAM_ERROR;
}
#endif

static enum result_code
basic_authorize(http_msg *msg)
{
	enum result_code result = SUCCEED;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Basic %s", msg->token) != 1) {
		return EMPTY_USERNAME_OR_PASSWORD;
	}

	size_t   token_len = strlen(msg->token);
	uint8_t *token     = nng_alloc(token_len + 1);
	memcpy(token, msg->token, token_len);
	token[token_len] = '\0';

	// Authorize username:password
	conf_http_server *server = get_http_server_conf();

	size_t auth_len =
	    strlen(server->username) + strlen(server->password) + 2;
	char *auth = nng_alloc(auth_len);
	snprintf(auth, auth_len, "%s:%s", server->username, server->password);

	uint8_t *decode      = nng_alloc(auth_len);
	decode[auth_len - 1] = '\0';

	base64_decode((const char *) token, token_len, decode);

	if (strncmp(auth, (const char *) decode, auth_len) != 0) {
		result = WRONG_USERNAME_OR_PASSWORD;
	}

	nng_free(auth, auth_len);
	nng_free(decode, msg->token_len);
	nng_free(token, token_len);

	return result;
}

http_msg
process_request(http_msg *msg, conf_http_server *config, nng_socket *sock)
{
	http_msg         ret    = { 0 };
	uint16_t         status = NNG_HTTP_STATUS_OK;
	enum result_code code   = SUCCEED;
	uri_content *    uri_ct = NULL;
	switch (config->auth_type) {
	case BASIC:
		if ((code = basic_authorize(msg)) != SUCCEED) {
			status = NNG_HTTP_STATUS_UNAUTHORIZED;
			goto exit;
		}
		break;

	case JWT:
		if ((code = jwt_authorize(msg)) != SUCCEED) {
			status = NNG_HTTP_STATUS_UNAUTHORIZED;
			goto exit;
		}

	default:
		break;
	}

	uri_ct = uri_parse(msg->uri);
	if (nng_strcasecmp(msg->method, "GET") == 0) {
		if (uri_ct->sub_count == 0) {
			ret = get_endpoints(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "brokers") == 0) {
			ret = get_brokers(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "nodes") == 0) {
			ret = get_nodes(msg, config->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "metrics") == 0) {
			ret = get_metrics(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, config->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, config->broker_sock);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node,
			    NULL, config->broker_sock);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "username") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL,
			    uri_ct->sub_tree[3]->node, config->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "subscriptions") == 0) {
			ret = get_subscriptions(
			    msg, uri_ct->params, uri_ct->params_count, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "subscriptions") == 0) {
			ret = get_subscriptions(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);

		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = get_rules(
			    msg, uri_ct->params, uri_ct->params_count, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = get_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);

		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "topic-tree") == 0) {
			ret = get_tree(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "reload") == 0) {
			ret = show_reload_config(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = get_config(msg, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = get_config(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = get_mqtt_bridge(msg, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = get_mqtt_bridge(msg, uri_ct->sub_tree[2]->node);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "POST") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "ctrl") == 0) {
			ret = post_ctrl(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "reload") == 0) {
			ret = post_reload_config(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = post_config(msg, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = post_config(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = post_rules(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "publish") == 0) {
			ret = post_mqtt_msg(msg, sock, handle_publish_msg);
		}  else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0 &&
			strcmp(uri_ct->sub_tree[2]->node, "sub") == 0
			) {
			ret = post_mqtt_bridge_sub(
			    msg, uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsub") == 0) {
			ret = post_mqtt_bridge_unsub(
			    msg, uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "publish_batch") == 0) {
			ret =
			    post_mqtt_msg_batch(msg, sock, handle_publish_msg);
		}

		/* else if (uri_ct->sub_count == 3 &&
		     uri_ct->sub_tree[2]->end &&
		     strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		     strcmp(uri_ct->sub_tree[2]->node, "subscribe") == 0) {
		         ret = post_mqtt_msg(msg, sock, handle_subscribe_msg);
		 }
		else if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "subscribe_batch") ==
		        0) {
		        ret = post_mqtt_msg_batch(
		            msg, sock, handle_subscribe_msg);
		}
		else if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsubscribe") == 0) {
		        ret = post_mqtt_msg(msg, sock, handle_unsubscribe_msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsubscribe_batch") ==
		        0) {
		        ret = post_mqtt_msg_batch(
		            msg, sock, handle_unsubscribe_msg);
		} */
		else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "PUT") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = put_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = put_mqtt_bridge(msg, uri_ct->sub_tree[2]->node);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "DELETE") == 0) {
		if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = delete_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else {
		status = NNG_HTTP_STATUS_METHOD_NOT_ALLOWED;
		code   = UNKNOWN_MISTAKE;
		goto exit;
	}

	uri_free(uri_ct);
	return ret;

exit:
	uri_free(uri_ct);
	ret = error_response(msg, status, code);
	return ret;
}

static http_msg
error_response(http_msg *msg, uint16_t status, enum result_code code)
{
	http_msg ret = { 0 };

	ret.status = status;

	cJSON *res_obj;
	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &ret, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);

	return ret;
}

static http_msg
get_endpoints(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	cJSON *array = cJSON_CreateArray();

	size_t ep_count = sizeof(api_ep) / sizeof(api_ep[0]);

	for (size_t i = 0; i < ep_count; i++) {
		cJSON *item = cJSON_CreateObject();
		cJSON_AddStringToObject(item, "path", api_ep[i].path);
		cJSON_AddStringToObject(item, "name", api_ep[i].name);
		cJSON_AddStringToObject(item, "method", api_ep[i].method);
		cJSON_AddStringToObject(item, "descr", api_ep[i].descr);
		cJSON_AddItemToArray(array, item);
	}
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);

	return res;
}

static void
get_uptime(char *str, size_t str_len)
{
	nng_time uptime = nng_clock() - get_boot_time();
	nng_time hours  = uptime / 1000 / 3600;
	nng_time mins   = uptime / 1000 / 60 % 60;
	nng_time secs   = uptime / 1000 % 60;

	snprintf(str, str_len, "%llu Hours, %llu minutes, %llu seconds", hours,
	    mins, secs);
}

static void
get_version(char *str, size_t str_len)
{
	snprintf(str, str_len, "%d.%d.%d-%s", NANO_VER_MAJOR, NANO_VER_MINOR,
	    NANO_VER_PATCH, NANO_VER_ID_SHORT);
}

static http_msg
get_brokers(http_msg *msg)
{
	http_msg res     = { .status = NNG_HTTP_STATUS_OK };
	cJSON *  res_obj = cJSON_CreateObject();

	char time_str[100] = { 0 };
	get_time_str(time_str, 100);

	char runtime[100] = { 0 };
	get_uptime(runtime, 100);

	char version[100] = { 0 };
	get_version(version, 100);

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	cJSON *array = cJSON_CreateArray();
	cJSON *item  = cJSON_CreateObject();
	cJSON_AddStringToObject(item, "datetime", time_str);
	cJSON_AddStringToObject(item, "node_status", "Running");
	cJSON_AddStringToObject(item, "sysdescr", "NanoMQ Broker");
	cJSON_AddStringToObject(item, "uptime", runtime);
	cJSON_AddStringToObject(item, "version", version);
	cJSON_AddItemToArray(array, item);
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);

	return res;
}

static void
get_conn_count_cb(void *key, void *value, void *arg)
{
	uint32_t count = *(uint32_t *) arg;
	count++;
	*(uint32_t *) arg = count;
}

static http_msg
get_nodes(http_msg *msg, nng_socket *broker_sock)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	char runtime[100] = { 0 };
	get_uptime(runtime, 100);

	char version[100] = { 0 };
	get_version(version, 100);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON *array = cJSON_CreateArray();
	cJSON *item  = cJSON_CreateObject();

	uint32_t conn_count = 0;

	nng_id_map *pipe_id_map;

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) == 0) {
		nng_id_map_foreach2(
		    pipe_id_map, get_conn_count_cb, &conn_count);
	}

	cJSON_AddNumberToObject(item, "connections", conn_count);
	cJSON_AddStringToObject(item, "node_status", "Running");
	cJSON_AddStringToObject(item, "uptime", runtime);
	cJSON_AddStringToObject(item, "version", version);

	cJSON_AddItemToArray(array, item);
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);
	return res;
}

typedef struct {
	cJSON *array;
	char * client_id;
	char * username;
} client_info;

typedef struct {
	uint32_t connections;
	uint32_t sessions;
	uint32_t topics;
	uint32_t subscribers;
	uint32_t message_received;
	uint32_t message_sent;
	uint32_t message_dropped;
	float    memory;
	float    cpu_percent;
} client_stats;

static void
get_client_cb(void *key, void *value, void *json_obj)
{
	client_info   *info    = json_obj;
	uint32_t       pipe_id = *(uint32_t *) key;
	nng_pipe       pipe    = { .id = pipe_id };
	bool           status  = nng_pipe_status(pipe);
	conn_param    *cp      = nng_pipe_cparam(pipe);
	const uint8_t *cid     = conn_param_get_clientid(cp);
	if (info->client_id != NULL) {
		if (strcmp(info->client_id, (const char *) cid) != 0) {
			return;
		}
	}
	const uint8_t *user_name = conn_param_get_username(cp);
	if (info->username != NULL) {
		if (user_name == NULL ||
		    strcmp(info->username, (const char *) user_name) != 0) {
			return;
		}
	}

	uint16_t      keep_alive  = conn_param_get_keepalive(cp);
	const uint8_t proto_ver   = conn_param_get_protover(cp);
	const char *  proto_name  = (const char *) conn_param_get_pro_name(cp);
	const bool    clean_start = conn_param_get_clean_start(cp);

	cJSON *data_info_elem;
	data_info_elem = cJSON_CreateObject();
	cJSON_AddStringToObject(data_info_elem, "client_id", (char *) cid);
	cJSON_AddStringToObject(data_info_elem, "username",
	    user_name == NULL ? "" : (char *) user_name);
	cJSON_AddNumberToObject(data_info_elem, "keepalive", keep_alive);
	if (status)
		cJSON_AddStringToObject(data_info_elem, "conn_state", "disconnected");
	else
		cJSON_AddStringToObject(data_info_elem, "conn_state", "connected");
	cJSON_AddBoolToObject(data_info_elem, "clean_start", clean_start);
	cJSON_AddStringToObject(data_info_elem, "proto_name", proto_name);
	cJSON_AddNumberToObject(data_info_elem, "proto_ver", proto_ver);
	// #ifdef STATISTICS
	// 		cJSON_AddNumberToObject(data_info_elem, "recv_msg",
	// 		    ctxt->recv_cnt != NULL ?
	// nng_atomic_get64(ctxt->recv_cnt) : 0); #endif
	cJSON_AddItemToArray(info->array, data_info_elem);
}

static void
get_metric_cb(void *key, void *value, void *stats)
{
	client_stats *s = (client_stats *) stats;
	s->sessions++;
	uint32_t       pipe_id = *(uint32_t *) key;
	nng_pipe       pipe    = { .id = pipe_id };
	bool           status  = nng_pipe_status(pipe);

	conn_param    *cp      = nng_pipe_cparam(pipe);
	const uint8_t *cid     = conn_param_get_clientid(cp);
	if (!status) s->connections++;

	// #ifdef STATISTICS
	// 		cJSON_AddNumberToObject(data_info_elem, "recv_msg",
	// 		    ctxt->recv_cnt != NULL ?
	// nng_atomic_get64(ctxt->recv_cnt) : 0); #endif
}

static http_msg
get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

 	cJSON *data_info;
	cJSON *res_obj;
	data_info = cJSON_CreateArray();

	nng_id_map *pipe_id_map;

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) != 0) {
		goto out;
	}


	client_info info = {
		.array     = data_info,
		.client_id = (char *) client_id,
		.username  = (char *) username,
	};

	nng_id_map_foreach2(pipe_id_map, get_client_cb, &info);

 out:

 	res_obj = cJSON_CreateObject();
 	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

 	// cJSON *meta = cJSON_CreateObject();

 	// cJSON_AddItemToObject(res_obj, "meta", meta);
 	// TODO add meta content: page, limit, count
 	cJSON_AddItemToObject(res_obj, "data", data_info);
 	char *dest = cJSON_PrintUnformatted(res_obj);
 	cJSON_Delete(res_obj);

 	put_http_msg(
 	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

 	cJSON_free(dest);

	return res;
}

static void
compose_metrics(char *ret, client_stats *ms, client_stats *s)
{
	char fmt[] = "# TYPE nanomq_connections_count gauge"
	             "\n# HELP nanomq_connections_count"
	             "\nnanomq_connections_count %d"
	             "\n# TYPE nanomq_connections_max gauge"
	             "\n# HELP nanomq_connections_max"
	             "\nnanomq_connections_max %d"
	             "\n# TYPE nanomq_sessions_count gauge"
	             "\n# HELP nanomq_sessions_count"
	             "\nnanomq_sessions_count %d"
	             "\n# TYPE nanomq_sessions_max gauge"
	             "\n# HELP nanomq_sessions_max"
	             "\nnanomq_sessions_max %d"
	             "\n# TYPE nanomq_topics_count gauge"
	             "\n# HELP nanomq_topics_count"
	             "\nnanomq_topics_count %d"
	             "\n# TYPE nanomq_topics_max gauge"
	             "\n# HELP nanomq_topics_max"
	             "\nnanomq_topics_max %d"
	             "\n# TYPE nanomq_subscribers_count gauge"
	             "\n# HELP nanomq_subscribers_count"
	             "\nnanomq_subscribers_count %d"
	             "\n# TYPE nanomq_subscribers_max gauge"
	             "\n# HELP nanomq_subscribers_max"
	             "\nnanomq_subscribers_max %d"
	             "\n# TYPE nanomq_messages_received counter"
	             "\n# HELP nanomq_messages_received"
	             "\nnanomq_messages_received %d"
	             "\n# TYPE nanomq_messages_sent counter"
	             "\n# HELP nanomq_messages_sent"
	             "\nnanomq_messages_sent %d"
	             "\n# TYPE nanomq_messages_dropped counter"
	             "\n# HELP nanomq_messages_dropped"
	             "\nnanomq_messages_dropped %d"
	             "\n# TYPE nanomq_memory_usage gauge"
	             "\n# HELP nanomq_memory_usage (MB)"
	             "\nnanomq_memory_usage %.2f"
	             "\n# TYPE nanomq_memory_usage_max gauge"
	             "\n# HELP nanomq_memory_usage_max (MB)"
	             "\nnanomq_memory_usage_max %.2f"
	             "\n# TYPE nanomq_cpu_usage gauge"
	             "\n# HELP nanomq_cpu_usage"
	             "\nnanomq_cpu_usage %.2f%"
	             "\n# TYPE nanomq_cpu_usage gauge"
	             "\n# HELP nanomq_cpu_usage"
	             "\nnanomq_cpu_usage %.2f%\n";

	snprintf(ret, METRICS_DATA_SIZE, fmt, s->connections, ms->connections,
	    s->sessions, ms->sessions, s->topics, ms->topics, s->subscribers,
	    ms->subscribers, s->message_received, s->message_sent,
	    s->message_dropped, s->memory, ms->memory, s->cpu_percent,
	    ms->cpu_percent);
}

#define max_stats(s, ms, field) ms->field > s->field ? ms->field : s->field

static void
update_max_stats(client_stats *ms, client_stats *s)
{
	// TODO not strictly the maximum value.
	ms->topics      = max_stats(s, ms, topics);
	ms->sessions    = max_stats(s, ms, sessions);
	ms->connections = max_stats(s, ms, connections);
	ms->subscribers = max_stats(s, ms, subscribers);
	ms->memory      = max_stats(s, ms, memory);
	ms->cpu_percent = max_stats(s, ms, cpu_percent);
}

static void *
get_client_exist_cb(uint32_t pid)
{
	return (void *) pid;
}

static size_t
get_topics_count()
{
	dbtree        *db = get_broker_db();
	dbtree_info ***vn =
	    (dbtree_info ***) dbtree_get_tree(db, get_client_exist_cb);
	size_t counter = 0;

	for (int i = 0; i < cvector_size(vn); i++) {
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			nng_free(vn[i][j]->topic, strlen(vn[i][j]->topic));
			if (vn[i][j]->clients) {
				counter++;
			}
			cvector_free(vn[i][j]->clients);
			nng_free(vn[i][j], sizeof(dbtree_info));
		}
		cvector_free(vn[i]);
	}
	cvector_free(vn);
	return counter;
}

static long
get_cpu_time()
{
	FILE *fd;
	char  buff[256];

	fd = fopen("/proc/stat", "r");
	if (fd == NULL) {
		log_error("open /proc/stat failed!");
		return -1;
	}

	fgets(buff, sizeof(buff), fd);
	uint32_t user, nice, sys, idle, iowait, irq, sirq, steal;

	int rc = sscanf(buff, "%*s %u %u %u %u %u %u %u %u", &user, &nice, &sys, &idle,
	    &iowait, &irq, &sirq, &steal);

	fclose(fd);

	if (rc != 8) {
		log_error("scanf error!");
		return -1;
	}
	long ret = user + nice + sys + idle + iowait + irq + sirq + steal;
	return ret;
}

static long
update_process_info(client_stats *s)
{
	static long last_cpu_time  = 0;
	static long last_proc_time = 0;

	long cpu_time = get_cpu_time();
	if (cpu_time == -1) {
		s->cpu_percent = -1;
		return -1;
	}

	int  pid = getpid();
	char stat_file[256];
	snprintf(stat_file, sizeof(stat_file), "/proc/%d/stat", pid);

	FILE *fp = fopen(stat_file, "r");
	if (fp == NULL) {
		perror("Error opening file");
		return -1;
	}

	long utime, stime, cutime, cstime, rss;
	if (fscanf(fp,
	        "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu "
	        "%lu %ld %ld %*d %*d %*d %*d %*u %*u %ld",
	        &utime, &stime, &cutime, &cstime, &rss) != 5) {
		perror("Error reading file");
		fclose(fp);
		return -1;
	}
	fclose(fp);

	s->memory = (float) rss * getpagesize() / (1024 * 1024);

	long   proc_time   = utime + stime + cutime + cstime;
	double cpu_percent = 100.0 *
	    ((double) (proc_time - last_proc_time) /
	        (cpu_time - last_cpu_time == 0 ? -1
	                                       : cpu_time - last_cpu_time));
	s->cpu_percent = cpu_percent <= 0 ? 0 : cpu_percent;
	log_debug("NanoMQ memory usage: %.2f MB\n", s->memory);
	log_debug("NanoMQ cpu usage: %.2f %\n", s->cpu_percent);

	last_proc_time = proc_time;
	last_cpu_time  = cpu_time;

	return 0;
}

static http_msg
get_metrics(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	client_stats stats = { 0 };
	static client_stats max_stats = { 0 };
	nng_id_map *pipe_id_map;

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) != 0) {
		goto out;
	}

	nng_id_map_foreach2(pipe_id_map, get_metric_cb, &stats);
	stats.subscribers      = dbhash_get_pipe_cnt();
	stats.topics           = get_topics_count();
	stats.message_received = nanomq_get_message_in();
	stats.message_sent     = nanomq_get_message_out();
	stats.message_dropped  = nanomq_get_message_drop();

#if NANO_PLATFORM_LINUX
	update_process_info(&stats);
#endif

	char dest[METRICS_DATA_SIZE] = { 0 };
	update_max_stats(&max_stats, &stats);
	compose_metrics(dest, &max_stats, &stats);

out:
	put_http_msg(&res, "text/plain", NULL, NULL, NULL, dest, strlen(dest));

	return res;
}



static http_msg
get_subscriptions(
    http_msg *msg, kv **params, size_t param_num, const char *client_id)
{
	http_msg res = { 0 };
 	res.status   = NNG_HTTP_STATUS_OK;

 	cJSON *res_obj   = NULL;
 	cJSON *data_info = NULL;
 	data_info        = cJSON_CreateArray();
 	res_obj          = cJSON_CreateObject();

 	dbtree *          db   = get_broker_db();
 	dbhash_ptpair_t **pt   = dbhash_get_ptpair_all();
 	size_t            size = cvector_size(pt);
 	for (size_t i = 0; i < size; i++) {
 		const char * cid     = NULL;
		nng_pipe p = { .id = pt[i]->pipe };
		conn_param *cp = nng_pipe_cparam(p);

 		if (cp) {
 			cid = (const char *) conn_param_get_clientid(
 			    cp);
 			if (client_id) {
 				if (strcmp(client_id, cid) != 0) {
 					goto skip;
 				}
 			}
 		}

 		// topic_queue *tn = pt[i]->topic;
		topic_queue *tq = dbhash_copy_topic_queue(pt[i]->pipe);
		topic_queue *reap_node = tq;
 		while (tq) {
 			cJSON *subscribe = cJSON_CreateObject();
 			if (cid) {
 				cJSON_AddStringToObject(
 				    subscribe, "clientid", cid);
 			} else {
 				cJSON_AddStringToObject(
 				    subscribe, "clientid", "");
 			}
 			cJSON_AddStringToObject(
 			    subscribe, "topic", tq->topic);
 			cJSON_AddNumberToObject(subscribe, "qos", tq->qos);
 			cJSON_AddItemToArray(data_info, subscribe);
 			tq = tq->next;
			nng_free(reap_node->topic, strlen(reap_node->topic));
			nng_free(reap_node, sizeof(topic_queue));
			reap_node = tq;
 		}
 	skip:
 		dbhash_ptpair_free(pt[i]);
 	}
 	cvector_free(pt);

 	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
 	// cJSON *meta = cJSON_CreateObject();
 	// cJSON_AddItemToObject(res_obj, "meta", meta);
 	// TODO add meta content: page, limit, count
 	cJSON_AddItemToObject(res_obj, "data", data_info);

 	char *dest = cJSON_PrintUnformatted(res_obj);

 	put_http_msg(
 	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

 	cJSON_free(dest);
 	cJSON_Delete(res_obj);
	return res;
}

static http_msg
post_rules(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);


	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}

	cJSON *res_obj = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)
	conf * config   = get_global_conf();
	conf_rule *cr = &config->rule_eng;

	cJSON *jso_sql = cJSON_GetObjectItem(req, "rawsql");
	char *rawsql = cJSON_GetStringValue(jso_sql);
	log_debug("rawsql: %s\n", rawsql);

	cJSON *jso_actions = cJSON_GetObjectItem(req, "actions");
	cJSON *jso_action = NULL;
	cJSON_ArrayForEach(jso_action, jso_actions) {
		cJSON *jso_name = cJSON_GetObjectItem(jso_action, "name");
		char  *name     = cJSON_GetStringValue(jso_name);
		log_debug("name: %s\n", name);
		cJSON *jso_params = cJSON_GetObjectItem(jso_action, "params");
		cJSON *jso_param  = NULL;
		if (!nng_strcasecmp(name, "repub")) {
			cr->option |= RULE_ENG_RPB;
			repub_t *repub = rule_repub_init();

			cJSON_ArrayForEach(jso_param, jso_params) {
				if (jso_param) {
					if (!nng_strcasecmp(jso_param->string, "topic")) {
						repub->topic = nng_strdup(jso_param->valuestring);
						log_debug("topic: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "address")) {
						repub->address = nng_strdup(jso_param->valuestring);
						log_debug("address: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "proto_ver")) {
						repub->proto_ver = jso_param->valueint;
						log_debug("proto_ver: %d\n", jso_param->valueint);
					} else if (!nng_strcasecmp(jso_param->string, "keepalive")) {
						repub->keepalive = jso_param->valueint;
						log_debug("keepalive: %d\n", jso_param->valueint);
					} else if (!nng_strcasecmp(jso_param->string, "clientid")) {
						repub->clientid = nng_strdup(jso_param->valuestring);
						log_debug("clientid: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "username")) {
						repub->username = nng_strdup(jso_param->valuestring);
						log_debug("username: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "password")) {
						repub->password = nng_strdup(jso_param->valuestring);
						log_debug("password: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "clean_start")) {
						repub->clean_start = !nng_strcasecmp(jso_param->string, "true");
						log_debug("clean_start: %s\n", jso_param->valuestring);
					} else {
						puts("Unsupport key word!");
					}
				}
			}
			if (NULL == repub->address || NULL == repub->topic) {
				cJSON_Delete(req);
				cJSON_Delete(res_obj);
				rule_repub_free(repub);
				return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
				    MISSING_KEY_REQUEST_PARAMES);
			}
			rule_sql_parse(cr, rawsql);
			cr->rules[cvector_size(cr->rules) - 1].forword_type = RULE_FORWORD_REPUB;


			// TODO set default key word
			nng_socket *sock  = (nng_socket *) nng_alloc(
				    	sizeof(nng_socket));
			// TODO FIXME fixed connect error response.
			nano_client(sock, repub);

			cr->rules[cvector_size(cr->rules) - 1]
			    .repub = repub;
			cr->rules[cvector_size(cr->rules) - 1]
			    .raw_sql = nng_strdup(rawsql);
			cr->rules[cvector_size(cr->rules) - 1]
			    .enabled = true;
			cr->rules[cvector_size(cr->rules) - 1]
			    .rule_id = rule_generate_rule_id();

		} else if (!strcasecmp(name, "sqlite")) {
			cr->option |= RULE_ENG_SDB;
			cJSON_ArrayForEach(jso_param, jso_params) {
				if (jso_param) {
					if (!nng_strcasecmp(jso_param->string, "table")) {
						log_debug("table: %s\n", jso_param->valuestring);
						rule_sql_parse(cr, rawsql);
						cr->rules[cvector_size(cr->rules) - 1].forword_type = RULE_FORWORD_SQLITE;
						cr->rules[cvector_size(cr->rules) - 1]
						    .sqlite_table = nng_strdup(jso_param->valuestring);
						cr->rules[cvector_size(cr->rules) - 1]
						    .raw_sql = nng_strdup(rawsql);
						cr->rules[cvector_size(cr->rules) - 1]
						    .enabled = true;
						cr->rules[cvector_size(cr->rules) - 1]
						    .rule_id = rule_generate_rule_id();
						nanomq_client_sqlite(cr, true);
					}
				}
			}
		} else if (!strcasecmp(name, "mysql")) {
			cr->option |= RULE_ENG_MDB;
			rule_mysql *mysql = rule_mysql_init();
			cJSON_ArrayForEach(jso_param, jso_params) {
				if (jso_param) {
					if (!nng_strcasecmp(jso_param->string, "table")) {
						mysql->table = nng_strdup(jso_param->valuestring);
						log_debug("table: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "username")) {
						mysql->username = nng_strdup(jso_param->valuestring);
						log_debug("username: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "password")) {
						mysql->password = nng_strdup(jso_param->valuestring);
						log_debug("password: %s\n", jso_param->valuestring);
					} else if (!nng_strcasecmp(jso_param->string, "host")) {
						mysql->host = nng_strdup(jso_param->valuestring);
						log_debug("host: %s\n", jso_param->valuestring);
					} else {
						puts("Unsupport key word!");
					}
				}
			}


			if (false == rule_mysql_check(mysql)) {
				cJSON_Delete(req);
				cJSON_Delete(res_obj);
				rule_mysql_free(mysql);
				return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
				    MISSING_KEY_REQUEST_PARAMES);
			}

			rule_sql_parse(cr, rawsql);
			cr->rules[cvector_size(cr->rules) - 1]
			    .forword_type = RULE_FORWORD_MYSOL;
			cr->rules[cvector_size(cr->rules) - 1]
				.mysql = mysql;
			cr->rules[cvector_size(cr->rules) - 1]
			    .raw_sql = nng_strdup(rawsql);
			cr->rules[cvector_size(cr->rules) - 1]
			    .enabled = true;
			cr->rules[cvector_size(cr->rules) - 1]
			    .rule_id = rule_generate_rule_id();
			if (-1 == nanomq_client_mysql(cr, true)) {
				rule_free(&cr->rules[cvector_size(cr->rules) - 1]);
				cvector_pop_back(cr->rules);
				cJSON_Delete(req);
				cJSON_Delete(res_obj);
				rule_mysql_free(mysql);
				return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
				    MISSING_KEY_REQUEST_PARAMES);
			}


		} else {
			log_debug("Unsupport forword type !");
		}

	}

	cJSON *jso_desc = cJSON_GetObjectItem(req, "description");
	if (jso_desc) {
		char *desc= cJSON_GetStringValue(jso_desc);
		log_debug("%s\n", desc);

	}

 	cJSON *data_info = cJSON_CreateObject();
	cJSON *actions = cJSON_CreateArray();

	cJSON_AddStringToObject(data_info, "rawsql", cr->rules[cvector_size(cr->rules) - 1].raw_sql);
	cJSON_AddNumberToObject(data_info, "id", cr->rules[cvector_size(cr->rules) - 1].rule_id);
	cJSON_AddBoolToObject(data_info, "enabled", cr->rules[cvector_size(cr->rules) - 1].enabled);
	cJSON_AddItemToObject(res_obj, "data", data_info);
	cJSON_AddItemToObject(res_obj, "actions", actions);
#endif

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

// TODO FIXME fixed enabled status error.
static http_msg
put_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}

	cJSON *res_obj = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)

	conf      *config = get_global_conf();
	conf_rule *cr     = &config->rule_eng;
	uint32_t  id     = 0;
	rule *old_rule = NULL;
	rule *new_rule = NULL;

	// Updated three parts， enabled status，sql and action
	// 1. update sql: parse sql, set raw_sql, set rule_id, do not need deal connection. free origin sql data,
	// 2. update enabled status: need to deal connection,  status changed will lead to connect/disconnect.
	// 3, update actions: need to deal connection，update repub/table.

	sscanf(rule_id, "rule:%u", &id);
	int i = 0;
	for (; i < cvector_size(cr->rules); i++) {
		if (rule_id && cr->rules[i].rule_id == id) {
			old_rule = &cr->rules[i];
			break;
		}
	}

	if (NULL == old_rule) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAM_ERROR);
	}

	cJSON *jso_sql = cJSON_GetObjectItem(req, "rawsql");
	if (NULL != jso_sql) {
		char *rawsql = cJSON_GetStringValue(jso_sql);
		rule_forword_type ft = old_rule->forword_type;
		repub_t *repub = old_rule->repub;
		char *sqlite_table = old_rule->sqlite_table;
		rule_mysql *mysql = old_rule->mysql;
		rule_sql_parse(cr, rawsql);
		new_rule = &cr->rules[cvector_size(cr->rules) - 1];
		new_rule->raw_sql = nng_strdup(rawsql);
		new_rule->enabled = true;
		new_rule->rule_id = id;
		new_rule->forword_type = ft;
		if (RULE_FORWORD_REPUB == ft) {
			new_rule->repub = repub;
		} else if (RULE_FORWORD_SQLITE == ft) {
			new_rule->sqlite_table = sqlite_table;
		} else if (RULE_FORWORD_MYSOL == ft) {
			new_rule->mysql = mysql;
		}

		// Maybe cvector_push_back() will realloc,
		// so for safty reassagn it
		old_rule = &cr->rules[i];
		rule_free(old_rule);
		cvector_erase(cr->rules, i);
		// TODO free old rule
	} else {

		if (old_rule->repub) {
			nng_close(*(nng_socket*) old_rule->repub->sock);
		}
		new_rule = old_rule;
	}

	cJSON *jso_enabled = cJSON_GetObjectItem(req, "enabled");
	if (NULL != jso_enabled) {
		new_rule->enabled = cJSON_IsTrue(jso_enabled);
	}

	// TODO support multi actions
	cJSON *jso_actions = cJSON_GetObjectItem(req, "actions");
	if (NULL != jso_actions) {
		cJSON *jso_action = NULL;
		cJSON_ArrayForEach(jso_action, jso_actions) {
			cJSON *jso_name = cJSON_GetObjectItem(jso_action, "name");
			char  *name     = cJSON_GetStringValue(jso_name);
			log_debug("name: %s\n", name);
			cJSON *jso_params = cJSON_GetObjectItem(jso_action, "params");
			cJSON *jso_param  = NULL;
			if (!nng_strcasecmp(name, "repub")) {
				cr->option |= RULE_ENG_RPB;
				if (NULL == new_rule->repub) {
					new_rule->repub = rule_repub_init();
					// TODO free new->table
				}
				repub_t *repub = new_rule->repub;
				new_rule->forword_type = RULE_FORWORD_REPUB;
				cJSON_ArrayForEach(jso_param, jso_params) {
					if (jso_param) {
						if (!nng_strcasecmp(jso_param->string, "topic")) {
							if (repub->topic) {
								nng_strfree(repub->topic);
							}
							repub->topic = nng_strdup(jso_param->valuestring);
							log_debug("topic: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "address")) {
							if (repub->address) {
								nng_strfree(repub->address);
							}
							repub->address = nng_strdup(jso_param->valuestring);
							log_debug("address: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "proto_ver")) {
							repub->proto_ver = jso_param->valueint;
							log_debug("proto_ver: %d\n", jso_param->valueint);
						} else if (!nng_strcasecmp(jso_param->string, "keepalive")) {
							repub->keepalive = jso_param->valueint;
							log_debug("keepalive: %d\n", jso_param->valueint);
						} else if (!nng_strcasecmp(jso_param->string, "clientid")) {
							if (repub->clientid) {
								nng_strfree(repub->clientid);
							}
							repub->clientid = nng_strdup(jso_param->valuestring);
							log_debug("clientid: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "username")) {
							if (repub->username) {
								nng_strfree(repub->username);
							}
							repub->username = nng_strdup(jso_param->valuestring);
							log_debug("username: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "password")) {
							if (repub->password) {
								nng_strfree(repub->password);
							}
							repub->password = nng_strdup(jso_param->valuestring);
							log_debug("password: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "clean_start")) {
							repub->clean_start = !nng_strcasecmp(jso_param->string, "true");
							log_debug("clean_start: %s\n", jso_param->valuestring);
						} else {
							puts("Unsupport key word!");
						}
					}
				}
			} else if (!strcasecmp(name, "sqlite")) {
				new_rule->forword_type = RULE_FORWORD_SQLITE;
				cJSON_ArrayForEach(jso_param, jso_params) {
					if (jso_param) {
						if (!nng_strcasecmp(jso_param->string, "table")) {
							log_debug("table: %s\n", jso_param->valuestring);
							if (new_rule->sqlite_table) {
								nng_strfree(new_rule->sqlite_table);
							} else {
								// TODO free repub;
							}
							new_rule->sqlite_table = nng_strdup(jso_param->valuestring);
							new_rule->rule_id = id;
							cr->rules[cvector_size(cr->rules) - 1] = *new_rule;

						}
					}
				}
			} else if (!strcasecmp(name, "mysql")) {
				if (NULL == new_rule->mysql) {
					new_rule->mysql = rule_mysql_init();
					// TODO free new->table
				}
				rule_mysql *mysql = new_rule->mysql;
				new_rule->forword_type = RULE_FORWORD_MYSOL;
				cJSON_ArrayForEach(jso_param, jso_params) {
					if (jso_param) {
						if (!nng_strcasecmp(jso_param->string, "table")) {
							if (mysql->table) {
								nng_strfree(mysql->table);
							}
							mysql->table = nng_strdup(jso_param->valuestring);
							log_debug("table: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "username")) {
							if (mysql->username) {
								nng_strfree(mysql->username);
							}
							mysql->username = nng_strdup(jso_param->valuestring);
							log_debug("username: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "password")) {
							if (mysql->password) {
								nng_strfree(mysql->password);
							}
							mysql->password = nng_strdup(jso_param->valuestring);
							log_debug("password: %s\n", jso_param->valuestring);
						} else if (!nng_strcasecmp(jso_param->string, "host")) {
							if (mysql->host) {
								nng_strfree(mysql->host);
							}
							mysql->host = nng_strdup(jso_param->valuestring);
							log_debug("host: %s\n", jso_param->valuestring);
						} else {
							puts("Unsupport key word!");
						}

					}

					// new_rule->rule_id = id;
					// cr->rules[cvector_size(cr->rules) - 1] = *new_rule;
				}


			} else {
				log_debug("Unsupport forword type !");
			}

		}

		if ((jso_enabled || jso_actions) && new_rule->enabled) {
			// TODO nng_mqtt_disconnct()
			// if (old_rule->repub) {
			// 	nng_close(*(nng_socket*) old_rule->repub->sock);
			// }
			if (RULE_FORWORD_REPUB == new_rule->forword_type) {
				nng_socket *sock  = (nng_socket *) nng_alloc(
					    	sizeof(nng_socket));
				nano_client(sock, new_rule->repub);
			} else if (RULE_FORWORD_SQLITE == new_rule->forword_type)
			{
				nanomq_client_sqlite(cr, true);
			}

		} else if (jso_enabled && false == new_rule->enabled) {
			// TODO nng_mqtt_disconnct()
		}

	}

	if (jso_enabled && new_rule->enabled) {
		// TODO nng_mqtt_disconnct()
		// if (old_rule->repub) {
		// 	nng_close(*(nng_socket*) old_rule->repub->sock);
		// }
		if (RULE_FORWORD_REPUB == new_rule->forword_type) {
			nng_socket *sock  = (nng_socket *) nng_alloc(
				    	sizeof(nng_socket));
			nano_client(sock, new_rule->repub);
		} else if (RULE_FORWORD_SQLITE == new_rule->forword_type)
		{
			nanomq_client_sqlite(cr, true);
		}

	} else if (jso_enabled && false == new_rule->enabled) {
		// TODO nng_mqtt_disconnct()
	}


	// cJSON *jso_desc = cJSON_GetObjectItem(req, "description");
	// char *desc= cJSON_GetStringValue(jso_desc);

 	cJSON *data_info = cJSON_CreateObject();
	cJSON *actions = cJSON_CreateArray();

	cJSON_AddStringToObject(data_info, "rawsql", new_rule->raw_sql);
	cJSON_AddNumberToObject(data_info, "id", new_rule->rule_id);
	cJSON_AddBoolToObject(data_info, "enabled", new_rule->enabled);
	cJSON_AddItemToObject(res_obj, "data", data_info);
	cJSON_AddItemToObject(res_obj, "actions", actions);
#endif
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static http_msg
delete_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res     = { 0 };
	res.status       = NNG_HTTP_STATUS_OK;
	cJSON   *res_obj = NULL;
	uint32_t id      = 0;
	res_obj          = cJSON_CreateObject();

	sscanf(rule_id, "rule:%d", &id);

#if defined(SUPP_RULE_ENGINE)
	conf * config   = get_global_conf();
	conf_rule *cr = &config->rule_eng;
	int i = 0;
	size_t size = cvector_size(cr->rules);
	for (; i < size; i++) {
		if (rule_id && cr->rules[i].rule_id == id) {
			// TODO free rule
			rule *re = &cr->rules[i];
			cvector_erase(cr->rules, i);
			break;
		}
	}

	if (rule_id && size == i) {
		cJSON_Delete(res_obj);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    MISSING_KEY_REQUEST_PARAMES);
	}


	// cJSON *meta = cJSON_CreateObject();
	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
#endif
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

// TODO add params realted key word
static http_msg
get_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *res_obj   = NULL;
	cJSON *data      = NULL;
	uint32_t id = 0;
	res_obj          = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)

	if (rule_id) {
		sscanf(rule_id, "rule:%d", &id);
		data = cJSON_CreateObject();
	} else {
		data = cJSON_CreateArray();
	}

	conf * config   = get_global_conf();
	conf_rule *cr = &config->rule_eng;
	int i = 0;
	for (; i < cvector_size(cr->rules); i++) {
		if (rule_id) {
			if (cr->rules[i].rule_id == id) {
				cJSON_AddStringToObject(
				    data, "rawsql", cr->rules[i].raw_sql);
				cJSON_AddNumberToObject(
				    data, "id", cr->rules[i].rule_id);
				cJSON_AddBoolToObject(
				    data, "enabled", cr->rules[i].enabled);
				break;
			}

		} else {
			cJSON *data_info = cJSON_CreateObject();
			cJSON_AddStringToObject(
			    data_info, "rawsql", cr->rules[i].raw_sql);
			cJSON_AddNumberToObject(
			    data_info, "id", cr->rules[i].rule_id);
			cJSON_AddBoolToObject(
			    data_info, "enabled", cr->rules[i].enabled);
			cJSON_AddItemToArray(data, data_info);
		}
	}


	if (rule_id && cvector_size(cr->rules) == i) {
		cJSON_Delete(res_obj);
		cJSON_Delete(data);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    MISSING_KEY_REQUEST_PARAMES);
	}

	// cJSON *meta = cJSON_CreateObject();
	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
	cJSON_AddItemToObject(res_obj, "data", data);
#endif
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static void *
get_client_info_cb(uint32_t pid)
{

	nng_pipe    pipe = { .id = pid };
	conn_param *cp   = nng_pipe_cparam(pipe);
	return (void *) conn_param_get_clientid(cp);
}

static http_msg
get_tree(http_msg *msg)
{
	http_msg res     = { 0 };
	res.status       = NNG_HTTP_STATUS_OK;
	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	res_obj          = cJSON_CreateObject();
	data_info        = cJSON_CreateArray();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", data_info);

	dbtree        *db = get_broker_db();
	dbtree_info ***vn =
	    (dbtree_info ***) dbtree_get_tree(db, get_client_info_cb);

	for (int i = 0; i < cvector_size(vn); i++) {
		cJSON *data_info_elem = cJSON_CreateArray();
		cJSON_AddItemToArray(data_info, data_info_elem);
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			cJSON *elem = cJSON_CreateObject();
			cJSON_AddItemToArray(data_info_elem, elem);
			cJSON_AddStringToObject(
			    elem, "topic", vn[i][j]->topic);
			nng_free(vn[i][j]->topic, strlen(vn[i][j]->topic));
			cJSON_AddNumberToObject(
			    elem, "cld_cnt", vn[i][j]->cld_cnt);
			cJSON *clients = cJSON_CreateStringArray(
			    (const char *const *) vn[i][j]->clients,
			    cvector_size(vn[i][j]->clients));
			cvector_free(vn[i][j]->clients);
			nng_free(vn[i][j], sizeof(dbtree_info));
			cJSON_AddItemToObject(elem, "clientid", clients);
		}
		cvector_free(vn[i]);
	}
	cvector_free(vn);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static char *
mk_str(int n, char **str_arr, char *seperator)
{
	size_t len = 0;
	char  *str = NULL;
	for (size_t i = 0; i < n; i++) {
		len += strlen(str_arr[i]) + strlen(seperator) + 2;
	}
	str = calloc(1, len);
	for (size_t i = 0; i < n; i++) {
		strcat(str, str_arr[i]);
		strcat(str, seperator);
	}
	return str;
}

#ifndef NANO_PLATFORM_WINDOWS
static void
ctrl_cb(void *arg)
{
	char * action = arg;
	int    argc   = get_cache_argc();
	char **argv   = get_cache_argv();
	char * cmd    = NULL;

	nng_msleep(2000);

	if (nng_strcasecmp(action, "stop") == 0) {
		argv[1] = "stop";
		cmd     = mk_str(2, argv, " ");
	} else if (nng_strcasecmp(action, "restart") == 0) {
		argv[1] = "restart";
		cmd     = mk_str(argc, argv, " ");
	}
	nng_strfree(action);
	if (cmd) {
		log_info("run system cmd: '%s'", cmd);
		system(cmd);
		free(cmd);
	}
}
#endif

static http_msg
post_ctrl(http_msg *msg, const char *type)
{
	http_msg    res = { 0 };
	nng_thread *thread;
	int         code = SUCCEED;

	if (nng_strcasecmp(type, "stop") == 0 ||
	    nng_strcasecmp(type, "restart") == 0) {
#ifndef NANO_PLATFORM_WINDOWS
		char *arg = nng_strdup(type);
		nng_thread_create(&thread, ctrl_cb, arg);
		res.status = NNG_HTTP_STATUS_OK;
#else
		res.status = NNG_HTTP_STATUS_NOT_ACCEPTABLE;
		code       = RPC_ERROR;
#endif
	} else {
		res.status = NNG_HTTP_STATUS_NOT_FOUND;
		code       = RPC_ERROR;
	}
	cJSON *res_obj;

	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	char *dest = cJSON_PrintUnformatted(res_obj);
	cJSON_Delete(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);

	return res;
}

static http_msg
show_reload_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	enum result_code code = SUCCEED;

	conf *config = get_global_conf();

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	cJSON *data = get_reload_config(config);
	cJSON_AddItemToObject(res_obj, "data", data);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
post_reload_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *conf_data = cJSON_GetObjectItem(req, "data");
	conf * config    = get_global_conf();

	set_reload_config(conf_data, config);
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static http_msg
get_config(http_msg *msg, const char *type)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	enum result_code code = SUCCEED;

	conf * config   = get_global_conf();
	cJSON *conf_obj = cJSON_CreateObject();

	if (type != NULL) {
		if (strcmp(type, "basic") == 0) {

			cJSON *basic = get_basic_config(config);
			cJSON_AddItemToObject(conf_obj, "basic", basic);

		} else if (strcmp(type, "tls") == 0) {

			cJSON *tls = get_tls_config(&config->tls, true);
			cJSON_AddItemToObject(conf_obj, "tls", tls);

		} else if (strcmp(type, "auth") == 0) {

			cJSON *auth = get_auth_config(&config->auths);
			cJSON_AddItemToObject(conf_obj, "auth", auth);

		} else if (strcmp(type, "auth_http") == 0) {

			cJSON *auth_http =
			    get_auth_http_config(&config->auth_http);
			cJSON_AddItemToObject(
			    conf_obj, "auth_http", auth_http);

		} else if (strcmp(type, "websocket") == 0) {

			cJSON *ws = get_websocket_config(&config->websocket);
			cJSON_AddItemToObject(conf_obj, "websocket", ws);

		} else if (strcmp(type, "http_server") == 0) {

			cJSON *http = get_http_config(&config->http_server);
			cJSON_AddItemToObject(conf_obj, "http_server", http);

		} else if (strcmp(type, "sqlite") == 0) {

			cJSON *sqlite = get_sqlite_config(&config->sqlite);
			cJSON_AddItemToObject(conf_obj, "sqlite", sqlite);

		} else if (strcmp(type, "bridge") == 0) {

			cJSON *bridge = get_bridge_config(&config->bridge, NULL);
			cJSON_AddItemToObject(conf_obj, "bridge", bridge);

		}
#ifdef SUPP_AWS_BRIDGE
		else if (strcmp(type, "aws_bridge") == 0) {
			cJSON *aws_bridge =
			    get_bridge_config(&config->aws_bridge, NULL);
			cJSON_AddItemToObject(
			    conf_obj, "aws_bridge", aws_bridge);
		}
#endif
		// TODO webhook ?
		// TODO log ?
		else {
			res.status = NNG_HTTP_STATUS_NOT_FOUND;
			code       = RPC_ERROR;
		}
	} else {
		cJSON *basic = get_basic_config(config);
		cJSON_AddItemToObject(conf_obj, "basic", basic);

		cJSON *tls = get_tls_config(&config->tls, true);
		cJSON_AddItemToObject(conf_obj, "tls", tls);

		cJSON *auth = get_auth_config(&config->auths);
		cJSON_AddItemToObject(conf_obj, "auth", auth);

		cJSON *auth_http = get_auth_http_config(&config->auth_http);
		cJSON_AddItemToObject(conf_obj, "auth_http", auth_http);

		cJSON *ws = get_websocket_config(&config->websocket);
		cJSON_AddItemToObject(conf_obj, "websocket", ws);

		cJSON *http = get_http_config(&config->http_server);
		cJSON_AddItemToObject(conf_obj, "http_server", http);

		cJSON *sqlite = get_sqlite_config(&config->sqlite);
		cJSON_AddItemToObject(conf_obj, "sqlite", sqlite);

		cJSON *bridge = get_bridge_config(&config->bridge, NULL);
		cJSON_AddItemToObject(conf_obj, "bridge", bridge);

#ifdef SUPP_AWS_BRIDGE
		cJSON *aws_bridge = get_bridge_config(&config->aws_bridge, NULL);
		cJSON_AddItemToObject(conf_obj, "aws_bridge", aws_bridge);
#endif
		// TODO webhook ?
		// TODO log ?
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	cJSON_AddItemToObject(res_obj, "data", conf_obj);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
post_config(http_msg *msg, const char *type)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *conf_data = cJSON_GetObjectItem(req, "data");
	conf * config    = get_global_conf();

	if (cJSON_IsObject(conf_data)) {
		if (type != NULL) {
			if (strcmp(type, "basic") == 0) {
				cJSON *basic =
				    cJSON_GetObjectItem(conf_data, "basic");
				if (cJSON_IsObject(basic)) {
					set_basic_config(basic, config);
				}

			} else if (strcmp(type, "tls") == 0) {
				cJSON *tls =
				    cJSON_GetObjectItem(conf_data, "tls");
				if (cJSON_IsObject(tls)) {
					set_tls_config(tls, config->conf_file,
					    &config->tls, "");
				}
			} else if (strcmp(type, "auth") == 0) {
				cJSON *auth =
				    cJSON_GetObjectItem(conf_data, "auth");
				if (cJSON_IsArray(auth)) {
					set_auth_config(auth,
					    config->conf_file, &config->auths);
				}
			} else if (strcmp(type, "auth_http") == 0) {
				cJSON *auth_http = cJSON_GetObjectItem(
				    conf_data, "auth_http");
				if (cJSON_IsObject(auth_http)) {
					set_auth_http_config(auth_http,
					    config->conf_file, &config->auth_http);
				}
			} else if (strcmp(type, "websocket") == 0) {
				cJSON *ws = cJSON_GetObjectItem(
				    conf_data, "websocket");
				if (cJSON_IsObject(ws)) {
					set_websocket_config(ws,
					    config->conf_file,
					    &config->websocket);
				}
			} else if (strcmp(type, "http_server") == 0) {
				cJSON *http = cJSON_GetObjectItem(
				    conf_data, "http_server");
				if (cJSON_IsObject(http)) {
					set_http_config(http,
					    config->conf_file,
					    &config->http_server);
				}
			} else if (strcmp(type, "sqlite") == 0) {
				cJSON *sqlite =
				    cJSON_GetObjectItem(conf_data, "sqlite");
				if (cJSON_IsObject(sqlite)) {
					set_sqlite_config(sqlite,
					    config->conf_file, &config->sqlite,
					    "");
				}
			} else if (strcmp(type, "bridge") == 0) {
			}
#ifdef SUPP_AWS_BRIDGE
			else if (strcmp(type, "aws_bridge") == 0) {
			}
#endif

		} else {
			cJSON *basic = cJSON_GetObjectItem(conf_data, "basic");
			if (cJSON_IsObject(basic)) {
				set_basic_config(basic, config);
			}

			cJSON *tls = cJSON_GetObjectItem(conf_data, "tls");
			if (cJSON_IsObject(tls)) {
				set_tls_config(
				    tls, config->conf_file, &config->tls, "");
			}

			cJSON *auth = cJSON_GetObjectItem(conf_data, "auth");
			if (cJSON_IsArray(auth)) {
				set_auth_config(
				    auth, config->conf_file, &config->auths);
			}

			cJSON *auth_http =
			    cJSON_GetObjectItem(conf_data, "auth_http");
			if (cJSON_IsArray(auth_http)) {
				set_auth_http_config(auth_http,
				    config->conf_file, &config->auth_http);
			}

			cJSON *ws =
			    cJSON_GetObjectItem(conf_data, "websocket");
			if (cJSON_IsObject(ws)) {
				set_websocket_config(
				    ws, config->conf_file, &config->websocket);
			}

			cJSON *http =
			    cJSON_GetObjectItem(conf_data, "http_server");
			if (cJSON_IsObject(http)) {
				set_http_config(http, config->conf_file,
				    &config->http_server);
			}

			cJSON *sqlite =
			    cJSON_GetObjectItem(conf_data, "sqlite");
			if (cJSON_IsObject(sqlite)) {
				set_sqlite_config(sqlite, config->conf_file,
				    &config->sqlite, "");
			}

			// TODO bridge
			// TODO aws_bridge
			// TODO webhook
			// TODO log
		}
	}
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static int
send_publish(nng_socket *sock, const char *clientid, char *payload,
    char **topics, size_t topic_count, uint8_t qos, uint8_t retain,
    bool encode_base64, property *props)
{
	int rv = 0;
	for (size_t i = 0; i < topic_count; i++) {
		nng_msg *pub_msg;
		nng_mqtt_msg_alloc(&pub_msg, 0);
		nng_mqtt_msg_set_packet_type(pub_msg, NNG_MQTT_PUBLISH);

		size_t payload_len = strlen(payload);
		if (encode_base64) {
			size_t out_size = BASE64_ENCODE_OUT_SIZE(payload_len);
			char * encode_data = nng_zalloc(out_size + 1);
			size_t len         = base64_encode(
                            (uint8_t *) payload, payload_len, encode_data);
			if (len > 0) {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, (uint8_t *) encode_data, len);
			} else {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, NULL, 0);
			}
			nng_strfree(encode_data);
		} else {
			nng_mqtt_msg_set_publish_payload(
			    pub_msg, (uint8_t *) payload, payload_len);
		}
		nng_mqtt_msg_set_publish_qos(pub_msg, qos);
		nng_mqtt_msg_set_publish_retain(pub_msg, retain);
		nng_mqtt_msg_set_publish_topic(pub_msg, topics[i]);

		uint8_t protover = MQTT_PROTOCOL_VERSION_v311;
		if (props != NULL) {
			protover = MQTT_PROTOCOL_VERSION_v5;
			property *dup_prop;
			property_dup(&dup_prop, props);
			nng_mqtt_msg_set_publish_property(pub_msg, dup_prop);
		}

		nng_msg *msg = NULL;
		if ((rv = encode_common_mqtt_msg(
		              &msg, pub_msg, clientid, protover) != 0) ||
		    (rv = nng_sendmsg(*sock, msg, 0)) != 0) {
     			nng_msg_free(msg);
			break;
		}
	}
	property_free(props);
	return rv;
}

static int
properties_parse(property **properties, cJSON *json)
{
	cJSON *   item;
	int       rv        = 0;
	uint8_t   byte      = 0;
	uint16_t  word      = 0;
	uint32_t  dword     = 0;
	char *    str       = NULL;
	uint8_t * bytes     = NULL;
	property *prop_list = property_alloc();
	property *sub_prop;

	getNumberValue(json, item, "payload_format_indicator", byte, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_u8(PAYLOAD_FORMAT_INDICATOR, byte);
		property_append(prop_list, sub_prop);
	}

	getNumberValue(json, item, "message_expiry_interval", word, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_u16(MESSAGE_EXPIRY_INTERVAL, word);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "response_topic", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_str(
		    RESPONSE_TOPIC, str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "correlation_data", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_binary(
		    CORRELATION_DATA, (uint8_t *) str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	getNumberValue(json, item, "subscription_identifier	", dword, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_varint(SUBSCRIPTION_IDENTIFIER, dword);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "content_type", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_str(
		    CORRELATION_DATA, str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	cJSON *prop_obj = cJSON_GetObjectItem(json, "user_properties");

	char number_str[50] = {0};

	cJSON_ArrayForEach(item, prop_obj)
	{
		if (cJSON_IsNumber(item)) {
			if (item->valuedouble - item->valueint == 0) {
				snprintf(number_str, 50, "%ld",
				    (long) item->valuedouble);
			} else {
				snprintf(
				    number_str, 50, "%lf", item->valuedouble);
			}
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), number_str,
		    strlen(number_str), true);
		}
		else if (cJSON_IsBool(item)) {
			snprintf(number_str, 50, "%s",
			    cJSON_IsTrue(item) ? "true" : "false");
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), number_str,
		    strlen(number_str), true);
		} else if (cJSON_IsString(item)) {
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), item->valuestring,
		    strlen(item->valuestring), true);
		} else {
			continue;
		}

		property_append(prop_list, sub_prop);
	}

	*properties = prop_list;
	return 0;

err:
	property_free(prop_list);
	return -1;
}

/**
 * send MQTT msg to broker socket
*/
static int
handle_publish_msg(cJSON *pub_obj, nng_socket *sock)
{
	cJSON *item;
	int    rv;
	char * topic          = NULL;
	char **topics         = NULL;
	size_t topic_count    = 0;
	getStringValue(pub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		getStringValue(pub_obj, item, "topics", topic, rv);
		if (rv != 0) {
			goto out;
		}
		// split topic by ","
		char *temp = NULL;
		char *ptr  = nano_strtok(topic, ",", &temp);

		while (ptr != NULL) {
			topic_count++;
			topics = realloc(topics, topic_count * sizeof(char *));
			topics[topic_count - 1] = ptr;
			ptr = nano_strtok(NULL, ",", &temp);
		}
	} else {
		topics      = nng_zalloc(sizeof(char *));
		topics[0]   = topic;
		topic_count = 1;
	}
	// clientid
	char *clientid;
	getStringValue(pub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		goto out;
	}
	// payload
	char *payload;
	getStringValue(pub_obj, item, "payload", payload, rv);
	if (rv != 0) {
		goto out;
	}
	// encoding
	char *encoding;

	getStringValue(pub_obj, item, "encoding", encoding, rv);
	if (rv != 0) {
		encoding = "plain";
	}

	// qos
	uint8_t qos = 0;
	getNumberValue(pub_obj, item, "qos", qos, rv);

	// retain
	bool retain = false;
	getBoolValue(pub_obj, item, "retain", retain, rv);

	// properties
	cJSON *json_prop = cJSON_GetObjectItem(pub_obj, "properties");
	property *props = NULL;
	if (cJSON_IsObject(json_prop)) {
		rv = properties_parse(&props, json_prop);
		if (rv != 0) {
			property_free(props);
			goto out;
		}
	}

	rv = send_publish(sock, clientid, payload, topics, topic_count, qos,
	    retain, strcmp(encoding, "base64") == 0, props);
	if (topics) {
		free(topics);
	}
	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	if (topics) {
		free(topics);
	}
	return REQ_PARAM_ERROR;
}

static int
handle_subscribe_msg(cJSON *sub_obj, nng_socket *sock)
{
	int    rv;
	char  *topic       = NULL;
	char **topics      = NULL;
	size_t topic_count = 0;
	cJSON *item;
	getStringValue(sub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		getStringValue(sub_obj, item, "topics", topic, rv);
		if (rv != 0) {
			goto out;
		}
		// split topic by ","
		char *temp = NULL;
		char *ptr  = nano_strtok(topic, ",", &temp);

		while (ptr != NULL) {
			topic_count++;
			topics = realloc(topics, topic_count * sizeof(char *));
			topics[topic_count - 1] = ptr;
			ptr = nano_strtok(NULL, ",", &temp);
		}
	} else {
		topics      = nng_zalloc(sizeof(char *));
		topics[0]   = topic;
		topic_count = 1;
	}

	char *clientid = NULL;
	getStringValue(sub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		goto out;
	}

	uint8_t qos = 0;
	getNumberValue(sub_obj, item, "qos", qos, rv);

	uint32_t          pid   = 0;
	struct hashmap_s *table = get_hashmap();
	dbtree           *db    = get_broker_db();
	if (0 != (pid = nano_hashmap_get(table, clientid, strlen(clientid)))) {
#ifdef STATISTICS
		// TODO
#endif

		int   topic_index = 0;
		int   topic_len   = 0;
		char *topic_str   = NULL;
		bool  topic_exist = false;
		while (topic_index < topic_count) {
			topic_str = topics[topic_index];
			puts(topic_str);
			topic_len = strlen(topic_str);

			/* Add items which not included in dbhash */
			topic_exist = dbhash_check_topic(pid, topic_str);
			if (!topic_exist) {
				dbtree_insert_client(db, topic_str, pid);

				dbhash_insert_topic(pid, topic_str, qos);
			}

			topic_index++;
		}
	}
	dbtree_print(db);

	if (topics) {
		free(topics);
	}
	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	if (topics) {
		free(topics);
	}
	return REQ_PARAM_ERROR;
}

static int
handle_unsubscribe_msg(cJSON *sub_obj, nng_socket *sock)
{
	int    rv;
	char  *topic       = NULL;
	char **topics      = NULL;
	size_t topic_count = 0;
	cJSON *item;
	getStringValue(sub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		goto out;
	}

	char *clientid = NULL;
	getStringValue(sub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		goto out;
	}

	uint32_t          pid   = 0;
	struct hashmap_s *table = get_hashmap();
	dbtree           *db    = get_broker_db();
	if (0 != (pid = nano_hashmap_get(table, clientid, strlen(clientid)))) {
		sub_ctx_del(db, topic, pid);
	}

	dbtree_print(db);

	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	return REQ_PARAM_ERROR;
}

/**
 * Post MQTT msg to broker via HTTP REST API
*/
static http_msg
post_mqtt_msg(http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	// send msg to broker via cb
	int rv = cb(req, sock);
	// return result code
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", rv);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);

	return res;
}

static http_msg
post_mqtt_msg_batch(http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsArray(req)) {
		goto out;
	}

	cJSON *temp;
	int rv = 0;
	int i;
	cJSON *res_arr = cJSON_CreateArray();
	for (i = 0; i < cJSON_GetArraySize(req); i++) {
		cJSON *item  = cJSON_GetArrayItem(req, i);
		char * topic = NULL;
		getStringValue(item, temp, "topics", topic, rv);
		if (rv != 0) {
			getStringValue(item, temp, "topic", topic, rv);
		}
		cJSON *res_item = cJSON_CreateObject();
		cJSON_AddStringToObject(res_item, "topic", topic);
		int code = cb(item, sock);
		cJSON_AddNumberToObject(res_item, "code", code);
		cJSON_AddItemToArray(res_arr, res_item);
	}
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(res_obj, "data", res_arr);
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;

out:
	if (!cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}
	return error_response(
	    msg, NNG_HTTP_STATUS_BAD_REQUEST, REQ_PARAMS_JSON_FORMAT_ILLEGAL);
}

static http_msg
get_mqtt_bridge(http_msg *msg, const char *name)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	conf * config    = get_global_conf();

	cJSON *bridge_json = cJSON_CreateObject();

	cJSON *bridge = get_bridge_config(&config->bridge, name);
	cJSON_AddItemToObject(bridge_json, "bridge", bridge);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", bridge_json);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
put_mqtt_bridge(http_msg *msg, const char *name)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *node_obj = cJSON_GetObjectItem(req, "data");
	conf * config   = get_global_conf();

	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node     = bridge->nodes[i];
		size_t            parallel = node->parallel;
		if (name != NULL && strcmp(node->name, name) != 0) {
			continue;
		}

		nng_mtx_lock(node->mtx);
		conf_bridge_node_destroy(node);
		conf_bridge_node_parse(node, &bridge->sqlite, node_obj);
		node->parallel = parallel;
		nng_mtx_unlock(node->mtx);

		found = true;
		// restart bridge client, parameters: config, node, node->sock
		bridge_reload(node->sock, config, node);
		break;
	}

	if (found) {
		cJSON *res_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
		char *dest = cJSON_PrintUnformatted(res_obj);

		put_http_msg(&res, "application/json", NULL, NULL, NULL, dest,
		    strlen(dest));

		cJSON_free(dest);
		cJSON_Delete(res_obj);
		cJSON_Delete(req);
		return res;
	} else {
		cJSON_Delete(req);
		return error_response(
		    msg, NNG_HTTP_STATUS_NOT_FOUND, REQ_PARAM_ERROR);
	}
}

static void
free_user_property(conf_user_property **prop, size_t sz)
{
	if (sz > 0 && prop) {
		for (size_t i = 0; i < sz; i++) {
			if (prop[i]) {
				if (prop[i]->key) {
					free(prop[i]->key);
				}
				if (prop[i]->value) {
					free(prop[i]->value);
				}
				free(prop[i]);
			}
		}
		cvector_free(prop);
		prop = NULL;
	}
}

static void
free_sub_property(conf_bridge_sub_properties *prop)
{
	if (prop) {
		free_user_property(
		    prop->user_property, prop->user_property_size);
		prop->user_property_size = 0;
		prop->identifier         = 0;
		free(prop);
		prop = NULL;
	}
}

static void
free_topic_list(topics **list, size_t count)
{
	if (list && count > 0) {
		for (size_t i = 0; i < count; i++) {
			if (list[i]->topic) {
				nng_free(list[i]->topic, list[i]->topic_len);
				list[i]->topic = NULL;
			}
			nng_free(list[i], sizeof(topics));
		}
		cvector_free(list);
		list = NULL;
	}
}

static void
free_string_list(char **list, size_t count)
{
	if (list && count > 0) {
		for (size_t i = 0; i < count; i++) {
			if (list[i]) {
				free(list[i]);
				list[i] = NULL;
			}
		}
		cvector_free(list);
		list = NULL;
	}
}

static nng_mqtt_topic_qos *
convert_topic_qos(topics **list, size_t count)
{
	nng_mqtt_topic_qos *topics = nng_mqtt_topic_qos_array_create(count);
	for (size_t i = 0; i < count; i++) {
		nng_mqtt_topic_qos_array_set(
		    topics, i, list[i]->topic, list[i]->qos, 1, 0, 0);
	}
	return topics;
}

static nng_mqtt_topic *
convert_topic(char **list, size_t count)
{
	nng_mqtt_topic *topics = nng_mqtt_topic_array_create(count);

	for (size_t i = 0; i < count; i++) {
		nng_mqtt_topic_array_set(topics, i, list[i]);
	}
	return topics;
}

static http_msg
post_mqtt_bridge_sub(http_msg *msg, const char *name)
{
	// node, [topic, qos], property
	http_msg             res    = { .status = NNG_HTTP_STATUS_OK };
	enum nng_http_status status = NNG_HTTP_STATUS_OK;
	int                  code   = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsObject(req)) {
		goto out;
	}

	cJSON *data_obj = cJSON_GetObjectItem(req, "data");
	if (!cJSON_IsObject(data_obj)) {
		goto out;
	}

	cJSON *sub_array = cJSON_GetObjectItem(data_obj, "subscription");

	if (!cJSON_IsArray(sub_array)) {
		goto out;
	}

	size_t   array_size = cJSON_GetArraySize(sub_array);

	topics **sub_topics = NULL;
	size_t   sub_count  = 0;

	cJSON *item;
	int    rv = 0;

	// Get topic list
	for (size_t i = 0; i < array_size; i++) {
		topics *tp       = nng_zalloc(sizeof(topics));
		cJSON * sub_item = cJSON_GetArrayItem(sub_array, i);
		getNumberValue(sub_item, item, "qos", tp->qos, rv);
		char *topic = NULL;
		getStringValue(sub_item, item, "topic", topic, rv);
		if (rv == 0) {
			tp->topic     = nng_strdup(topic);
			tp->topic_len = strlen(tp->topic);
		} else {
			continue;
		}
		cvector_push_back(sub_topics, tp);
		sub_count++;
	}

	// Get properties
	cJSON *json_prop = cJSON_GetObjectItem(data_obj, "sub_properties");
	conf_bridge_sub_properties *sub_props = NULL;

	if (cJSON_IsObject(json_prop)) {
		sub_props = nng_zalloc(sizeof(conf_bridge_sub_properties));
		getNumberValue(
		    json_prop, item, "identifier", sub_props->identifier, rv);
		cJSON *up_array =
		    cJSON_GetObjectItem(json_prop, "user_properties");
		size_t up_count = cJSON_GetArraySize(up_array);

		conf_user_property **conf_ups = NULL;

		for (size_t i = 0; i < up_count; i++) {
			char *key   = NULL;
			char *value = NULL;

			getStringValue(json_prop, item, "key", key, rv);
			if (rv == 0) {
				getStringValue(
				    json_prop, item, "value", value, rv);
				if (rv == 0) {
					conf_user_property *up = nng_zalloc(
					    sizeof(conf_user_property));
					up->key   = nng_strdup(key);
					up->value = nng_strdup(value);
					cvector_push_back(conf_ups, up);
				}
			}
		}
		sub_props->user_property      = conf_ups;
		sub_props->user_property_size = cvector_size(conf_ups);
	}

	conf *config = get_global_conf();

	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node = bridge->nodes[i];

		nng_mtx_lock(node->mtx);
		if (name != NULL && strcmp(node->name, name) != 0) {
			nng_mtx_unlock(node->mtx);
			continue;
		}

		// Decode properties to nng_mqtt_property
		property *prop_list = NULL;
		if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
			if (cJSON_IsObject(json_prop)) {
				properties_parse(&prop_list, json_prop);
			}
		}

		if (sub_count > 0) {
			// TODO handle repeated topics
			cvector_copy(sub_topics, node->sub_list);
			node->sub_count += sub_count;
		}
		if (sub_props != NULL) {
			free_sub_property(node->sub_properties);
			node->sub_properties = sub_props;
		}
		nng_mtx_unlock(node->mtx);

		cvector_free(sub_topics);
		found = true;

		// convert sub_topics to nng_mqtt_topic_qos
		// TODO uncomment the following line if you want to use nng_mqtt_topic_qos
		// nng_mqtt_topic_qos *topic_list = convert_topic_qos(node->sub_list, node->sub_count);

		// TODO @Wangha handle subscribe
		// TODO params: config, node, node->sock, topic_list, sub_count, prop_list
		break;
	}

	if (!found) {
		status = NNG_HTTP_STATUS_NOT_FOUND;
		code   = REQ_PARAM_ERROR;
		free_sub_property(sub_props);
		free_topic_list(sub_topics, sub_count);
		goto out;
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_Delete(req);
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;

out:
	if (cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}

	return error_response(msg,
	    status == NNG_HTTP_STATUS_NOT_FOUND ? status
	                                        : NNG_HTTP_STATUS_BAD_REQUEST,
	    (code == REQ_PARAM_ERROR ? code : REQ_PARAMS_JSON_FORMAT_ILLEGAL));
}

static http_msg
post_mqtt_bridge_unsub(http_msg *msg, const char *name)
{
	http_msg             res    = { .status = NNG_HTTP_STATUS_OK };
	enum nng_http_status status = NNG_HTTP_STATUS_OK;
	int                  code   = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsObject(req)) {
		goto out;
	}

	cJSON *data_obj = cJSON_GetObjectItem(req, "data");
	if (!cJSON_IsObject(data_obj)) {
		goto out;
	}

	// Get unsub topic list
	cJSON *unsub_array = cJSON_GetObjectItem(data_obj, "unsubscription");
	if (!cJSON_IsArray(unsub_array)) {
		goto out;
	}

	char **  unsub_topics = NULL;
	size_t   unsub_count  = 0;

	cJSON *item;
	int    rv = 0;

	size_t   array_size = cJSON_GetArraySize(unsub_array);

	for (size_t i = 0; i < array_size; i++) {
		cJSON * unsub_item = cJSON_GetArrayItem(unsub_array, i);
		char *topic = NULL;
		getStringValue(unsub_item, item, "topic", topic, rv);
		if (rv == 0) {
			topic     = nng_strdup(topic);
		} else {
			continue;
		}
		cvector_push_back(unsub_topics, topic);
		unsub_count++;
	}

	conf *config = get_global_conf();

	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node = bridge->nodes[i];
		nng_mtx_lock(node->mtx);
		if (name != NULL && strcmp(node->name, name) != 0) {
			nng_mtx_unlock(node->mtx);
			continue;
		}

		// Get properties
		property *prop_list = NULL;
		if (node->proto_ver == MQTT_VERSION_V5) {
			cJSON *json_prop =
			    cJSON_GetObjectItem(data_obj, "unsub_properties");

			if (cJSON_IsObject(json_prop)) {
				properties_parse(&prop_list, json_prop);
			}
		}

		for (size_t i = 0; i < unsub_count; i++) {
			char *unsub_topic = unsub_topics[i];
			for (size_t j = 0; j < node->sub_count; j++) {
				topics *sub_topic = node->sub_list[j];
				if (strcmp(unsub_topic,
				        sub_topic->topic) == 0) {

					cvector_erase(node->sub_list, j);
					node->sub_count--;
					nng_free(sub_topic->topic,
					    sub_topic->topic_len);
					nng_free(sub_topic, sizeof(topics));
					break;
				}
			}
		}
		nng_mtx_unlock(node->mtx);

		found = true;
		// convert unsub_topics to nng_mqtt_topic
		// TODO uncomment the following line if you want to use nng_mqtt_topic
		// nng_mqtt_topic *topic_list = convert_topic(unsub_topics, unsub_count);

		// TODO @Wangha handle unsubscribe
		// TODO params: config, node, node->sock, topic_list, unsub_count, prop_list
		break;
	}

	free_string_list(unsub_topics, unsub_count);

	if (!found) {
		status = NNG_HTTP_STATUS_NOT_FOUND;
		code   = REQ_PARAM_ERROR;
		goto out;
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_Delete(req);
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;

out:
	if (cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}

	return error_response(msg,
	    status == NNG_HTTP_STATUS_NOT_FOUND ? status
	                                        : NNG_HTTP_STATUS_BAD_REQUEST,
	    (code == REQ_PARAM_ERROR ? code : REQ_PARAMS_JSON_FORMAT_ILLEGAL));
}
