#ifndef DDS_PROXY_H
#define DDS_PROXY_H

#if defined(SUPP_DDS_PROXY)

#include <pthread.h>
#include <stdlib.h>

#include "vector.h"
#include "mqtt_client.h"

// #define DDS_TYPE_NAME_CAT1(A, B) A ## B
// #define DDS_TYPE_NAME_CAT(A, B) DDS_TYPE_NAME_CAT1(A, B)

// #define DDS_TYPE_NAME_FREE1(x, y) do {\
// 	DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, _free)(x, y); \
// } while (0)
// #define DDS_TYPE_NAME_FREE(x, y) DDS_TYPE_NAME_FREE1(x, y)
// #define DDS_TYPE_NAME_ALLOC() DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, __alloc())
// #define DDS_TYPE_NAME_DESC() DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, _desc)

// #define DDS_DATA_FREE(name, func) DDS_TYPE_NAME_FREE(name, func)
// #define DDS_DATA_ALLOC(name) DDS_TYPE_NAME_CAT(name, __alloc())
// #define DDS_DATA_DESC(name) DDS_TYPE_NAME_CAT(name, _desc())

typedef struct dds_cli dds_cli;

struct dds_cli {
	int running;

	nftp_vec *      handleq;
	pthread_mutex_t mtx;

	char *ddssend_topic;
	char *ddsrecv_topic;

	dds_gateway_conf *config;
};

int dds_publisher (int argc, char ** argv);
int dds_subscriber (int argc, char ** argv);
int dds_proxy_start (int argc, char ** argv);


#endif

#endif
