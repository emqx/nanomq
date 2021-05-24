#ifndef CONF_H
#define CONF_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "zmalloc.h"

#define USAGE \
		"Usage: nanomq broker {"\
		"{start|restart -url <url> [-daemon] [-tq_thread <num>] [-max_tq_thread <num>] [-parallel <num>] [--conf]}|stop}\n"\
		"  -url <url>            the form of 'tcp://ip_addr:host'\n"\
		"  -tq_thread <num>      the number of taskq threads used, `num` greater than 0 and less than 256\n"\
		"  -max_tq_thread <num>  the maximum number of taskq threads used, `num` greater than 0 and less than 256\n"\
		"  -parallel <num>       the maximum number of outstanding requests we can handle\n"\
		"  -property_size <num>  the max size for a MQTT user property\n"\
		"  -msq_len <num>        the queue length for resending messages\n"\
		"  -qos_timer <num>      the nano qos time\n"

#define CONF_READ_RECORD \
		"Conf_file: %s read as %s\n"

#define PID_PATH_NAME "/tmp/nanomq/nanomq.pid"
#define CONF_PATH_NAME "./etc/nanomq.conf"

struct conf {
	char*  url;
	int    daemon;
	int    num_taskq_thread;
	int    max_taskq_thread;
	int    parallel;
    int    property_size;
    int    msq_len;
    int    qos_timer;
	void*  db_root;
};

typedef struct conf conf;

extern bool conf_parser(conf **nanomq_conf);
extern void macro_def_parser(conf **nanomq_conf);
extern void print_conf(conf *nanomq_conf);

#endif 