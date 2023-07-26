#include "tests_api.h"

conf*
get_wbhk_conf_base64()
{
	conf *conf                    = get_webhook_conf();
	conf->web_hook.encode_payload = base64;
	return conf;
}

int
main(int argc, char **argv)
{
	char *cmd_pub =
	    "mosquitto_pub -h 127.0.0.1 -p 1881 -t topic1 -m messagei+/ -q 2";
	int         rv;
	nng_thread *inproc_thr;
	uint16_t    port = 8888;
	nng_thread *nmq;
	FILE       *p_pub = NULL;
	conf       *conf;

	// start the RESTful http server thread
	rv = nng_thread_create(&inproc_thr, test_inproc_server, NULL);
	if (rv != 0) {
		fatal("cannot start inproc server", rv);
	}
	test_rest_start(port);
	// test for base64 as encoding method
	conf = get_wbhk_conf_base64();
	nng_thread_create(&nmq, broker_start_with_conf, conf);
	nng_msleep(800); // wait a while for broker to init.
	                 // webhook_server_start() will msleep for 500ms.

	p_pub = popen(cmd_pub, "r");
	pclose(p_pub);

	nng_thread_destroy(nmq);

	// printf("\tend_webhook_msg:%d\n", webhook_msg_cnt);
	assert(webhook_msg_cnt == 5);
}