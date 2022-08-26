#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/queue.h>
#include "example.h"
#include "sshd.h"
#include "esp_log.h"

/* change this */
static struct ssh_user hardcoded_example_users[] = {
	{
		.su_user = "tnn",
		.su_keytype = SSH_KEYTYPE_ED25519,
		.su_base64_key = "AAAAC3NzaC1lZDI1NTE5AAAAIIv2sYdZCi7jXuUbhxo67hJLdsletjqcxhEp2y5C2QTL"
	}
};

/* obviously you'll want to replace this also */
const char *hardcoded_example_host_key =
"-----BEGIN OPENSSH PRIVATE KEY-----\n"
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
"QyNTUxOQAAACDYmnsxmICODLMs4LyJTcI7wXJEyZymY35oJiiY11YeeAAAAJDljBEl5YwR\n"
"JQAAAAtzc2gtZWQyNTUxOQAAACDYmnsxmICODLMs4LyJTcI7wXJEyZymY35oJiiY11YeeA\n"
"AAAECO+LnX2LE6GBUzQ6SCuHaZo7mFgPvZJljtdkfdvFZP09iaezGYgI4MsyzgvIlNwjvB\n"
"ckTJnKZjfmgmKJjXVh54AAAADGpvcmlzQG1haW5wYwE=\n"
"-----END OPENSSH PRIVATE KEY-----\n";

static struct ssh_user *
lookup_user(struct server_ctx *sc, const char *user)
{
	struct ssh_user *su;
	for (su = hardcoded_example_users; su->su_user; su++) {
		if (strcmp(user, su->su_user) == 0)
			return su;
	}
	return NULL;

}

void espidf_log(int priority, const char *funcname, const char *bufferdata, void *userdata) {
	ESP_LOGI("SSHD", "%s", bufferdata);
}

void
sshd_task(void *arg)
{
	ssh_set_log_callback(espidf_log);
	struct server_ctx *sc;
	sc = calloc(1, sizeof(struct server_ctx));
	if (!sc)
		return;
	sc->sc_host_key = hardcoded_example_host_key;
	sc->sc_lookup_user = lookup_user;
	sc->sc_begin_interactive_session = minicli_begin_interactive_session;
	sc->sc_auth_methods = SSH_AUTH_METHOD_PUBLICKEY;
	sshd_main(sc);
}

void
start_sshd(void)
{
	xTaskCreate(sshd_task, "sshd", 32768, NULL, 10, NULL);
}
