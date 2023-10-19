/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2019, CyCore Systems, Inc
 *
 * Seán C McCord <scm@cycoresys.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief AudioSocket application -- transmit and receive audio through a TCP socket
 *
 * \author Seán C McCord <scm@cycoresys.com>
 *
 * \ingroup applications
 */

/*** MODULEINFO
	<depend>res_audiosocket</depend>
	<support_level>extended</support_level>
 ***/

#ifndef AST_MODULE
#define AST_MODULE "AudioSocket"
#endif

#include "asterisk.h"
#include "errno.h"
#include <uuid/uuid.h>

#include "asterisk/file.h"
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/app.h"
#include "asterisk/res_audiosocket.h"
#include "asterisk/utils.h"
#include "asterisk/format_cache.h"
#include "asterisk/audiohook.h"
#include "asterisk/autochan.h"

#define AUDIOSOCKET_CONFIG "audiosocket.conf"
#define MAX_CONNECT_TIMEOUT_MSEC 2000

/*** DOCUMENTATION
	<application name="AudioSocket" language="en_US">
		<synopsis>
			Transmit and receive audio between channel and TCP socket
		</synopsis>
		<syntax>
			<parameter name="uuid" required="true">
				<para>UUID is the universally-unique identifier of the call for the audio socket service.  This ID must conform to the string form of a standard UUID.</para>
			</parameter>
			<parameter name="service" required="true">
				<para>Service is the name or IP address and port number of the audio socket service to which this call should be connected.  This should be in the form host:port, such as myserver:9019 </para>
			</parameter>
		</syntax>
		<description>
			<para>Connects to the given TCP service, then transmits channel audio over that socket.  In turn, audio is received from the socket and sent to the channel.  Only audio frames will be transmitted.</para>
			<para>Protocol is specified at https://wiki.asterisk.org/wiki/display/AST/AudioSocket</para>
			<para>This application does not automatically answer and should generally be preceeded by an application such as Answer() or Progress().</para>
		</description>
	</application>
 ***/

static const char app[] = "AudioSocket";
static const char *const audiosocket_spy_type = "AudioSocket";

struct audiosocket_data {
	enum ast_audiohook_direction direction;
	struct ast_audiohook audiohook;
	ast_callid callid;
	struct ast_autochan *autochan;
	struct audiosocket_ds *audiosocket_ds;
	int samples_per_frame;
	char *server;
	char *idStr;


};

struct audiosocket_ds {
	ast_callid callid;
	unsigned int destruction_ok;
	ast_cond_t destruction_condition;
	ast_mutex_t lock;
	char *server;
	char *idStr;

	unsigned int samp_rate;
	struct ast_audiohook *audiohook;
};

static void audiosocket_ds_destroy(void *data)
{
	struct audiosocket_ds *audiosocket_ds = data;

	ast_mutex_lock(&audiosocket_ds->lock);
	audiosocket_ds->audiohook = NULL;
	audiosocket_ds->destruction_ok = 1;
	ast_free(audiosocket_ds->server);
	ast_free(audiosocket_ds->idStr);
	ast_cond_signal(&audiosocket_ds->destruction_condition);
	ast_mutex_unlock(&audiosocket_ds->lock);
}

static const struct ast_datastore_info audiosocket_ds_info = {
	.type = "audiosocket",
	.destroy = audiosocket_ds_destroy,
};

static int audiosocket_run(struct ast_channel *chan, struct audiosocket_data *audiosocket_data, const int svc);

static void audiosocket_destroy(void *data)
{
	struct audiosocket_ds *audiosocket_ds = data;

	ast_mutex_lock(&audiosocket_ds->lock);
	audiosocket_ds->audiohook = NULL;
	audiosocket_ds->destruction_ok = 1;
	ast_free(audiosocket_ds->server);
	ast_free(audiosocket_ds->idStr);
	ast_cond_signal(&audiosocket_ds->destruction_condition);
	ast_mutex_unlock(&audiosocket_ds->lock);
}

static int setup_audiosocket_ds(struct audiosocket_data *audiosocket_data, struct ast_channel *chan, char **datastore_id)
{
	struct ast_datastore *datastore = NULL;
	struct audiosocket_ds *audiosocket_ds;

	if (!(audiosocket_ds = ast_calloc(1, sizeof(*audiosocket_ds)))) {
		return -1;
	}

	if (ast_asprintf(datastore_id, "%p", audiosocket_ds) == -1) {
		ast_log(LOG_ERROR, "Failed to allocate memory for Audiosocket ID.\n");
		ast_free(audiosocket_ds);
		return -1;
	}

	ast_mutex_init(&audiosocket_ds->lock);
	ast_cond_init(&audiosocket_ds->destruction_condition, NULL);

	if (!(datastore = ast_datastore_alloc(&audiosocket_ds_info, *datastore_id))) {
		ast_mutex_destroy(&audiosocket_ds->lock);
		ast_cond_destroy(&audiosocket_ds->destruction_condition);
		ast_free(audiosocket_ds);
		return -1;
	}

	audiosocket_ds->samp_rate = 8000;
	audiosocket_ds->audiohook = &audiosocket_data->audiohook;
	audiosocket_ds->server = ast_strdup(audiosocket_data->server);
	audiosocket_ds->idStr = ast_strdup(audiosocket_data->idStr);
	datastore->data = audiosocket_ds;

	ast_channel_lock(chan);
	ast_channel_datastore_add(chan, datastore);
	ast_channel_unlock(chan);

	audiosocket_data->audiosocket_ds = audiosocket_ds;
	return 0;
}

static int start_audiohook(struct ast_channel *chan, struct ast_audiohook *audiohook)
{
	if (!chan) {
		return -1;
	}

	return ast_audiohook_attach(chan, audiohook);
}

static void audiosocket_free(struct audiosocket_data *audiosocket_data)
{
	if (audiosocket_data) {
		if (audiosocket_data->audiosocket_ds) {
			ast_mutex_destroy(&audiosocket_data->audiosocket_ds->lock);
			ast_cond_destroy(&audiosocket_data->audiosocket_ds->destruction_condition);
			ast_free(audiosocket_data->audiosocket_ds);
		}

		ast_free(audiosocket_data->server);
		ast_free(audiosocket_data->idStr);
		ast_free(audiosocket_data);
	}
}

static void *audiosocket_thread(void *obj)
{
	struct ast_format *format_slin;
	struct audiosocket_data *audiosocket_data = obj;
	struct ast_channel *chan = audiosocket_data->autochan->chan;

	int s = 0;
	struct ast_format *readFormat, *writeFormat;
	char *datastore_id = NULL;
	const char *chanName =  ast_channel_name(audiosocket_data->autochan->chan);
	int res;

	ast_module_unref(ast_module_info->self);

	if ((s = ast_audiosocket_connect(audiosocket_data->server, chan)) < 0) {
		/* The res module will already output a log message, so another is not needed */
		ast_log(LOG_ERROR, "Could not connect to audiosocket server\n");
		return 0;
	}

	writeFormat = ao2_bump(ast_channel_writeformat(chan));
	readFormat = ao2_bump(ast_channel_readformat(chan));

	if (ast_set_write_format(chan, ast_format_slin)) {
		ast_log(LOG_ERROR, "Failed to set write format to SLINEAR for channel %s\n", chanName);
		ao2_ref(writeFormat, -1);
		ao2_ref(readFormat, -1);
		return -1;
	}
	if (ast_set_read_format(chan, ast_format_slin)) {
		ast_log(LOG_ERROR, "Failed to set read format to SLINEAR for channel %s\n", chanName);

		/* Attempt to restore previous write format even though it is likely to
		 * fail, since setting the read format did.
		 */
		if (ast_set_write_format(chan, writeFormat)) {
			ast_log(LOG_ERROR, "Failed to restore write format for channel %s\n", chanName);
		}
		ao2_ref(writeFormat, -1);
		ao2_ref(readFormat, -1);
		return -1;
	}

	if (setup_audiosocket_ds(audiosocket_data, chan, &datastore_id)) {
		ast_autochan_destroy(audiosocket_data->autochan);
		audiosocket_free(audiosocket_data);
		ast_free(datastore_id);
		return -1;
	}

	ast_verb(2, "setup audiosocket ds successfully. server = %s direction = %d\n", audiosocket_data->server, audiosocket_data->direction);
	res = audiosocket_run(chan, audiosocket_data, s);
	/* On non-zero return, report failure */
	if (res) {
		/* Restore previous formats and close the connection */
		if (ast_set_write_format(chan, writeFormat)) {
			ast_log(LOG_ERROR, "Failed to restore write format for channel %s\n", chanName);
		}
		if (ast_set_read_format(chan, readFormat)) {
			ast_log(LOG_ERROR, "Failed to restore read format for channel %s\n", chanName);
		}
		ao2_ref(writeFormat, -1);
		ao2_ref(readFormat, -1);
		close(s);
		return res;
	}
	close(s);

	if (ast_set_write_format(chan, writeFormat)) {
		ast_log(LOG_ERROR, "Failed to restore write format for channel %s\n", chanName);
	}
	if (ast_set_read_format(chan, readFormat)) {
		ast_log(LOG_ERROR, "Failed to restore read format for channel %s\n", chanName);
	}
	ao2_ref(writeFormat, -1);
	ao2_ref(readFormat, -1);

	return 0;

	return NULL;
}

static int launch_audiosocket_thread(struct ast_channel *chan, char* server, char* idStr) {
	pthread_t thread;
	struct audiosocket_data *audiosocket_data;
	if (!(audiosocket_data = ast_calloc(1, sizeof(*audiosocket_data)))) {
		return -1;
	}
	ast_verb(2, "Starting audiosocket thread\n");
	audiosocket_data->callid = ast_read_threadstorage_callid();
	audiosocket_data->server = ast_strdup( server );
	audiosocket_data->idStr = ast_strdup( idStr );
	audiosocket_data->samples_per_frame = 160;
	audiosocket_data->direction = AST_AUDIOHOOK_DIRECTION_BOTH;

	if (!(audiosocket_data->autochan = ast_autochan_setup(chan))) {
		audiosocket_free(audiosocket_data);
		return -1;
	}

	// create an audiohook
	if (ast_audiohook_init(&audiosocket_data->audiohook, AST_AUDIOHOOK_TYPE_SPY, audiosocket_spy_type, 0)) {
		audiosocket_free(audiosocket_data);
		return -1;
	}

	if (start_audiohook(chan, &audiosocket_data->audiohook)) {
		ast_log(LOG_WARNING, "<%s> [Audiosocket] Unable to add audiohook type '%s'\n", ast_channel_name(chan), audiosocket_spy_type);
		ast_audiohook_destroy(&audiosocket_data->audiohook);
		audiosocket_free(audiosocket_data);
		return -1;
	}

	ast_verb(2, "<%s> [Audiosocket] Added AudioHook\n", ast_channel_name(chan));
	ast_verb(2, "Connection params server=%s idStr=%s direction=%d\n", audiosocket_data->server, audiosocket_data->idStr, audiosocket_data->direction);
	return ast_pthread_create_detached_background(&thread, NULL, audiosocket_thread, audiosocket_data);
}

static int audiosocket_exec(struct ast_channel *chan, const char *data)
{
	char *parse;
	struct ast_format *readFormat, *writeFormat;
	const char *chanName;
	int res;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(idStr);
		AST_APP_ARG(server);
	);

	int s = 0;
	uuid_t uu;

	/* Parse and validate arguments */
	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);
	if (ast_strlen_zero(args.idStr)) {
		ast_log(LOG_ERROR, "UUID is required\n");
		return -1;
	}
	if (uuid_parse(args.idStr, uu)) {
		ast_log(LOG_ERROR, "Failed to parse UUID '%s'\n", args.idStr);
		return -1;
	}


	chanName = ast_channel_name(chan);
	ast_verb(2, "Audiosocket was called\n");
	if (launch_audiosocket_thread( chan, args.server, args.idStr )) {
		ast_module_unref(ast_module_info->self);
		return -1;
	}
	return 0;
}

static void destroy_monitor_audiohook(struct audiosocket_data *audiosocket_data)
{
	if (audiosocket_data->audiosocket_ds) {
		ast_mutex_lock(&audiosocket_data->audiosocket_ds->lock);
		audiosocket_data->audiosocket_ds->audiohook = NULL;
		ast_mutex_unlock(&audiosocket_data->audiosocket_ds->lock);
	}
	/* kill the audiohook. */
	ast_audiohook_lock(&audiosocket_data->audiohook);
	ast_audiohook_detach(&audiosocket_data->audiohook);
	ast_audiohook_unlock(&audiosocket_data->audiohook);
	ast_audiohook_destroy(&audiosocket_data->audiohook);
}

static int audiosocket_run(struct ast_channel *chan, struct audiosocket_data *audiosocket_data, int svc)
{
	const char *chanName;
	struct ast_format *format_slin;

	if (!chan || ast_channel_state(chan) != AST_STATE_UP) {
		return -1;
	}

	const char* id = audiosocket_data->idStr;
	if (ast_audiosocket_init(svc, id)) {
		return -1;
	}

	int recvRetries;
	int writeRetries;
	int recvCounter = 0;
	int writeCounter = 0;
	recvRetries = 3;
	writeRetries = 3;
	chanName = ast_channel_name(chan);
	ast_verb(2, "audiosocket_run was called");
	ast_mutex_lock(&audiosocket_data->audiosocket_ds->lock);
	format_slin = ast_format_cache_get_slin_by_rate(audiosocket_data->audiosocket_ds->samp_rate);
	ast_mutex_unlock(&audiosocket_data->audiosocket_ds->lock);

	//ast_audiohook_lock(&audiosocket_data->audiohook);
	while (audiosocket_data->audiohook.status == AST_AUDIOHOOK_STATUS_RUNNING) {
		struct ast_channel *targetChan;
		int ms = 5000;
		int outfd = 0;
		struct ast_frame *f;

		if (!chan || ast_channel_state(chan) != AST_STATE_UP) {
			break;
		}

		if (outfd >= 0) {
			f = ast_audiosocket_receive_frame(svc);
			if (!f) {
				ast_log(LOG_ERROR, "Failed to receive frame from AudioSocket message for"
					"channel %s\n", chanName);
				if ( recvCounter >= recvRetries ) {
					break;
				} else {
					recvCounter++;
				}
			} else {
				recvCounter = 0;
			}
			if (ast_write(chan, f)) {
				//ast_log(LOG_WARNING, "Failed to forward frame to channel %s\n", chanName);
				if ( writeCounter >= writeRetries ) {
					ast_frfree(f);
					break;
				} else {
					writeCounter++;
				}
			} else {
				writeCounter = 0;
			}

			ast_frfree(f);
		}


		//ast_audiohook_lock(&audiosocket_data->audiohook);
	}

	ast_verb(4, "Closing audiosocket connection\n");
	ast_audiohook_unlock(&audiosocket_data->audiohook);
	destroy_monitor_audiohook(audiosocket_data);
	ast_autochan_destroy(audiosocket_data->autochan);
	audiosocket_free(audiosocket_data);
	audiosocket_free(audiosocket_data);
	ast_verb(4, "Closed connection successfully\n");

	return 0;
}

static int manager_audiosocket(struct mansession *s, const struct message *m)
{
	struct ast_channel *c;
	const char *name = astman_get_header(m, "Channel");
	const char *action_id = astman_get_header(m, "ActionID");
	const char *id = astman_get_header(m, "Id");
	const char *server = astman_get_header(m, "Server");
	int res;
	char args[PATH_MAX];

	if (ast_strlen_zero(name)) {
		astman_send_error(s, m, "No channel specified");
		return AMI_SUCCESS;
	}

	c = ast_channel_get_by_name(name);
	if (!c) {
		astman_send_error(s, m, "No such channel");
		return AMI_SUCCESS;
	}

	snprintf(args, sizeof(args), "%s,%s", id, server);

	res = audiosocket_exec(c, args);

	if (res) {
		ast_channel_unref(c);
		astman_send_error(s, m, "Could not start Audiosocket");
		return AMI_SUCCESS;
	}

	astman_append(s, "Response: Success\r\n");

	if (!ast_strlen_zero(action_id)) {
		astman_append(s, "ActionID: %s\r\n", action_id);
	}

	astman_append(s, "\r\n");

	ast_channel_unref(c);

	return AMI_SUCCESS;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	int res;
	res = ast_register_application_xml(app, audiosocket_exec);
	res |= ast_manager_register_xml("Audiosocket", EVENT_FLAG_SYSTEM, manager_audiosocket);

	return res;
}

AST_MODULE_INFO(
	ASTERISK_GPL_KEY,
	AST_MODFLAG_LOAD_ORDER,
	"AudioSocket Application",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load =	load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	.requires = "res_audiosocket",
);