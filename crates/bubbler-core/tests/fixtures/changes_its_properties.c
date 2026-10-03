/*
 * A stream that changes its own node's properties once it is in the
 * graph, as any client may with pw_stream_update_properties: the way a
 * sandbox's stream would turn itself into a device after the session
 * manager has already decided what it is.
 *
 * usage: changes_its_properties in|out <properties> <properties a second later>
 */
#include <spa/param/audio/format-utils.h>
#include <pipewire/pipewire.h>

struct state {
	struct pw_stream *stream;
	const char *later;
};

static void on_process(void *data)
{
	struct state *state = data;
	struct pw_buffer *buffer = pw_stream_dequeue_buffer(state->stream);
	if (buffer)
		pw_stream_queue_buffer(state->stream, buffer);
}

static const struct pw_stream_events events = {
	PW_VERSION_STREAM_EVENTS,
	.process = on_process,
};

static void on_timer(void *data, uint64_t expirations)
{
	struct state *state = data;
	struct pw_properties *later = pw_properties_new_string(state->later);
	pw_stream_update_properties(state->stream, &later->dict);
	pw_properties_free(later);
}

int main(int argc, char *argv[])
{
	if (argc != 4)
		return 2;
	pw_init(&argc, &argv);
	struct pw_main_loop *main_loop = pw_main_loop_new(NULL);
	struct pw_loop *loop = pw_main_loop_get_loop(main_loop);
	struct state state = { .later = argv[3] };
	state.stream = pw_stream_new_simple(loop, "changes-its-properties",
			pw_properties_new_string(argv[2]), &events, &state);

	uint8_t buffer[1024];
	struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
	const struct spa_pod *params[1] = {
		spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat,
				&SPA_AUDIO_INFO_RAW_INIT(.format = SPA_AUDIO_FORMAT_F32,
					.channels = 2, .rate = 48000,
					.position = { SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR })),
	};
	enum pw_direction direction =
		argv[1][0] == 'i' ? PW_DIRECTION_INPUT : PW_DIRECTION_OUTPUT;
	pw_stream_connect(state.stream, direction, PW_ID_ANY,
			PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS, params, 1);

	struct spa_source *timer = pw_loop_add_timer(loop, on_timer, &state);
	struct timespec second = { 1, 0 }, once = { 0, 0 };
	pw_loop_update_timer(loop, timer, &second, &once, false);
	pw_main_loop_run(main_loop);
	return 0;
}
