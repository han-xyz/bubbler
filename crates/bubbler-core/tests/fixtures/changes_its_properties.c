/*
 * A stream that changes its own node's properties once it is in the
 * graph, as any client may with pw_stream_update_properties: the way a
 * sandbox's stream would turn itself into a device after the session
 * manager has already decided what it is.
 *
 * It prints every global its client is shown, as `pw-mon` does: what the
 * stream's own client sees of the graph.
 *
 * usage: changes_its_properties in|out <properties> [<properties a second later>]
 */
#include <spa/param/audio/format-utils.h>
#include <pipewire/pipewire.h>

struct state {
	struct pw_stream *stream;
	struct pw_properties *later;
	struct spa_hook registry_listener;
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

static void on_global(void *data, uint32_t id, uint32_t permissions,
		const char *type, uint32_t version, const struct spa_dict *props)
{
	printf("added:\n\tid: %u\n", id);
	fflush(stdout);
}

static void on_global_remove(void *data, uint32_t id)
{
	printf("removed:\n\tid: %u\n", id);
	fflush(stdout);
}

static const struct pw_registry_events registry_events = {
	PW_VERSION_REGISTRY_EVENTS,
	.global = on_global,
	.global_remove = on_global_remove,
};

static void on_timer(void *data, uint64_t expirations)
{
	struct state *state = data;
	pw_stream_update_properties(state->stream, &state->later->dict);
}

int main(int argc, char *argv[])
{
	if (argc != 3 && argc != 4)
		return 2;
	pw_init(&argc, &argv);
	struct pw_main_loop *main_loop = pw_main_loop_new(NULL);
	struct pw_loop *loop = pw_main_loop_get_loop(main_loop);
	struct pw_properties *props = pw_properties_new_string(argv[2]);
	struct state state = { 0 };
	if (argc == 4 && !(state.later = pw_properties_new_string(argv[3])))
		return 2;
	if (!props)
		return 2;
	state.stream = pw_stream_new_simple(loop, "changes-its-properties",
			props, &events, &state);
	if (!state.stream)
		return 2;

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

	struct pw_registry *registry =
		pw_core_get_registry(pw_stream_get_core(state.stream), PW_VERSION_REGISTRY, 0);
	pw_registry_add_listener(registry, &state.registry_listener, &registry_events, NULL);

	if (state.later) {
		struct spa_source *timer = pw_loop_add_timer(loop, on_timer, &state);
		struct timespec second = { 1, 0 }, once = { 0, 0 };
		pw_loop_update_timer(loop, timer, &second, &once, false);
	}
	pw_main_loop_run(main_loop);
	return 0;
}
