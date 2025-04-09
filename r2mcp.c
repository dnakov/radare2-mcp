/* r2mcp - MIT - Copyright 2025 - pancake, dnakov */

#include <r_core.h>
#include <r_util/r_json.h>
#include <r_util/r_print.h>

#define R2MCP_DEBUG   1
#define R2MCP_LOGFILE "/tmp/r2mcp.txt"

static inline void r2mcp_log(const char *x) {
#if R2MCP_DEBUG
	r_file_dump (R2MCP_LOGFILE, (const ut8 *)(x), -1, true);
	r_file_dump (R2MCP_LOGFILE, (const ut8 *)"\n", -1, true);
#else
	// do nothing
#endif
}

static st64 r_json_get_num(const RJson *json, const char *key) {
	if (!json || !key) {
		return 0;
	}

	const RJson *field = r_json_get (json, key);
	if (!field || field->type != R_JSON_STRING) {
		return 0;
	}

	return r_num_get (NULL, field->str_value);
}

static const char *r_json_get_str(const RJson *json, const char *key) {
	if (!json || !key) {
		return NULL;
	}

	const RJson *field = r_json_get (json, key);
	if (!field || field->type != R_JSON_STRING) {
		return NULL;
	}

	return field->str_value;
}

#define PORT            3000
#define BUFFER_SIZE     65536
#define READ_CHUNK_SIZE 32768

#define LATEST_PROTOCOL_VERSION "2024-11-05"

typedef struct {
	const char *name;
	const char *version;
} ServerInfo;

typedef struct {
	bool logging;
	bool tools;
} ServerCapabilities;

typedef struct {
	ServerInfo info;
	ServerCapabilities capabilities;
	const char *instructions;
	bool initialized;
	RJson *client_capabilities;
	RJson *client_info;
} ServerState;

// TODO: remove globals
static RCore *r_core = NULL;
static bool file_opened = false;
static char current_file[1024] = { 0 };
static volatile sig_atomic_t running = 1;
static bool is_direct_mode = false;
static ServerState server_state = {
	.info = {
		.name = "Radare2 MCP Connector",
		.version = "1.0.0" },
	.capabilities = { .logging = true, .tools = true },
	.instructions = "Use this server to analyze binaries with radare2",
	.initialized = false,
	.client_capabilities = NULL,
	.client_info = NULL
};

// Forward declarations
static void process_mcp_message(const char *msg);
static void direct_mode_loop(void);

#define JSON_RPC_VERSION "2.0"
#define MCP_VERSION      "2024-11-05"

typedef struct {
	char *data;
	size_t size;
	size_t capacity;
} ReadBuffer;

static void r2_settings(RCore *core) {
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", false);
	r_config_set_b (core->config, "scr.interactive", false);
	r_config_set_b (core->config, "emu.str", true);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "asm.lines.fcn", false);
	r_config_set_b (core->config, "asm.cmt.right", false);
	r_config_set_b (core->config, "scr.html", false);
	r_config_set_b (core->config, "scr.prompt", false);
	r_config_set_b (core->config, "scr.echo", false);
	r_config_set_b (core->config, "scr.flush", true);
	r_config_set_b (core->config, "scr.null", false);
	r_config_set_b (core->config, "scr.pipecolor", false);
	r_config_set_b (core->config, "scr.utf8", false);
}

static char *r2_cmd_filter(const char *cmd, bool *changed) {
	char *res = r_str_trim_dup (cmd);
	char fchars[] = "|>`";
	*changed = false;
	if (*res == '!') {
		*changed = true;
		*res = 0;
	} else {
		char *ch = strstr (res, "$(");
		if (ch) {
			*changed = true;
			*ch = 0;
		}
		for (ch = fchars; *ch; ch++) {
			char *p = strchr (res, *ch);
			if (p) {
				*changed = true;
				*p = 0;
			}
		}
	}
	return res;
}

static char *r2_cmd(const char *cmd) {
	if (!r_core || !file_opened) {
		return strdup ("Error: No file is open");
	}
	bool changed = false;
	char *filteredCommand = r2_cmd_filter (cmd, &changed);
	if (changed) {
		r2mcp_log ("command injection prevented");
	}
	char *res = r_core_cmd_str (r_core, filteredCommand);
	free (filteredCommand);
	r2_settings (r_core);
	return res;
}

ReadBuffer *read_buffer_new(void) {
	ReadBuffer *buf = R_NEW (ReadBuffer);
	buf->data = malloc (BUFFER_SIZE);
	buf->size = 0;
	buf->capacity = BUFFER_SIZE;
	return buf;
}

static void read_buffer_append(ReadBuffer *buf, const char *data, size_t len) {
	if (buf->size + len > buf->capacity) {
		size_t new_capacity = buf->capacity * 2;
		char *new_data = realloc (buf->data, new_capacity);
		if (!new_data) {
			R_LOG_ERROR ("Failed to resize buffer");
			return;
		}
		buf->data = new_data;
		buf->capacity = new_capacity;
	}
	memcpy (buf->data + buf->size, data, len);
	buf->size += len;
}

static char *read_buffer_get_message(ReadBuffer *buf) {
	char *newline = memchr (buf->data, '\n', buf->size);
	if (!newline) {
		return NULL;
	}

	size_t msg_len = newline - buf->data;
	char *msg = malloc (msg_len + 1);
	memcpy (msg, buf->data, msg_len);
	msg[msg_len] = '\0';

	size_t remaining = buf->size - (msg_len + 1);
	if (remaining > 0) {
		memmove (buf->data, newline + 1, remaining);
	}
	buf->size = remaining;

	return msg;
}

static void read_buffer_free(ReadBuffer *buf) {
	if (buf) {
		free (buf->data);
		free (buf);
	}
}

static char *get_capabilities();
static char *handle_initialize(RJson *params);
static char *handle_list_tools(RJson *params);
static char *handle_call_tool(RJson *params);
static char *format_string(const char *format, ...);
static char *format_string(const char *format, ...) {
	char buffer[4096];
	va_list args;
	va_start (args, format);
	vsnprintf (buffer, sizeof (buffer), format, args);
	va_end (args);
	return strdup (buffer);
}

static bool init_r2(void) {
	r_core = r_core_new ();
	if (!r_core) {
		R_LOG_ERROR ("Failed to initialize radare2 core");
		return false;
	}

	r2_settings (r_core);

	R_LOG_INFO ("Radare2 core initialized");
	return true;
}

static void cleanup_r2(void) {
	if (r_core) {
		r_core_free (r_core);
		r_core = NULL;
		file_opened = false;
		memset (current_file, 0, sizeof (current_file));
	}
}

static bool r2_open_file(const char *filepath) {
	R_LOG_INFO ("Attempting to open file: %s\n", filepath);

	if (!r_core && !init_r2 ()) {
		R_LOG_ERROR ("Failed to initialize r2 core\n");
		return false;
	}

	if (file_opened) {
		R_LOG_INFO ("Closing previously opened file: %s", current_file);
		r_core_cmd0 (r_core, "o-*");
		file_opened = false;
		memset (current_file, 0, sizeof (current_file));
	}

	r_core_cmd0 (r_core, "e bin.relocs.apply=true");
	r_core_cmd0 (r_core, "e bin.cache=true");

	char *cmd = r_str_newf ("'o %s", filepath);
	R_LOG_INFO ("Running r2 command: %s", cmd);
	char *result = r_core_cmd_str (r_core, cmd);
	free (cmd);
	bool success = (result && strlen (result) > 0);
	free (result);

	if (!success) {
		R_LOG_INFO ("Trying alternative method to open file");
		RIODesc *fd = r_core_file_open (r_core, filepath, R_PERM_R, 0);
		if (fd) {
			r_core_bin_load (r_core, filepath, 0);
			R_LOG_INFO ("File opened using r_core_file_open");
			success = true;
		} else {
			R_LOG_ERROR ("Failed to open file: %s", filepath);
			return false;
		}
	}

	R_LOG_INFO ("Loading binary information");
	r_core_cmd0 (r_core, "ob");

	strncpy (current_file, filepath, sizeof (current_file) - 1);
	file_opened = true;
	R_LOG_INFO ("File opened successfully: %s", filepath);

	return true;
}

static bool r2_analyze(int level) {
	if (!r_core || !file_opened) {
		return false;
	}
	const char *cmd = "aa";
	switch (level) {
	case 1: cmd = "aaa"; break;
	case 2: cmd = "aaaa"; break;
	case 3: cmd = "aaaaa"; break;
	}
	cmd = "af @@ sym.*";
	r_core_cmd0 (r_core, cmd);
	return true;
}

static void signal_handler(int signum) {
	const char msg[] = "\nInterrupt received, shutting down...\n";
	write (STDERR_FILENO, msg, sizeof (msg) - 1);

	running = 0;

	signal (signum, SIG_DFL);
}

static bool check_client_capability(const char *capability) {
	if (!server_state.client_capabilities) {
		return false;
	}
	RJson *cap = (RJson *)r_json_get (server_state.client_capabilities, capability);
	return cap != NULL;
}

static bool check_server_capability(const char *capability) {
	if (!strcmp (capability, "logging")) {
		return server_state.capabilities.logging;
	}
	if (!strcmp (capability, "tools")) {
		return server_state.capabilities.tools;
	}
	return false;
}

static bool assert_capability_for_method(const char *method, char **error) {
	if (!strcmp (method, "sampling/createMessage")) {
		if (!check_client_capability ("sampling")) {
			*error = strdup ("Client does not support sampling");
			return false;
		}
	} else if (!strcmp (method, "roots/list")) {
		if (!check_client_capability ("roots")) {
			*error = strdup ("Client does not support listing roots");
			return false;
		}
	}
	return true;
}

static bool assert_request_handler_capability(const char *method, char **error) {
	if (!strcmp (method, "sampling/createMessage")) {
		if (!check_server_capability ("sampling")) {
			*error = strdup ("Server does not support sampling");
			return false;
		}
	} else if (!strcmp (method, "logging/setLevel")) {
		if (!check_server_capability ("logging")) {
			*error = strdup ("Server does not support logging");
			return false;
		}
	} else if (!strncmp (method, "prompts/", 8)) {
		if (!check_server_capability ("prompts")) {
			*error = strdup ("Server does not support prompts");
			return false;
		}
	} else if (!strncmp (method, "tools/", 6)) {
		if (!check_server_capability ("tools")) {
			*error = strdup ("Server does not support tools");
			return false;
		}
	}
	return true;
}

// Helper function to create JSON-RPC error responses
static char *create_error_response(int code, const char *message, const char *id, const char *uri) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");
	if (id) {
		pj_ks (pj, "id", id);
	}
	pj_k (pj, "error");
	pj_o (pj);
	pj_ki (pj, "code", code);
	pj_ks (pj, "message", message);
	if (uri) {
		pj_k (pj, "data");
		pj_o (pj);
		pj_ks (pj, "uri", uri);
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

// Helper function to create a successful JSON-RPC response
static char *create_success_response(const char *result, const char *id) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "jsonrpc", "2.0");
	if (id) {
		pj_ks (pj, "id", id);
	}
	pj_k (pj, "result");
	if (result) {
		pj_raw (pj, result);
	} else {
		pj_null (pj);
	}
	pj_end (pj);
	char *s = pj_drain (pj);
	r2mcp_log (">>>");
	r2mcp_log (s);
	return s;
}

#if 0
// Helper function to create tool error responses with specific format
static char *create_tool_error_response(const char *error_message) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", error_message);
	pj_end (pj);
	pj_end (pj);
	pj_kb (pj, "isError", true);
	pj_end (pj);
	return pj_drain (pj);
}
#endif

// Helper function to create a simple text tool result
static char *create_tool_text_response(const char *text) {
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_k (pj, "content");
	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "type", "text");
	pj_ks (pj, "text", text);
	pj_end (pj);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static char *handle_mcp_request(const char *method, RJson *params, const char *id) {
	char *error = NULL;
	char *result = NULL;

	if (!assert_capability_for_method (method, &error) || !assert_request_handler_capability (method, &error)) {
		char *response = create_error_response (-32601, error, id, NULL);
		free (error);
		return response;
	}

	if (!strcmp (method, "initialize")) {
		result = handle_initialize (params);
	} else if (!strcmp (method, "notifications/initialized")) {
		return NULL; // No response for notifications
	} else if (!strcmp (method, "ping")) {
		result = strdup ("{}");
	} else if (!strcmp (method, "resources/templates/list")) {
		return create_error_response (-32601, "Method not implemented: templates are not supported", id, NULL);
	} else if (!strcmp (method, "resources/list")) {
		return create_error_response (-32601, "Method not implemented: resources are not supported", id, NULL);
	} else if (!strcmp (method, "resources/read") || !strcmp (method, "resource/read")) {
		return create_error_response (-32601, "Method not implemented: resources are not supported", id, NULL);
	} else if (!strcmp (method, "resources/subscribe") || !strcmp (method, "resource/subscribe")) {
		return create_error_response (-32601, "Method not implemented: subscriptions are not supported", id, NULL);
	} else if (!strcmp (method, "tools/list") || !strcmp (method, "tool/list")) {
		result = handle_list_tools (params);
	} else if (!strcmp (method, "tools/call") || !strcmp (method, "tool/call")) {
		result = handle_call_tool (params);
	} else {
		return create_error_response (-32601, "Unknown method", id, NULL);
	}

	char *response = create_success_response (result, id);
	free (result);
	return response;
}

static char *handle_initialize(RJson *params) {
	if (server_state.client_capabilities) {
		r_json_free (server_state.client_capabilities);
	}
	if (server_state.client_info) {
		r_json_free (server_state.client_info);
	}

	server_state.client_capabilities = (RJson *)r_json_get (params, "capabilities");
	server_state.client_info = (RJson *)r_json_get (params, "clientInfo");

	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "protocolVersion", LATEST_PROTOCOL_VERSION);
	pj_k (pj, "serverInfo");
	pj_o (pj);
	pj_ks (pj, "name", server_state.info.name);
	pj_ks (pj, "version", server_state.info.version);
	pj_end (pj);
	pj_k (pj, "capabilities");
	pj_raw (pj, get_capabilities ());
	if (server_state.instructions) {
		pj_ks (pj, "instructions", server_state.instructions);
	}
	pj_end (pj);

	server_state.initialized = true;
	return pj_drain (pj);
}

static char *get_capabilities(void) {
	PJ *pj = pj_new ();
	pj_o (pj);

	pj_ko (pj, "experimental");
	pj_end (pj);

	pj_ko (pj, "tools");
	pj_kb (pj, "listChanged", false);
	pj_end (pj);

	pj_ko (pj, "prompts");
	pj_kb (pj, "listChanged", false);
	pj_end (pj);

	pj_ko (pj, "resources");
	pj_kb (pj, "listChanged", false);
	pj_kb (pj, "subscribe", false);
	pj_end (pj);

	pj_end (pj);
	return pj_drain (pj);
}

static char *handle_list_tools(RJson *params) {
	// Add pagination support
	const char *cursor = r_json_get_str (params, "cursor");
	int page_size = 32; // Default page size XXX pagination doesnt work. just use > len (tools)
	int start_index = 0;

	// Parse cursor if provided
	if (cursor) {
		start_index = atoi (cursor);
		if (start_index < 0) {
			start_index = 0;
		}
	}

	// Use more straightforward JSON construction for tools list
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_append (sb, "{\"tools\":[");

	// fprintf (stream, "{\"tools\":[");

	// Define our tools with their descriptions and schemas
	// Format: {name, description, schema_definition}
	const char *tools[18][3] = {
		{ "openFile",
			"Open a file for analysis",
			"{\"type\":\"object\",\"properties\":{\"filePath\":{\"type\":\"string\",\"description\":\"Path to the file to open\"}},\"required\":[\"filePath\"]}" },
		{ "closeFile",
			"Close the currently open file",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listFunctions",
			"Enumerate all the functions found, listing the address and its name",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listLibraries",
			"Enumerate all the libraries used by the binary",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listImports",
			"Enumerate all the symbols imported in the binary",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listSymbols",
			"Enumerate all the symbols exported from the binary",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listEntrypoints",
			"Enumerate entrypoints",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "listMethods",
			"Enumerate methods for the given class",
			"{\"type\":\"object\",\"properties\":{\"classname\":{\"type\":\"string\",\"description\":\"Name of the class to list its methods\"}},\"required\":[\"classname\"]}" },
		{ "listClasses",
			"Enumerate all the class names from C++, ObjC, Swift, Java, Dalvik",
			"{\"type\":\"object\",\"properties\":{\"regexpFilter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}" },
		{ "listDecompilers",
			"List all the decompilers available for radare2",
			"{\"type\":\"object\",\"properties\":{}}" },
		{ "renameFunction",
			"Rename function at given address",
			"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"},\"address\":{\"type\":\"string\",\"description\":\"address of the function to rename\"}},\"required\":[\"name\",\"address\"]}" },
		{ "useDecompiler",
			"Use given decompiler",
			"{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Name of the decompiler\"}},\"required\":[\"name\"]}" },
		{ "listStrings",
			"List strings matching the given regexp",
			"{\"type\":\"object\",\"properties\":{\"regexpFilter\":{\"type\":\"string\",\"description\":\"Regular expression to filter the results\"}}}" },
#if 0
		{ "runCommand",
			"Run a radare2 command and get the output",
			"{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"Command to execute\"}},\"required\":[\"command\"]}" },
#endif
		{ "analyze",
			"Run analysis on the current file",
			"{\"type\":\"object\",\"properties\":{\"level\":{\"type\":\"number\",\"description\":\"Analysis level (0, 1, 2, 3)\"}},\"required\":[]}" },
		{ "xrefsTo",
			"List all the references to the given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the address to check for crossed references\"}},\"required\":[\"address\"]}" },
		{ "decompileFunction",
			"Decompile function at given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to decompile\"}},\"required\":[\"address\"]}" },
		{ "disassembleFunction",
			"Disassemble function at given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address of the function to disassemble\"}},\"required\":[\"address\"]}" },
		{ "disassemble",
			"Disassemble instructions at a given address",
			"{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\",\"description\":\"Address to start disassembly\"},\"numInstructions\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble\"}},\"required\":[\"address\"]}" }
	};

	int total_tools = sizeof (tools) / sizeof (tools[0]);
	int end_index = start_index + page_size;
	if (end_index > total_tools) {
		end_index = total_tools;
	}

	// Add tools for this page
	for (int i = start_index; i < end_index; i++) {
		if (i > start_index) {
			r_strbuf_appendf (sb, ",");
		}
		r_strbuf_appendf (sb, "{\"name\":\"%s\",\"description\":\"%s\",\"inputSchema\":%s}",
			tools[i][0], tools[i][1], tools[i][2]);
	}

	r_strbuf_append (sb, "]");

	// Add nextCursor if there are more tools
	if (end_index < total_tools) {
		r_strbuf_appendf (sb, ",\"nextCursor\":\"%d\"", end_index);
	}

	r_strbuf_appendf (sb, "}");
	return r_strbuf_drain (sb);
}

static char *handle_call_tool(RJson *params) {
	const char *tool_name = r_json_get_str (params, "name");

	if (!tool_name) {
		return create_error_response (-32602, "Missing required parameter: name", NULL, NULL);
	}

	RJson *tool_args = (RJson *)r_json_get (params, "arguments");

	// Handle openFile tool
	if (!strcmp (tool_name, "openFile")) {
		const char *filepath = r_json_get_str (tool_args, "filePath");
		if (!filepath) {
			return create_error_response (-32602, "Missing required parameter: filePath", NULL, NULL);
		}

		bool success = r2_open_file (filepath);
		return create_tool_text_response (success ? "File opened successfully." : "Failed to open file.");
	}

	// Handle listMethods tool
	if (!strcmp (tool_name, "listMethods")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		const char *classname = r_json_get_str (tool_args, "classname");
		if (!classname) {
			return create_tool_text_response ("Missing classname parameter");
		}
		char *cmd = r_str_newf ("'ic %s", classname);
		char *res = r2_cmd (cmd);
		free (cmd);
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listClasses tool
	if (!strcmp (tool_name, "listClasses")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		const char *filter = r_json_get_str (tool_args, "filter");
		char *res = r2_cmd ("icqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			RStrBuf *sb = r_strbuf_new ("");
			RList *strings = r_str_split_list (res, "\n", 0);
			RListIter *iter;
			const char *str;
			RRegex rx;
			int re_flags = r_regex_flags ("e");
			bool ok = r_regex_init (&rx, filter, re_flags);
			if (ok) {
				r_list_foreach (strings, iter, str) {
					if (r_regex_exec (&rx, str, 0, 0, 0) == 0) {
						r_strbuf_appendf (sb, "%s\n", str);
					}
				}
				r_regex_fini (&rx);
			} else {
				R_LOG_ERROR ("Invalid regex: %s", filter);
			}
			free (res);
			res = r_strbuf_drain (sb);
		}
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listDecompilers tool
	if (!strcmp (tool_name, "listDecompilers")) {
		char *res = r2_cmd ("e cmd.pdc=?");
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listFunctions tool
	if (!strcmp (tool_name, "listFunctions")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		char *res = r2_cmd ("afl,addr/cols/name");
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listImports tool
	if (!strcmp (tool_name, "listImports")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		char *res = r2_cmd ("iiq");
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listSymbols tool
	if (!strcmp (tool_name, "listSymbols")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		char *res = r_core_cmd_str (r_core, "isq~!func.,!imp.");
		// TODO: remove imports and func
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listEntrypoints tool
	if (!strcmp (tool_name, "listEntrypoints")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		char *res = r_core_cmd_str (r_core, "ies");
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle listLibraries tool
	if (!strcmp (tool_name, "listLibraries")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}
		char *res = r_core_cmd_str (r_core, "ilq");
		char *o = create_tool_text_response (res);
		free (res);
		return o;
	}

	// Handle closeFile tool
	if (!strcmp (tool_name, "closeFile")) {
		if (!file_opened) {
			return create_tool_text_response ("No file was open.");
		}

		char filepath_copy[1024];
		strncpy (filepath_copy, current_file, sizeof (filepath_copy) - 1);
		if (r_core) {
			r_core_cmd0 (r_core, "o-*");
			file_opened = false;
			memset (current_file, 0, sizeof (current_file));
		}

		return create_tool_text_response ("File closed successfully.");
	}

#if 0
	// Handle runCommand tool
	if (!strcmp (tool_name, "runCommand")) {
		if (!r_core || !file_opened) {
			return strdup ("Error: No file is open");
		}
		const char *command = r_json_get_str (tool_args, "command");
		if (!command) {
			return create_error_response (-32602, "Missing required parameter: command", NULL, NULL);
		}

		char *result = r2_cmd (command);
		char *response = create_tool_text_response (result);
		free (result);
		return response;
	}
#endif

	// Handle listStrings tool
	if (!strcmp (tool_name, "listStrings")) {
		const char *filter = r_json_get_str (tool_args, "filter");

		char *result = r2_cmd ("izqq");
		if (R_STR_ISNOTEMPTY (filter)) {
			RStrBuf *sb = r_strbuf_new ("");
			RList *strings = r_str_split_list (result, "\n", 0);
			RListIter *iter;
			const char *str;
			RRegex rx;
			int re_flags = r_regex_flags ("e");
			bool ok = r_regex_init (&rx, filter, re_flags);
			if (ok) {
				r_list_foreach (strings, iter, str) {
					if (r_regex_exec (&rx, str, 0, 0, 0) == 0) {
						r_strbuf_appendf (sb, "%s\n", str);
					}
				}
				r_regex_fini (&rx);
			} else {
				R_LOG_ERROR ("Invalid regex: %s", filter);
			}
			free (result);
			result = r_strbuf_drain (sb);
		}
		char *response = create_tool_text_response (result);
		free (result);
		return response;
	}

	// Handle analyze tool
	if (!strcmp (tool_name, "analyze")) {
		const int level = r_json_get_num (tool_args, "level");
		r2_analyze (level);
		char *result = r2_cmd ("aflc");
		char *text = format_string ("Analysis completed with level %d.\n\nfound %d functions", level, atoi (result));
		char *response = create_tool_text_response (text);
		free (result);
		free (text);
		return response;
	}

	// Handle disassemble tool
	if (!strcmp (tool_name, "disassemble")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}

		// Use const_cast pattern
		RJson *num_instr_json = (RJson *)r_json_get (tool_args, "numInstructions");
		int num_instructions = 10;
		if (num_instr_json && num_instr_json->type == R_JSON_INTEGER) {
			num_instructions = (int)num_instr_json->num.u_value;
		}

		char *cmd = r_str_newf ("'@%s'pd %d", address, num_instructions);
		char *disasm = r2_cmd (cmd);
		free (cmd);
		char *response = create_tool_text_response (disasm);
		free (disasm);
		return response;
	}

	// Handle useDecompiler tool
	if (!strcmp (tool_name, "useDecompiler")) {
		const char *deco = r_json_get_str (tool_args, "useDecompiler");
		if (!deco) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *decompilersAvailable = r_core_cmd_str (r_core, "e cmd.pdc=?");
		const char *response = "ok";
		if (strstr (deco, "ghidra")) {
			if (strstr (decompilersAvailable, "pdg")) {
				r_core_cmd0 (r_core, "-e cmd.pdc=pdg");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "decai")) {
			if (strstr (decompilersAvailable, "decai")) {
				r_core_cmd0 (r_core, "-e cmd.pdc=decai -d");
			} else {
				response = "This decompiler is not available";
			}
		} else if (strstr (deco, "r2dec")) {
			if (strstr (decompilersAvailable, "pdd")) {
				r_core_cmd0 (r_core, "-e cmd.pdc=pdd");
			} else {
				response = "This decompiler is not available";
			}
		} else {
			response = "Unknown decompiler";
		}
		return create_tool_text_response (response);
	}

	// Handle xrefsTo tool
	if (!strcmp (tool_name, "xrefsTo")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'axt", address);
		char *disasm = r2_cmd (cmd);
		char *response = create_tool_text_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	// Handle disassembleFunction tool
	if (!strcmp (tool_name, "disassembleFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'pdf", address);
		char *disasm = r2_cmd (cmd);
		char *response = create_tool_text_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	// Handle renameFunction tool
	if (!strcmp (tool_name, "renameFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		const char *name = r_json_get_str (tool_args, "name");
		if (!name) {
			return create_error_response (-32602, "Missing required parameter: name", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'afn %s", address, name);
		r_core_cmd0 (r_core, cmd);
		return create_tool_text_response ("ok");
	}

	// Handle decompileFunction tool
	if (!strcmp (tool_name, "decompileFunction")) {
		const char *address = r_json_get_str (tool_args, "address");
		if (!address) {
			return create_error_response (-32602, "Missing required parameter: address", NULL, NULL);
		}
		char *cmd = r_str_newf ("'@%s'pdc", address);
		char *disasm = r2_cmd (cmd);
		char *response = create_tool_text_response (disasm);
		free (cmd);
		free (disasm);
		return response;
	}

	return create_error_response (-32602, format_string ("Unknown tool: %s", tool_name), NULL, NULL);
}

// Added back the direct_mode_loop implementation
static void process_mcp_message(const char *msg) {
	r2mcp_log ("<<<");
	r2mcp_log (msg);
	RJson *request = r_json_parse ((char *)msg);
	if (!request) {
		R_LOG_ERROR ("Invalid JSON");
		return;
	}

	const char *method = r_json_get_str (request, "method");
	RJson *params = (RJson *)r_json_get (request, "params");
	RJson *id_json = (RJson *)r_json_get (request, "id");

	if (!method) {
		R_LOG_INFO (">>> %s", msg);
		R_LOG_ERROR ("Invalid JSON-RPC message: missing method");
		r_json_free (request);
		return;
	}

	if (id_json) {
		const char *id = NULL;
		char id_buf[32] = { 0 };
		if (id_json->type == R_JSON_STRING) {
			id = id_json->str_value;
		} else if (id_json->type == R_JSON_INTEGER) {
			snprintf (id_buf, sizeof (id_buf), "%lld", (long long)id_json->num.u_value);
			id = id_buf;
		}

		char *response = handle_mcp_request (method, params, id);
		if (response) {
			// Add a newline at the end of the response
			char *formatted_response = r_str_newf ("%s\n", response);

			// Write directly to stdout and flush immediately
			write (STDOUT_FILENO, formatted_response, strlen (formatted_response));
			fsync (STDOUT_FILENO);
			fflush (stdout);

			r2mcp_log (">>>");
			r2mcp_log (formatted_response);

			free (formatted_response);
			free (response);
		}
	} else {
		// Handle notification - we now properly handle notifications/initialized
		if (!strcmp (method, "notifications/initialized")) {
			r2mcp_log ("Received initialized notification");
		} else {
			r2mcp_log ("Ignoring notification");
		}
	}

	r_json_free (request);
}

// Set buffering modes for stdin/stdout
static void set_nonblocking_io(bool nonblocking) {
	// Set stdin/stdout to blocking or non-blocking mode
	int flags = fcntl (STDIN_FILENO, F_GETFL, 0);
	if (nonblocking) {
		fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	} else {
		fcntl (STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
	}

	// Set stdout to line buffered mode
	setvbuf (stdout, NULL, _IOLBF, 0);
}

// Patch for direct_mode_loop function
static void direct_mode_loop(void) {
    r2mcp_log("Starting MCP direct mode (stdin/stdout)");

    // Send an initial greeting to mcpo to start the conversation
    // This is crucial - mcpo might be waiting for the program to send something first
    const char *greeting = "{\"jsonrpc\":\"2.0\",\"method\":\"greeting\",\"params\":{\"version\":\"" LATEST_PROTOCOL_VERSION "\"}}\n";
    write(STDOUT_FILENO, greeting, strlen(greeting));
    fsync(STDOUT_FILENO);
    r2mcp_log("Sent initial greeting");

    // Use consistent unbuffered mode for stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    // Use non-blocking IO with timeout handling
    set_nonblocking_io(true);

    ReadBuffer *buffer = read_buffer_new();
    char chunk[READ_CHUNK_SIZE];

    // Set up timeout handling
    fd_set read_fds;
    struct timeval tv;

    while (running) {
        // Set up select with timeout
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        // 5 second timeout
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int select_result = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &tv);

        if (select_result == -1) {
            // Error in select
            if (errno != EINTR) {
                r2mcp_log("Select error");
                break;
            }
            continue;
        } else if (select_result == 0) {
            // Timeout - send a ping to keep the connection alive
            const char *ping = "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":\"keepalive\"}\n";
            write(STDOUT_FILENO, ping, strlen(ping));
            fsync(STDOUT_FILENO);
            r2mcp_log("Sent keepalive ping");
            continue;
        }

        // Data is available to read
        ssize_t bytes_read = read(STDIN_FILENO, chunk, sizeof(chunk) - 1);

        if (bytes_read > 0) {
            // Ensure null termination
            chunk[bytes_read] = '\0';
            r2mcp_log("Read data from stdin");

            // Debug: Log the raw input
            r2mcp_log("Raw input:");
            r2mcp_log(chunk);

            // Append to our buffer
            read_buffer_append(buffer, chunk, bytes_read);

            // Process any complete messages in the buffer
            char *msg;
            while ((msg = read_buffer_get_message(buffer)) != NULL) {
                r2mcp_log("Processing complete message");
                process_mcp_message(msg);
                free(msg);
            }
        } else if (bytes_read == 0) {
            // EOF - stdin closed
            r2mcp_log("End of input stream - exiting");
            break;
        } else {
            // Error
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                r2mcp_log("Read error");
                break;
            }
            // For EAGAIN/EWOULDBLOCK, just continue the loop
        }
    }

    read_buffer_free(buffer);
    r2mcp_log("Direct mode loop terminated");
}

// Patch for main function
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    // Enable logging right away
    r2mcp_log("r2mcp starting");

    // Set up signal handlers
    struct sigaction sa = { 0 };
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    r2mcp_log("Signal handlers installed");

    // Initialize r2 right away
    if (!init_r2()) {
        R_LOG_ERROR("Failed to initialize radare2");
        r2mcp_log("Failed to initialize radare2");
        return 1;
    }

    r2mcp_log("r2 initialized");

    // Force direct mode if running with mcpo
    char *mcpo_env = getenv("MCPO_ENABLED");
    if (mcpo_env != NULL) {
        r2mcp_log("MCPO environment detected, forcing direct mode");
        is_direct_mode = true;
    } else {
        // Check stdin
        if (!isatty(STDIN_FILENO)) {
            r2mcp_log("stdin is not a TTY, using direct mode");
            is_direct_mode = true;
        } else {
            r2mcp_log("stdin is a TTY");
            // Check command line args for direct mode
            for (int i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "--direct") || !strcmp(argv[i], "-d")) {
                    r2mcp_log("Direct mode requested via command line");
                    is_direct_mode = true;
                    break;
                }
            }
        }
    }

    // Always run in direct mode for now
    is_direct_mode = true;
    r2mcp_log("Starting direct mode loop");
    direct_mode_loop();

    r2mcp_log("Cleaning up r2");
    cleanup_r2();
    r2mcp_log("r2mcp exiting");
    return 0;
}

// Add a helper function to read a message with timeout
static char *read_buffer_get_message_timeout(ReadBuffer *buf, int timeout_sec) {
    time_t start_time = time(NULL);

    while (1) {
        // Check if we have a complete message
        char *msg = read_buffer_get_message(buf);
        if (msg) {
            return msg;
        }

        // Check for timeout
        if (difftime(time(NULL), start_time) > timeout_sec) {
            r2mcp_log("Timeout waiting for complete message");
            return NULL;
        }

        // Read more data
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        // Short timeout for polling
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int select_result = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &tv);

        if (select_result <= 0) {
            continue;  // Try again or timeout will eventually trigger
        }

        char chunk[READ_CHUNK_SIZE];
        ssize_t bytes_read = read(STDIN_FILENO, chunk, sizeof(chunk) - 1);

        if (bytes_read <= 0) {
            if (bytes_read == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                // EOF or error
                return NULL;
            }
            continue;
        }

        // Append the data and try again
        read_buffer_append(buf, chunk, bytes_read);
    }
}

