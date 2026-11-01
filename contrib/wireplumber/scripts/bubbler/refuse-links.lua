-- bubbler's audio policy: the links WirePlumber may not make for a
-- sandbox, the levels it may not save of one, and the ports, links and
-- video streams it may not see.
--
-- Install as bubbler/refuse-links.lua in one of
--   /usr/share/wireplumber/scripts/
--   $XDG_DATA_HOME/wireplumber/scripts/
-- beside 50-bubbler.conf, which is what loads it.
--
-- Of a bubbler sandbox's nodes only its audio streams are linked, to
-- device nodes and to its own; a capture stream only to a node with
-- `Audio/Source` anywhere in the class or an `Audio/Duplex` one, and only
-- where the instance was granted `microphone`; and the sandbox links
-- nothing itself.
--
-- Under the device grant (`devices` in its grant) a sandbox's nodes that
-- are no stream are devices like the host's: WirePlumber may link another
-- client's stream to them and make one a default. Into such a device flows
-- only a playback stream; a capture stream records from it as from a host
-- device. Every factory but `client-node` stays hidden from it all the
-- same, so its devices are nodes it runs itself, carrying its client id.
-- A node of such a sandbox that is marked a smart filter (`filter.smart`)
-- or shares a `node.name`, `object.path` or `node.nick` with another
-- device keeps no session item all the same.
--
-- A link with a sandbox's node at either end is destroyed when
-- WirePlumber sees it, unless WirePlumber made it and it is one the
-- hooks above would have let it make; one drawn in a patchbay is
-- destroyed. Under the `capturable` grant a host program's own live link
-- from a playback stream to a node of no sandbox is kept too.
--
-- The policy states its revision in the metadata `bubbler-policy`, key
-- `revision` on subject 0, which no sandbox can see: bubbler reads it to
-- tell a WirePlumber still running an older policy.

local lutils = require ("linking-utils")
local cutils = require ("common-utils")
local log = Log.open_topic ("s-linking")

local BUBBLER_ENGINE = "org.bubbler"

-- Raised whenever what this policy makes WirePlumber do changes; bubbler
-- expects the revision it ships with and reads it from this line.
local POLICY_REVISION = 8

local EPERM = -1

-- The one media class a sandbox's stream may have in each direction:
-- what the audio grant covers, and all the hooks below link.
local AUDIO_STREAM_CLASS = {
  output = "Stream/Output/Audio",
  input = "Stream/Input/Audio",
}

local function lookup (source, kind, id)
  return source:call ("get-object-manager", kind):lookup {
    Constraint { "bound-id", "=", id, type = "gobject" },
  }
end

local function bubbler_client (source, client_id)
  if not client_id then
    return nil
  end
  local client = lookup (source, "client", client_id)
  if client and client.properties ["pipewire.sec.engine"] == BUBBLER_ENGINE then
    return client
  end
  return nil
end

-- The grant is a comma-separated list of words, and no word may match
-- inside another.
local function granted (client, word)
  local grant = client.properties ["pipewire.sec.bubbler.audio"] or ""
  return ("," .. grant .. ","):find ("," .. word .. ",", 1, true) ~= nil
end

local function offers_devices (client)
  return granted (client, "devices")
end

-- A sink, source or filter of a sandbox without the device grant keeps no
-- session item, so a target meets one only when it was itemised before
-- WirePlumber knew its client and has not been swept yet: this is the
-- backstop that keeps a host stream off it in that window. A device of a
-- sandbox with the device grant is a device like the host's; its streams
-- are still its own.
local function foreign_sandbox_node (source, si_props, target_props)
  local owner = bubbler_client (source, target_props ["client.id"])
  if not owner then
    return false
  end
  if target_props ["item.node.type"] == "stream" then
    return target_props ["client.id"] ~= si_props ["client.id"]
  end
  return not offers_devices (owner)
end

-- Whether a stream can record from the node: the classes 50-bubbler.conf
-- hides without the microphone grant, `Audio/Source` anywhere in the class
-- as its unanchored `~Audio/Source.*` matches, and `Audio/Duplex`.
local function capture_capable (node_props)
  local class = node_props ["media.class"] or ""
  return class:find ("Audio/Source", 1, true) ~= nil or class == "Audio/Duplex"
end

-- Whether the stream would hold its target for itself: asked for it
-- exclusively, or either end able to take encoded audio only, which is
-- passed through unmixed.
local function holds_its_target (si_props, target_props)
  return cutils.parseBool (si_props ["node.exclusive"]) or
      cutils.parseBool (si_props ["item.node.encoded-only"]) or
      cutils.parseBool (target_props ["item.node.encoded-only"])
end

local HOLDS_ITS_TARGET =
    "a stream that would hold its target for itself, without the exclusive grant"

local function refusal (si_props, target_props, client)
  if si_props ["media.class"] ~=
      AUDIO_STREAM_CLASS [si_props ["item.node.direction"]] then
    return "a node that is not an audio stream"
  end

  if target_props ["item.node.type"] == "stream" and
      target_props ["client.id"] ~= si_props ["client.id"] then
    return "another client's stream"
  end

  if si_props ["item.node.direction"] == "input" then
    -- A capture stream and a target that is also an input and records
    -- nothing itself: the target is a sink and what would be linked are
    -- its monitor ports.
    if not capture_capable (target_props) then
      return target_props ["item.node.direction"] == "input" and
          "a sink's monitor ports" or "a node that is not a source"
    end

    if not granted (client, "microphone") then
      return "a source, without the microphone grant"
    end
  end

  -- Last, so a stream is told it needs the exclusive grant only where
  -- that grant alone would let it be linked.
  if holds_its_target (si_props, target_props) and
      not granted (client, "exclusive") then
    return HOLDS_ITS_TARGET
  end

  return nil
end

SimpleEventHook {
  name = "bubbler/refuse-links",
  after = "linking/prepare-link",
  before = "linking/link-target",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-target" },
    },
  },
  execute = function (event)
    local source, _, si, si_props, si_flags, target =
        lutils:unwrap_select_target_event (event)

    if not target then
      return
    end

    local target_props = target.properties
    local why
    local client = bubbler_client (source, si_props ["client.id"])
    if foreign_sandbox_node (source, si_props, target_props) then
      why = "a sandbox's node that is not the stream's own"
    elseif not client then
      return
    else
      why = refusal (si_props, target_props, client)
    end

    if why then
      log:info (si, string.format ("refusing %s (client %s) a link to %s: %s",
          tostring (si_props ["node.name"]),
          tostring (si_props ["client.id"]),
          tostring (target_props ["node.name"]),
          why))
      event:set_data ("target", nil)
      -- Told, as stock tells a stream it turns away from a held target;
      -- the other refusals leave a stream that may yet be linked elsewhere.
      -- Once per session item, kept in its flags as link-target keeps
      -- `was_handled`: every rescan selects the stream again.
      if why == HOLDS_ITS_TARGET and not si_flags.told_it_holds_its_target then
        si_flags.told_it_holds_its_target = true
        log:info (si, "telling the client of " ..
            tostring (si_props ["node.name"]) .. " it needs the exclusive grant")
        lutils.sendClientError (event, si:get_associated_proxy ("node"),
            EPERM, "bubbler: holding a device for one stream needs the " ..
            "exclusive grant")
      end
    elseif not granted (client, "exclusive") then
      -- link-target marks a passthrough link, which holds the target as
      -- an exclusive one does (lib/linking-utils.lua isLinked).
      si_flags.can_passthrough = false
    end
  end
}:register ()

-- The keys a stock lookup by name matches a target on:
-- linking/find-defined-target takes a candidate whose `node.name` or
-- `object.path` is the pinned value, and
-- linking/find-media-role-sink-target one whose `node.name`, failing
-- that whose `node.nick`, is the preferred target.
local NAME_KEYS = { "node.name", "object.path", "node.nick" }

local function shares_a_name (props, device)
  for _, key in ipairs (NAME_KEYS) do
    for _, device_key in ipairs (NAME_KEYS) do
      if props [key] ~= nil and props [key] == device [device_key] then
        return true
      end
    end
  end
  return false
end

-- Whether a session item that is no stream — a device or a filter — of
-- the host's, or of a sandbox whose own devices stand beside the host's,
-- and not the item of the node `node_id` itself, shares a name with any
-- of `props_list`. A stream pinned to that name would otherwise be aimed
-- at whichever of the two a lookup meets first, streams included. A host
-- stream of the same name is left alone: two instances of one
-- application commonly share one.
local function shadows_a_device (source, node_id, props_list)
  for si in source:call ("get-object-manager", "session-item"):iterate {
      type = "SiLinkable" } do
    local device = si.properties
    local owner = bubbler_client (source, device ["client.id"])
    if not (device ["media.class"] or ""):find ("^Stream/") and
        (not owner or offers_devices (owner)) and
        device ["node.id"] ~= node_id then
      for _, props in ipairs (props_list) do
        if shares_a_name (props, device) then
          return true
        end
      end
    end
  end
  return false
end

-- The `filters` metadata, the other place a node is marked smart, is
-- hidden from every sandbox.
local function smart_filter (props_list)
  for _, props in ipairs (props_list) do
    if cutils.parseBool (props ["filter.smart"]) then
      return true
    end
  end
  return false
end

-- `item_props`, where the node has a session item, are what the finders
-- read: frozen at the item's creation. A stream carries a link group only
-- as one half of a filter.
local function kept_from_the_session (source, node, item_props)
  local node_props = node.properties
  local client = bubbler_client (source, node_props ["client.id"])
  if not client then
    return false
  end
  local props_list = { node_props, item_props }
  local named_after_a_device = function ()
    return shadows_a_device (source, tostring (node ["bound-id"]), props_list)
  end
  if offers_devices (client) then
    return smart_filter (props_list) or named_after_a_device ()
  end
  local class = node_props ["media.class"]
  return (class ~= AUDIO_STREAM_CLASS.output and
      class ~= AUDIO_STREAM_CLASS.input) or
      node_props ["node.link-group"] ~= nil or
      named_after_a_device ()
end

-- Every finder, the smart-filter chain (lib/filter-utils.lua) and the
-- default-node rescan search session items alone. node/create-item is
-- the only maker of a node's session item.
SimpleEventHook {
  name = "bubbler/no-device-from-a-sandbox",
  after = "bubbler/destroy-refused-link-once-its-ends-are-known",
  before = "node/create-item",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "node-added" },
    },
  },
  execute = function (event)
    local node = event:get_subject ()
    if not kept_from_the_session (event:get_source (), node) then
      return
    end
    log:info (node, string.format ("%s (client %s, %s) is no device of " ..
        "the session: not a plain audio stream of a sandbox, a smart " ..
        "filter, or named after a device",
        tostring (node.properties ["node.name"]),
        tostring (node.properties ["client.id"]),
        tostring (node.properties ["media.class"])))
    event:stop_processing ()
  end
}:register ()

-- The same, for a node that has a session item all the same: one that
-- reached node-added before WirePlumber knew its client (after a
-- WirePlumber restart the node is already in the graph), and a stream
-- that has since changed its own properties into a filter's (a client
-- may, and no event follows), or a stream older than the host device it
-- is named after (a headset that reconnects). Default-node selection and
-- the filter chain are rebuilt only in these two rescans and read the
-- node's current properties there (default-nodes/rescan.lua,
-- lib/filter-utils.lua rescanFilters), so removing the item first keeps
-- the node out of both.
SimpleEventHook {
  name = "bubbler/no-device-from-a-sandbox-on-rescan",
  before = { "default-nodes/rescan", "lib/filter-utils/rescan",
      "linking/mpris-pause-disable-rescan", "linking/rescan" },
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "rescan-for-default-nodes" },
    },
    EventInterest {
      Constraint { "event.type", "=", "rescan-for-linking" },
    },
  },
  execute = function (event)
    local source = event:get_source ()
    local kept = {}
    for si in source:call ("get-object-manager", "session-item"):iterate {
        type = "SiLinkable" } do
      local node = si:get_associated_proxy ("node")
      if node and kept_from_the_session (source, node, si.properties) then
        table.insert (kept, si)
      end
    end
    for _, si in ipairs (kept) do
      log:info (si, string.format ("removing the session item of %s " ..
          "(client %s): not a plain audio stream of a sandbox, a smart " ..
          "filter, or named after a device",
          tostring (si.properties ["node.name"]),
          tostring (si.properties ["client.id"])))
      si:remove ()
    end
  end
}:register ()

-- A `client.id` WirePlumber does not know yet counts as a sandbox's, so a
-- restart fails closed.
local function may_belong_to_a_sandbox (source, node_props)
  local client_id = node_props ["client.id"]
  if not client_id then
    return false
  end
  return lookup (source, "client", client_id) == nil or
      bubbler_client (source, client_id) ~= nil
end

-- Stock keys saved levels by names the client chooses (formKey in
-- node/state-stream.lua); the only hook on it in WirePlumber 0.5.18.
SimpleEventHook {
  name = "bubbler/no-saved-state-from-a-sandbox",
  before = "node/store-stream-props",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "node-params-changed" },
      Constraint { "event.subject.param-id", "=", "Props" },
    },
  },
  execute = function (event)
    local node = event:get_subject ()
    if not may_belong_to_a_sandbox (event:get_source (), node.properties) then
      return
    end
    log:debug (node, string.format ("not saving the levels of %s (client %s)",
        tostring (node.properties ["node.name"]),
        tostring (node.properties ["client.id"])))
    event:stop_processing ()
  end
}:register ()

-- A sandbox keeps `client-node`, which is what a stream is made through
-- (pipewire-pulse's included), and loses the rest: `link-factory`,
-- through which it would link what it can see itself, and every factory
-- that makes a node or other object the daemon owns (`adapter`,
-- `spa-node-factory`, `metadata`, ...) — such a node, made with
-- `object.linger`, carries no `client.id` (PipeWire 1.6.9,
-- module-adapter.c), so nothing below could tell it was a sandbox's.
-- The permission managers cannot express that — measured: their `rules`
-- are not applied to factory globals — so it is set on the client below.
local STREAM_FACTORY = "client-node"
local factories = ObjectManager {
  Interest { type = "factory" },
}

-- Before the standard event source is loaded no access has been decided,
-- and bubbler/hide-factories will find the factory listed here.
factories:connect ("object-added", function (_, factory)
  local source = Plugin.find ("standard-event-source")
  if not source or factory.properties ["factory.name"] == STREAM_FACTORY then
    return
  end
  for client in source:call ("get-object-manager", "client"):iterate () do
    if client.properties ["pipewire.sec.engine"] == BUBBLER_ENGINE then
      client:update_permissions { [factory ["bound-id"]] = "-" }
      log:info (client, string.format ("%s hidden from %s as it appeared",
          tostring (factory.properties ["factory.name"]),
          tostring (client.properties ["pipewire.sec.app-id"])))
    end
  end
end)
factories:activate ()

-- Before the permission manager attaches, not after: the attach is the
-- update that lets the client's held requests through, and a hook after
-- it runs one main-loop turn later — measured on WirePlumber 0.5.18,
-- long enough for a fresh connection to create a link with the factory
-- still readable. The explicit entries set here survive the attach,
-- which changes the default and the objects its rules match, never a
-- factory.
SimpleEventHook {
  name = "bubbler/hide-factories",
  before = "client/apply-access",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-access" },
    },
  },
  execute = function (event)
    local client = event:get_subject ()
    if client.properties ["pipewire.sec.engine"] ~= BUBBLER_ENGINE then
      return
    end
    -- No permission at all, not read-only: measured on PipeWire 1.6.8,
    -- the core asks only for read on the factory global before creating
    -- the object, so a readable factory is a usable one.
    local hidden = {}
    local link_factory = false
    for factory in factories:iterate () do
      local name = factory.properties ["factory.name"]
      if name ~= STREAM_FACTORY then
        hidden [factory ["bound-id"]] = "-"
        link_factory = link_factory or name == "link-factory"
      end
    end
    if not link_factory then
      log:warning (client, "no link factory in the graph: a sandbox that " ..
          "can see two nodes can link them itself")
    end
    client:update_permissions (hidden)
    log:info (client, "every factory but " .. STREAM_FACTORY ..
        " hidden from " .. tostring (client.properties ["pipewire.sec.app-id"]))
  end
}:register ()

-- Ports and links carry no `media.class` for 50-bubbler.conf to match, only
-- a node id, and may arrive before their node (PipeWire 1.6.9).
local nodes = ObjectManager {
  Interest { type = "node" },
}
local ports_and_links = ObjectManager {
  Interest { type = "port" },
  Interest { type = "link" },
}

local function is_sandbox (client)
  return client.properties ["pipewire.sec.engine"] == BUBBLER_ENGINE
end

-- The owner is bubbler's too and carries the instance id the security
-- context set, which no client can; another engine may carry the same id.
local function same_sandbox (client, node_props)
  local instance = client.properties ["pipewire.sec.instance-id"]
  local owner_id = node_props ["client.id"]
  local source = Plugin.find ("standard-event-source")
  if not instance or not owner_id or not source then
    return false
  end
  local owner = lookup (source, "client", owner_id)
  return owner ~= nil and is_sandbox (owner)
    and owner.properties ["pipewire.sec.instance-id"] == instance
end

-- Cameras and capture nodes are hidden by 50-bubbler.conf; a video stream
-- here, as no rule there can tell which sandbox made it.
local function hidden_from (client, node_props)
  local class = node_props ["media.class"] or ""
  if class:find ("Video/", 1, true) then
    return true
  end
  if class:find ("Stream/", 1, true) and class:find ("/Video$") then
    return not same_sandbox (client, node_props)
  end
  return capture_capable (node_props) and not granted (client, "microphone")
end

local function hides_node (client)
  return function (node_id)
    if not node_id then
      return false
    end
    local node = nodes:lookup {
      Constraint { "bound-id", "=", node_id, type = "gobject" },
    }
    return node ~= nil and hidden_from (client, node.properties)
  end
end

local function belongs (object, of_node)
  local props = object.properties
  return of_node (props ["node.id"]) or
      of_node (props ["link.output.node"]) or
      of_node (props ["link.input.node"])
end

local function hidden_of (of_node)
  local hidden
  local function hide (object)
    hidden = hidden or {}
    hidden [object ["bound-id"]] = "-"
  end
  for node in nodes:iterate () do
    if of_node (tostring (node ["bound-id"])) then
      hide (node)
    end
  end
  for object in ports_and_links:iterate () do
    if belongs (object, of_node) then
      hide (object)
    end
  end
  return hidden
end

-- `hidden_for (client)` is the permissions table to apply to a connected
-- sandbox, or false or nil where there is nothing to hide from it.
local function hide_from_connected_sandboxes (hidden_for)
  local source = Plugin.find ("standard-event-source")
  if not source then
    return
  end
  for client in source:call ("get-object-manager", "client"):iterate () do
    local hidden = is_sandbox (client) and hidden_for (client)
    if hidden then
      client:update_permissions (hidden)
    end
  end
end

local function hide_node_from_connected_sandboxes (node)
  local id = tostring (node ["bound-id"])
  hide_from_connected_sandboxes (function (client)
    return hidden_from (client, node.properties) and
        hidden_of (function (node_id) return node_id == id end)
  end)
end

nodes:connect ("object-added", function (_, node)
  hide_node_from_connected_sandboxes (node)
  -- A node's client sets its class and may change it later; the permission
  -- manager does not look at the node again (WirePlumber 0.5.18).
  local class = node.properties ["media.class"]
  node:connect ("notify::properties", function (changed)
    local now = changed.properties ["media.class"]
    if now ~= class then
      class = now
      hide_node_from_connected_sandboxes (changed)
    end
  end)
end)
ports_and_links:connect ("object-added", function (_, object)
  hide_from_connected_sandboxes (function (client)
    return belongs (object, hides_node (client)) and
        { [object ["bound-id"]] = "-" }
  end)
end)
nodes:activate ()
ports_and_links:activate ()

SimpleEventHook {
  name = "bubbler/hide-capture-ports-and-links",
  before = "client/apply-access",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-access" },
    },
  },
  execute = function (event)
    local client = event:get_subject ()
    if not is_sandbox (client) then
      return
    end
    local hidden = hidden_of (hides_node (client))
    if hidden then
      client:update_permissions (hidden)
    end
  end
}:register ()

-- Whether a WirePlumber instance made `link` — any instance, not only
-- this one: the hook runs in every instance of a split setup, and each
-- would otherwise destroy the links the others make. The daemon writes
-- the creator's id into `client.id` only on a link that does not linger
-- (PipeWire 1.6.9, module-link-factory.c); a lingering link carries
-- whatever its creator sent, so there the id proves nothing. Every
-- instance's client carries `wireplumber.daemon`, but so may any client
-- (impl-client.c refuses a client only `pipewire.*` keys), so it counts
-- only outside every security context: a context's client has
-- `pipewire.sec.engine` from the context's socket before it says
-- anything (module-protocol-native.c) and can neither change nor drop
-- it. A restricted client outside every context can wear the marker
-- too; confining those is not this policy's.
local function made_by_wireplumber (source, link)
  local linger = link.properties ["object.linger"]
  local creator = link.properties ["client.id"]
  if linger == "true" or linger == "1" or not creator then
    return false
  end
  local client = lookup (source, "client", creator)
  return client ~= nil and
      client.properties ["wireplumber.daemon"] == "true" and
      client.properties ["pipewire.sec.engine"] == nil
end

local function bubbler_node (source, node_id)
  local node = lookup (source, "node", node_id)
  if node and bubbler_client (source, node.properties ["client.id"]) then
    return node.properties
  end
  return nil
end

local function may_record_from (source, capture_props, output_props)
  local client = bubbler_client (source, capture_props ["client.id"])
  return client ~= nil and capture_capable (output_props) and
      granted (client, "microphone")
end

-- Whether `link`, from `sandbox_output` to `sandbox_input`, is one the
-- first line would have let WirePlumber make: a context's own audio
-- streams in their own direction, and where only one end is a sandbox's,
-- the other end what `refusal` allows it — a playback stream into
-- anything but another client's stream, a capture stream from a source
-- and only with the microphone grant. WirePlumber links a stream before
-- it knows the stream's client after a restart, and then this is the
-- only check.
local function own_stream_link (source, link, sandbox_output, sandbox_input)
  if sandbox_output and
      sandbox_output ["media.class"] ~= AUDIO_STREAM_CLASS.output then
    return false
  end
  if sandbox_input and
      sandbox_input ["media.class"] ~= AUDIO_STREAM_CLASS.input then
    return false
  end
  if sandbox_output and sandbox_input then
    return sandbox_output ["client.id"] == sandbox_input ["client.id"]
  end
  if sandbox_output then
    local host = lookup (source, "node", link.properties ["link.input.node"])
    return host ~= nil and
        (host.properties ["media.class"] or ""):find ("^Stream/") == nil
  end
  local host = lookup (source, "node", link.properties ["link.output.node"])
  return host ~= nil and may_record_from (source, sandbox_input, host.properties)
end

local function offered_device (source, props)
  local client = bubbler_client (source, props ["client.id"])
  return client ~= nil and offers_devices (client) and
      (props ["media.class"] or ""):find ("^Stream/") == nil
end

-- Whether a link between `output` and `input`, one of them a device a
-- sandbox offers, is one WirePlumber makes for a stream aimed at that
-- device: a playback stream into it, or a capture stream from it, where a
-- sandbox's capture stream needs a source and the microphone grant as it
-- does from a host device. Nothing else flows into an offered device: not
-- a source, not a sink's monitor, since the sandbox hears what does.
local function offered_device_link (source, output, input)
  if offered_device (source, input) then
    return output ["media.class"] == AUDIO_STREAM_CLASS.output
  end
  if input ["media.class"] ~= AUDIO_STREAM_CLASS.input then
    return false
  end
  return bubbler_client (source, input ["client.id"]) == nil or
      may_record_from (source, input, output)
end

-- A client can name another as a link's creator only on a link that
-- lingers, and cannot set its own access (see `made_by_wireplumber`).
local function captured_by_a_host_program (source, link, output, input)
  if not output or input or
      output ["media.class"] ~= AUDIO_STREAM_CLASS.output or
      not lookup (source, "node", link.properties ["link.input.node"]) then
    return false
  end
  local owner = bubbler_client (source, output ["client.id"])
  if not owner or not granted (owner, "capturable") then
    return false
  end
  local linger = link.properties ["object.linger"]
  local creator = link.properties ["client.id"]
  if linger == "true" or linger == "1" or not creator then
    return false
  end
  local client = lookup (source, "client", creator)
  return client ~= nil and
      client.properties ["pipewire.sec.engine"] == nil and
      client.properties ["pipewire.access"] == "unrestricted"
end

-- The `object.serial` of every link already asked to go, which a later
-- check would otherwise ask again. Serials are never reused.
local destroying = {}

-- By the link's ends, not its creator: a link a sandbox won before its
-- factory was hidden lingers with no creator on it at all, and any other
-- client's link to or from a sandbox is one the policy above would have
-- refused. WirePlumber's own links are kept only where they are the
-- ones the policy permits.
local function destroy_if_refused (source, link)
  local serial = link.properties ["object.serial"]
  if destroying [serial] then
    return
  end
  local output = bubbler_node (source, link.properties ["link.output.node"])
  local input = bubbler_node (source, link.properties ["link.input.node"])
  if not output and not input then
    return
  end
  if captured_by_a_host_program (source, link, output, input) then
    return
  end
  local allowed
  if (output and offered_device (source, output)) or
      (input and offered_device (source, input)) then
    local output_node = lookup (source, "node", link.properties ["link.output.node"])
    local input_node = lookup (source, "node", link.properties ["link.input.node"])
    allowed = output_node ~= nil and input_node ~= nil and
        offered_device_link (source, output_node.properties,
            input_node.properties)
  else
    allowed = own_stream_link (source, link, output, input)
  end
  if not (made_by_wireplumber (source, link) and allowed) then
    log:warning (link, "destroying a link to a bubbler context " ..
        "that the policy refuses")
    link:request_destroy ()
    if serial then
      destroying [serial] = true
    end
  end
end

SimpleEventHook {
  name = "bubbler/destroy-refused-link",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "link-added" },
    },
  },
  execute = function (event)
    destroy_if_refused (event:get_source (), event:get_subject ())
  end
}:register ()

-- Remove every link WirePlumber made for a stream of the client
-- `client_id` that holds its target: link-target marks it `exclusive` or
-- `passthrough`, and while it stands every later stream is turned away
-- from the target (lib/linking-utils.lua isLinked). Only a link made
-- before WirePlumber knew the client, after a restart, can be one; no
-- rescan undoes it, since prepare-link keeps a stream already linked to
-- its target. The peer and a role-policy priority link are forgotten, as
-- linking/rescan.lua does when it removes a link, so the next rescan
-- reaches the first line again.
local function release_held_targets (source, client_id)
  local items = source:call ("get-object-manager", "session-item")
  local own = {}
  for si in items:iterate { type = "SiLinkable" } do
    if si.properties ["client.id"] == client_id then
      own [si.id] = true
    end
  end
  local held = {}
  for silink in items:iterate { type = "SiLink" } do
    local props = silink.properties
    if own [tonumber (props ["main.item.id"])] and
        (cutils.parseBool (props ["exclusive"]) or
            cutils.parseBool (props ["passthrough"])) then
      table.insert (held, silink)
    end
  end
  for _, silink in ipairs (held) do
    log:info (silink, string.format ("removing a link holding its target " ..
        "for client %s, made before WirePlumber knew it", client_id))
    lutils:get_flags (tonumber (silink.properties ["main.item.id"])).peer_id = nil
    if silink.properties:get_boolean ("is.role.policy.link") then
      lutils.clearPriorityMediaRoleLink (silink)
    end
    silink:remove ()
  end
end

-- At `link-added` the node at an end, or the client that owns it, may
-- not be in WirePlumber's object managers yet, and the link would pass
-- as one with no sandbox at either end. It is decided again when that
-- node or a bubbler client arrives. A bubbler client's arrival also
-- rescans defaults and links, whose first hook removes the session item
-- a node of that client got while the client was not known yet:
-- default-nodes/rescan-trigger rescans on session items, the default
-- metadata and device routes, never on a client.
SimpleEventHook {
  name = "bubbler/destroy-refused-link-once-its-ends-are-known",
  interests = {
    EventInterest {
      Constraint { "event.type", "c", "node-added", "client-added" },
    },
  },
  execute = function (event)
    local source = event:get_source ()
    local subject = event:get_subject ()
    local id = tostring (subject ["bound-id"])
    local is_client = event:get_properties () ["event.type"] == "client-added"
    if is_client then
      if subject.properties ["pipewire.sec.engine"] ~= BUBBLER_ENGINE then
        return
      end
      if not granted (subject, "exclusive") then
        release_held_targets (source, id)
      end
      source:call ("schedule-rescan", "default-nodes")
      source:call ("schedule-rescan", "linking")
    end

    local function ends_here (node_id)
      if not is_client then
        return node_id == id
      end
      local node = lookup (source, "node", node_id)
      return node ~= nil and node.properties ["client.id"] == id
    end

    local links = source:call ("get-object-manager", "link")
    for link in links:iterate () do
      if ends_here (link.properties ["link.output.node"]) or
          ends_here (link.properties ["link.input.node"]) then
        destroy_if_refused (source, link)
      end
    end
  end
}:register ()

-- A global, as stock metadata.lua keeps its own: a script's globals live
-- as long as the script, and a local nothing refers to would be collected
-- and the metadata destroyed with it.
policy_revision_metadata = ImplMetadata ("bubbler-policy")
policy_revision_metadata:activate (Features.ALL, function (m, e)
  if e then
    log:warning ("bubbler-policy metadata not activated: " .. tostring (e))
    return
  end
  m:set (0, "revision", "Spa:Int", tostring (POLICY_REVISION))
end)
