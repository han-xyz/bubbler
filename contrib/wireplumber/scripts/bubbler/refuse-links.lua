-- bubbler's audio policy: the links WirePlumber may not make for a
-- sandbox.
--
-- Install as bubbler/refuse-links.lua in one of
--   /usr/share/wireplumber/scripts/
--   $XDG_DATA_HOME/wireplumber/scripts/
-- beside 50-bubbler.conf, which is what loads it.
--
-- The permission managers in 50-bubbler.conf say what a sandbox may
-- see. Three things they cannot say, because each is a fact about a
-- link's two ends and a permission is a fact about one object:
--
--   * A sink's monitor ports carry everything the session is playing
--     and are reached through the sink's own read permission, so a
--     capture stream asking for `stream.capture.sink` records every
--     other application. Hiding sinks is not an option — that is the
--     grant.
--
--   * Stream nodes are readable because the private pulse server of a
--     `pulseaudio` grant must see the streams it creates, and
--     PW_PERM_L is only consulted for a node the client cannot see
--     ("a link can be made between a node that doesn't have permission
--     to see the other node", pipewire/permission.h), so a readable
--     stream is a linkable one: measured on PipeWire 1.6.8, a capture
--     stream aimed at another client's playback stream is linked to it
--     and records it.
--
--   * A client can make a link itself, and the daemon lets any client
--     link two nodes it can see (PipeWire 1.6.8,
--     src/pipewire/impl-link.c `check_permission`: read on both nodes
--     for the client creating the link, and the owner of each node must
--     see the other unless the creating client holds PW_PERM_L). A
--     playback sandbox has to see the sink for its own audio to reach
--     it, so no node permission tells "WirePlumber links my stream to
--     the sink" apart from "I link the sink's monitor to my capture
--     stream". What separates them is the link factory: measured on
--     1.6.8, a client that cannot see the `link-factory` global gets
--     ENOENT from the core and makes no link, while WirePlumber goes on
--     linking on its behalf. The permission managers cannot express
--     that — measured: their `rules` are not applied to factory globals
--     — so it is set on the client below.
--
-- So: of a bubbler sandbox's nodes only its audio streams are linked, to
-- device nodes and to its own; a capture stream only to an
-- `Audio/Source*` or `Audio/Duplex` node, and only where the instance
-- was granted `microphone`; and the sandbox links nothing itself.
--
-- A sandbox offers no device: its nodes that are not plain audio streams,
-- and its streams named after a host device, keep no session item, so
-- WirePlumber links no other client's stream to them and makes none of
-- them a default or a filter. WirePlumber links
-- no other client's stream to a sandbox's stream either.
--
-- A link with a sandbox's node at either end is destroyed when
-- WirePlumber sees it, unless WirePlumber made it and it is one the
-- hooks above would have let it make; one drawn in a patchbay is
-- destroyed.

local lutils = require ("linking-utils")
local log = Log.open_topic ("s-linking")

-- The engine name bubbler gives every security context it creates.
local BUBBLER_ENGINE = "org.bubbler"

-- The one media class a sandbox's stream may have in each direction:
-- what the audio grant covers, and all the hooks below link.
local AUDIO_STREAM_CLASS = {
  output = "Stream/Output/Audio",
  input = "Stream/Input/Audio",
}

-- The object of `kind` ("client", "node") whose bound id is `id`, or nil.
local function lookup (source, kind, id)
  return source:call ("get-object-manager", kind):lookup {
    Constraint { "bound-id", "=", id, type = "gobject" },
  }
end

-- The client object `client_id` names, or nil where the graph has no
-- such client (a node whose client is already gone).
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

-- Whether the target is a sandbox's node that is not the stream's own:
-- whoever the stream belongs to, a sink, source or filter a sandbox
-- offers would otherwise take a host stream without the sandbox making
-- any link.
local function foreign_sandbox_node (source, si_props, target_props)
  return bubbler_client (source, target_props ["client.id"]) ~= nil and
      (target_props ["item.node.type"] ~= "stream" or
       target_props ["client.id"] ~= si_props ["client.id"])
end

-- Whether a stream can record from the node: the classes 50-bubbler.conf
-- hides without the microphone grant (its `~Audio/Source.*` is an
-- unanchored match, so it hides at least these).
local function capture_capable (node_props)
  local class = node_props ["media.class"] or ""
  return class:find ("^Audio/Source") ~= nil or class == "Audio/Duplex"
end

-- Why this link may not be made, or nil where it may.
local function refusal (si_props, target_props, grant)
  if si_props ["media.class"] ~=
      AUDIO_STREAM_CLASS [si_props ["item.node.direction"]] then
    return "a node that is not an audio stream"
  end

  if target_props ["item.node.type"] == "stream" and
      target_props ["client.id"] ~= si_props ["client.id"] then
    return "another client's stream"
  end

  if si_props ["item.node.direction"] ~= "input" then
    return nil
  end

  -- A capture stream and a target that is also an input and records
  -- nothing itself: the target is a sink and what would be linked are
  -- its monitor ports.
  if not capture_capable (target_props) then
    return target_props ["item.node.direction"] == "input" and
        "a sink's monitor ports" or "a node that is not a source"
  end

  if not string.find (grant, "microphone", 1, true) then
    return "a source, without the microphone grant"
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
    local source, _, si, si_props, _, target =
        lutils:unwrap_select_target_event (event)

    if not target then
      return
    end

    local target_props = target.properties
    local why
    if foreign_sandbox_node (source, si_props, target_props) then
      why = "a sandbox's node that is not the stream's own"
    else
      local client = bubbler_client (source, si_props ["client.id"])
      if not client then
        return
      end
      why = refusal (si_props, target_props,
          client.properties ["pipewire.sec.bubbler.audio"] or "")
    end

    if why then
      log:info (si, string.format ("refusing %s (client %s) a link to %s: %s",
          tostring (si_props ["node.name"]),
          tostring (si_props ["client.id"]),
          tostring (target_props ["node.name"]),
          why))
      event:set_data ("target", nil)
    end
  end
}:register ()

-- Whether the client's grant lets its own devices stand beside the
-- host's.
local function offers_devices (client)
  local grant = client.properties ["pipewire.sec.bubbler.audio"] or ""
  return ("," .. grant .. ","):find (",devices,", 1, true) ~= nil
end

-- The keys a stock lookup by name matches a target on:
-- linking/find-defined-target takes a candidate whose `node.name` or
-- `object.path` is the pinned value, and
-- linking/find-media-role-sink-target one whose `node.name`, failing
-- that whose `node.nick`, is the preferred target.
local NAME_KEYS = { "node.name", "object.path", "node.nick" }

-- Whether `props` has a name among `NAME_KEYS` that is also one of the
-- device's.
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
-- shares a name with any of `props_list`. A stream pinned to that name
-- would otherwise be aimed at whichever of the two a lookup meets first,
-- streams included. A host stream of the same name is left alone: two
-- instances of one application commonly share one.
local function shadows_a_device (source, props_list)
  for si in source:call ("get-object-manager", "session-item"):iterate {
      type = "SiLinkable" } do
    local device = si.properties
    local owner = bubbler_client (source, device ["client.id"])
    if not (device ["media.class"] or ""):find ("^Stream/") and
        (not owner or offers_devices (owner)) then
      for _, props in ipairs (props_list) do
        if shares_a_name (props, device) then
          return true
        end
      end
    end
  end
  return false
end

-- Whether a node with these properties, as they stand now, is kept out of
-- the session: a node of a sandbox without the device grant that is not a
-- plain audio stream, or that shares a name with a device.
-- `item_props`, where the node has a session item, are what the finders
-- read: frozen at the item's creation. A stream carries a link group only
-- as one half of a filter.
local function kept_from_the_session (source, node_props, item_props)
  local client = bubbler_client (source, node_props ["client.id"])
  if not client or offers_devices (client) then
    return false
  end
  local class = node_props ["media.class"]
  return (class ~= AUDIO_STREAM_CLASS.output and
      class ~= AUDIO_STREAM_CLASS.input) or
      node_props ["node.link-group"] ~= nil or
      shadows_a_device (source, { node_props, item_props })
end

-- A sandbox offers no device: of its nodes only its plain audio streams
-- become session items. Every finder, the smart-filter chain
-- (lib/filter-utils.lua) and the default-node rescan search session items
-- alone, so a sink, source or filter a sandbox makes is never a target,
-- a filter or a default for anyone; the node stays in the graph,
-- unlinked, and its client gets no error. node/create-item is the only
-- maker of a node's session item.
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
    if not kept_from_the_session (event:get_source (), node.properties) then
      return
    end
    log:info (node, string.format ("%s (client %s, %s) is no device of " ..
        "the session: not a plain audio stream of a sandbox, or named " ..
        "after a host device",
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
      if node and kept_from_the_session (source, node.properties,
          si.properties) then
        table.insert (kept, si)
      end
    end
    for _, si in ipairs (kept) do
      log:info (si, string.format ("removing the session item of %s " ..
          "(client %s): not a plain audio stream of a sandbox, or named " ..
          "after a host device",
          tostring (si.properties ["node.name"]),
          tostring (si.properties ["client.id"])))
      si:remove ()
    end
  end
}:register ()

-- Every factory in the graph. A sandbox keeps `client-node`, which is
-- what a stream is made through (pipewire-pulse's included), and loses
-- the rest: `link-factory`, through which it would link what it can see
-- itself, and every factory that makes a node or other object the daemon
-- owns (`adapter`, `spa-node-factory`, `metadata`, ...) — such a node,
-- made with `object.linger`, carries no `client.id` (PipeWire 1.6.9,
-- module-adapter.c), so nothing below could tell it was a sandbox's.
local STREAM_FACTORY = "client-node"
local factories = ObjectManager {
  Interest { type = "factory" },
}

-- A factory the graph gains after a sandbox's access was decided, or one
-- this object manager had not listed yet when it was, is hidden from
-- every sandbox already connected. Before the standard event source is
-- loaded no access has been decided, and bubbler/hide-factories will
-- find the factory listed here.
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

-- The properties of the node `node_id` names where it belongs to a
-- bubbler context, or nil.
local function bubbler_node (source, node_id)
  local node = lookup (source, "node", node_id)
  if node and bubbler_client (source, node.properties ["client.id"]) then
    return node.properties
  end
  return nil
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
  local client = bubbler_client (source, sandbox_input ["client.id"])
  return host ~= nil and client ~= nil and capture_capable (host.properties) and
      string.find (client.properties ["pipewire.sec.bubbler.audio"] or "",
          "microphone", 1, true) ~= nil
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
  if not (made_by_wireplumber (source, link) and
      own_stream_link (source, link, output, input)) then
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
