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
-- WirePlumber links no other client's stream to a sandbox's node that
-- is not that stream's own, and no such node becomes the session's
-- default; a host stream aimed at one goes where it would go without
-- it, and one pinned to it with `node.dont-fallback` gets no link.
--
-- A link with a sandbox's node at either end is destroyed when
-- WirePlumber sees it, unless WirePlumber made it and it is one the
-- hooks above would have let it make; one drawn in a patchbay is
-- destroyed.

local lutils = require ("linking-utils")
local cutils = require ("common-utils")
local futils = require ("filter-utils")
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

-- The first enabled smart filter of the host's in front of `target`, or
-- of no target at all where `target` is nil, in WirePlumber's chain
-- order: futils.get_filter_from_target's search, passing over a
-- sandbox's filter that put itself first in the chain.
local function host_filter (source, si_props, target)
  local direction = cutils.getTargetDirection (si_props)
  for _, filter in ipairs (futils.filters) do
    if filter.direction == direction and
        filter.media_type == si_props ["media.type"] and
        filter.smart and not filter.disabled and
        ((target ~= nil and filter.target ~= nil and filter.target.id == target.id) or
         (target == nil and filter.targetless)) and
        not foreign_sandbox_node (source, si_props, filter.main_si.properties) then
      return filter.main_si
    end
  end
  return nil
end

-- What a stream sent to `filter` was aimed at, where `filter` is a smart
-- filter's main node with a target, else nil.
local function filter_target (filter)
  for _, entry in ipairs (futils.filters) do
    if entry.main_si.id == filter.id then
      return entry.target
    end
  end
  return nil
end

-- Whether the stream is a smart filter's own node: host_filter would find
-- that filter, or one before it in the chain, and neither can be linked.
local function filters_own_stream (si_props)
  local link_group = si_props ["node.link-group"]
  if link_group == nil then
    return false
  end
  for _, entry in ipairs (futils.filters) do
    if entry.link_group == link_group then
      return true
    end
  end
  return false
end

-- WirePlumber's finders can still aim a stream at a sandbox's node: its
-- smart filter (linking/get-filter-from-target), a node named as the
-- stream's target (linking/find-defined-target) or one ranked above the
-- host's own (linking/find-best-target). Refused after
-- linking/prepare-link, the stream would play nowhere, so here, after
-- every finder and before prepare-link, it is decided as though the
-- sandbox's node were not there: what a sandbox's filter stood in front
-- of, else the session's default (never a sandbox's node), each through
-- the host's own filters as get-filter-from-target would have put it,
-- except for a filter's own stream, which goes there directly;
-- and a stream pinned with `node.dont-fallback` to a target that is
-- only a sandbox's is left as find-defined-target leaves one whose
-- target is missing.
SimpleEventHook {
  name = "bubbler/no-target-from-a-sandbox",
  after = { "linking/find-defined-target",
            "linking/find-audio-group-target",
            "linking/find-filter-target",
            "linking/find-media-role-target",
            "linking/find-media-role-sink-target",
            "linking/find-default-target",
            "linking/find-best-target",
            "linking/get-filter-from-target" },
  before = "linking/prepare-link",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-target" },
    },
  },
  execute = function (event)
    local source, _, si, si_props, si_flags, target =
        lutils:unwrap_select_target_event (event)
    if not target or
        not foreign_sandbox_node (source, si_props, target.properties) then
      return
    end

    local aimed = filter_target (target)
    if aimed and foreign_sandbox_node (source, si_props, aimed.properties) then
      aimed = nil
    end
    local defined = si_flags.has_defined_target
    if not aimed and defined and
        cutils.parseBool (si_props ["node.dont-fallback"]) then
      log:info (si, string.format ("%s is pinned to %s, a sandbox's node",
          tostring (si_props ["node.name"]),
          tostring (target.properties ["node.name"])))
      event:set_data ("target", nil)
      if not cutils.parseBool (si_props ["node.linger"]) then
        local node = si:get_associated_proxy ("node")
        lutils.sendClientError (event, node, -2, "defined target not found")
        node:request_destroy ()
      end
      event:stop_processing ()
      return
    end

    if not aimed then
      aimed = lutils.findDefaultLinkable (si)
      defined = false
      si_flags.has_defined_target = false
      si_flags.has_node_defined_target = false
    end
    local chosen = aimed
    if aimed and not filters_own_stream (si_props) then
      chosen = host_filter (source, si_props, aimed) or
          (not defined and host_filter (source, si_props, nil)) or aimed
    end

    local compatible, can_passthrough
    if chosen then
      compatible, can_passthrough = lutils.checkPassthroughCompatibility (si, chosen)
    end
    if chosen and compatible and lutils.canLink (si_props, chosen) and
        not foreign_sandbox_node (source, si_props, chosen.properties) then
      log:info (si, string.format ("%s goes to %s, not %s",
          tostring (si_props ["node.name"]),
          tostring (chosen.properties ["node.name"]),
          tostring (target.properties ["node.name"])))
      si_flags.can_passthrough = can_passthrough
      event:set_data ("target", chosen)
    else
      event:set_data ("target", nil)
    end
  end
}:register ()

-- Refusing the link alone would leave every host stream unlinked while a
-- sandbox's node is the default: find-default-target picks the default
-- before any later hook can refuse it. So a sandbox's node is never a
-- candidate for the default in the first place.
SimpleEventHook {
  name = "bubbler/no-default-from-a-sandbox",
  before = { "default-nodes/find-selected-default-node",
             "default-nodes/find-stored-default-node",
             "default-nodes/find-best-default-node" },
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-default-node" },
    },
  },
  execute = function (event)
    local available = event:get_data ("available-nodes")
    available = available and available:parse ()
    if not available then
      return
    end
    local source = event:get_source ()
    local kept = {}
    for _, node_props in ipairs (available) do
      if not bubbler_client (source, node_props ["client.id"]) then
        table.insert (kept, Json.Object (node_props))
      end
    end
    event:set_data ("available-nodes", Json.Array (kept))
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
-- node or a bubbler client arrives, and so is the default, which a
-- sandbox's node may have won while its client was not known yet:
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
