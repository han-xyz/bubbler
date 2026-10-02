-- bubbler's audio policy: the links WirePlumber may not make for a
-- sandbox.
--
-- Install as bubbler/refuse-links.lua in one of
--   /usr/share/wireplumber/scripts/
--   $XDG_DATA_HOME/wireplumber/scripts/
-- beside 50-bubbler.conf, which is what loads it.
--
-- The permission managers in 50-bubbler.conf say what a sandbox may
-- see. Two things they cannot say, because both are facts about a
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
-- So: a bubbler sandbox's stream is linked to device nodes and to its
-- own, a capture stream only to an `Audio/Source*` or `Audio/Duplex`
-- node, and only where the instance was granted `microphone`; and the
-- sandbox links nothing itself.
--
-- Nor is anything linked to a sandbox's node that is not one of its own
-- streams — a sink, source or filter it offers takes no host stream —
-- and no such node becomes the session's default. A link to or from a
-- sandbox's node that is not one of its own streams as WirePlumber
-- linked it is destroyed once WirePlumber sees it, one drawn in a
-- patchbay included.

local lutils = require ("linking-utils")
local log = Log.open_topic ("s-linking")

-- The engine name bubbler gives every security context it creates.
local BUBBLER_ENGINE = "org.bubbler"

-- The client object `client_id` names, or nil where the graph has no
-- such client (a node whose client is already gone).
local function bubbler_client (source, client_id)
  if not client_id then
    return nil
  end
  local clients = source:call ("get-object-manager", "client")
  local client = clients:lookup {
    Constraint { "bound-id", "=", client_id, type = "gobject" },
  }
  if client and client.properties ["pipewire.sec.engine"] == BUBBLER_ENGINE then
    return client
  end
  return nil
end

-- Whether a stream can record from the node: the classes 50-bubbler.conf
-- hides without the microphone grant, by the same test.
local function capture_capable (node_props)
  local class = node_props ["media.class"] or ""
  return class:find ("^Audio/Source") ~= nil or class == "Audio/Duplex"
end

-- Why this link may not be made, or nil where it may.
local function refusal (si_props, target_props, grant)
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
    -- Whoever the stream belongs to: a sink, source or filter a sandbox
    -- offers would otherwise take a host stream without the sandbox
    -- making any link.
    if bubbler_client (source, target_props ["client.id"]) and
        (target_props ["item.node.type"] ~= "stream" or
         target_props ["client.id"] ~= si_props ["client.id"]) then
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

-- The link factory, which every client that makes a link of its own
-- asks the core for by name.
local factories = ObjectManager {
  Interest {
    type = "factory",
    Constraint { "factory.name", "=", "link-factory", type = "pw-global" },
  },
}
factories:activate ()

-- Before the permission manager attaches, not after: the attach is the
-- update that lets the client's held requests through, and a hook after
-- it runs one main-loop turn later — measured on WirePlumber 0.5.18,
-- long enough for a fresh connection to create a link with the factory
-- still readable. The explicit entry set here survives the attach, which
-- changes the default and the objects its rules match, never a factory.
SimpleEventHook {
  name = "bubbler/hide-link-factory",
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
    local factory = factories:lookup {}
    if not factory then
      log:warning (client, "no link factory in the graph: a sandbox that " ..
          "can see two nodes can link them itself")
      return
    end
    -- No permission at all, not read-only: measured on PipeWire 1.6.8,
    -- the core asks only for read on the factory global before creating
    -- the object, so a readable factory is a usable one.
    client:update_permissions { [factory ["bound-id"]] = "-" }
    log:info (client, "link factory hidden from " ..
        tostring (client.properties ["pipewire.sec.app-id"]))
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
-- it.
local function made_by_wireplumber (source, link)
  local linger = link.properties ["object.linger"]
  local creator = link.properties ["client.id"]
  if linger == "true" or linger == "1" or not creator then
    return false
  end
  local clients = source:call ("get-object-manager", "client")
  local client = clients:lookup {
    Constraint { "bound-id", "=", creator, type = "gobject" },
  }
  return client ~= nil and
      client.properties ["wireplumber.daemon"] == "true" and
      client.properties ["pipewire.sec.engine"] == nil
end

-- The properties of the node `node_id` names where it belongs to a
-- bubbler context, or nil.
local function bubbler_node (source, node_id)
  local nodes = source:call ("get-object-manager", "node")
  local node = nodes:lookup {
    Constraint { "bound-id", "=", node_id, type = "gobject" },
  }
  if node and bubbler_client (source, node.properties ["client.id"]) then
    return node.properties
  end
  return nil
end

-- Whether a link from `output` to `input`, the properties of each end
-- that belongs to a bubbler context (nil for one that does not), is one
-- of a context's own streams in that stream's own direction.
local function own_stream_link (output, input)
  if output and output ["media.class"] ~= "Stream/Output/Audio" then
    return false
  end
  if input and input ["media.class"] ~= "Stream/Input/Audio" then
    return false
  end
  return not (output and input) or output ["client.id"] == input ["client.id"]
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
      own_stream_link (output, input)) then
    log:warning (link, "destroying a link to a bubbler context " ..
        "that the policy refuses")
    destroying [serial] = true
    link:request_destroy ()
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
-- node or a bubbler client arrives.
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
    local nodes = source:call ("get-object-manager", "node")
    local is_client = event:get_properties () ["event.type"] == "client-added"
    if is_client and
        subject.properties ["pipewire.sec.engine"] ~= BUBBLER_ENGINE then
      return
    end

    local function ends_here (node_id)
      if not is_client then
        return node_id == id
      end
      local node = nodes:lookup {
        Constraint { "bound-id", "=", node_id, type = "gobject" },
      }
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
