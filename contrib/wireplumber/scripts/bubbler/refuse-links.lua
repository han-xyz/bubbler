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
-- own, a capture stream only to an `Audio/Source`, and only where the
-- instance was granted `microphone`; and the sandbox links nothing
-- itself.

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

-- Why this link may not be made, or nil where it may.
local function refusal (si_props, target_props, grant)
  if target_props ["item.node.type"] == "stream" and
      target_props ["client.id"] ~= si_props ["client.id"] then
    return "another client's stream"
  end

  if si_props ["item.node.direction"] ~= "input" then
    return nil
  end

  -- A capture stream and a target that is also an input: the target is
  -- a sink and what would be linked are its monitor ports.
  if target_props ["item.node.direction"] == "input" then
    return "a sink's monitor ports"
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

    local client = bubbler_client (source, si_props ["client.id"])
    if not client then
      return
    end

    local why = refusal (si_props, target.properties,
        client.properties ["bubbler.audio"] or "")
    if why then
      log:info (si, string.format ("refusing %s (%s) a link to %s: %s",
          tostring (si_props ["node.name"]),
          tostring (client.properties ["pipewire.sec.app-id"]),
          tostring (target.properties ["node.name"]),
          why))
      event:set_data ("target", nil)
    end
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

SimpleEventHook {
  name = "bubbler/hide-link-factory",
  after = "client/apply-access",
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
      log:warning (client, "no link factory in the graph: a sandbox that can \
          see two nodes can link them itself")
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

SimpleEventHook {
  name = "bubbler/destroy-self-made-link",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "link-added" },
    },
  },
  execute = function (event)
    local link = event:get_subject ()
    -- A link WirePlumber makes on a sandbox's behalf carries its own
    -- client id, not the sandbox's, so this reaches only a link the
    -- sandbox created for itself — which the hidden factory should
    -- already have refused.
    if bubbler_client (event:get_source (), link.properties ["client.id"]) then
      log:warning (link, "destroying a link a bubbler context made for itself")
      link:request_destroy ()
    end
  end
}:register ()
