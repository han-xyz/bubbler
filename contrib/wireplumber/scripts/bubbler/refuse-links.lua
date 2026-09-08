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
-- So: a bubbler sandbox's stream is linked to device nodes and to its
-- own, a capture stream only to an `Audio/Source`, and only where the
-- instance was granted `microphone`.

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
