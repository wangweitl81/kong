local BasePlugin = require "kong.plugins.base_plugin"
local constants = require "kong.constants"
local tablex = require "pl.tablex"
local groups = require "kong.plugins.acl.groups"


local setmetatable = setmetatable
local concat = table.concat
local kong = kong


local EMPTY = tablex.readonly {}
local BLACK = "BLACK"
local WHITE = "WHITE"


local mt_cache = { __mode = "k" }
local config_cache = setmetatable({}, mt_cache)


local function get_to_be_blocked(config_groups, config_type, consumer_groups,
                                 hide_groups_header)

  local in_group = groups.consumer_in_groups(config_groups, consumer_groups)

  local to_be_blocked
  if config_type == BLACK then
    to_be_blocked = in_group
  else
    to_be_blocked = not in_group
  end

  if to_be_blocked == false then
    -- we're allowed, convert 'false' to the header value, if needed
    -- if not needed, set dummy value to save mem for potential long strings
    to_be_blocked = hide_groups_header and "" or concat(consumer_groups, ", ")
  end

  return to_be_blocked
end


local ACLHandler = BasePlugin:extend()


ACLHandler.PRIORITY = 950
ACLHandler.VERSION = "1.0.0"


function ACLHandler:new()
  ACLHandler.super.new(self, "acl")
end


function ACLHandler:access(conf)
  ACLHandler.super.access(self)

  -- simplify our plugins 'conf' table
  local config = config_cache[conf]
  if not config then
    config = {}
    config.type = (conf.blacklist or EMPTY)[1] and BLACK or WHITE
    config.groups = config.type == BLACK and conf.blacklist or conf.whitelist
    config.cache = setmetatable({}, mt_cache)
  end

  local to_be_blocked

  -- get the consumer/credentials
  local consumer_id = groups.get_current_consumer_id()
  if not consumer_id then
    local authenticated_groups = groups.get_authenticated_groups()
    if not authenticated_groups then
      kong.log.err("Cannot identify the consumer, add an authentication ",
                   "plugin to use the ACL plugin")

      return kong.response.exit(403, {
        message = "You cannot consume this service"
      })
    end

    to_be_blocked = get_to_be_blocked(config.groups, config.type,
                                      authenticated_groups,
                                      conf.hide_groups_header)
  else
    local authenticated_groups
    if not kong.client.get_credential() then
      -- authenticated groups overrides anonymous groups
      authenticated_groups = groups.get_authenticated_groups()
    end

    if authenticated_groups then
      consumer_id = nil
      to_be_blocked = get_to_be_blocked(config.groups, config.type,
                                        authenticated_groups,
                                        conf.hide_groups_header)

    else
      -- get the consumer groups, since we need those as cache-keys to make sure
      -- we invalidate properly if they change
      local consumer_groups, err = groups.get_consumer_groups(consumer_id)
      if not consumer_groups then
        kong.log.err(err)
        return kong.response.exit(500, {
          message = "An unexpected error occurred"
        })
      end


      -- 'to_be_blocked' is either 'true' if it's to be blocked, or the header
      -- value if it is to be passed
      to_be_blocked = config.cache[consumer_groups]
      if to_be_blocked == nil then
        to_be_blocked = get_to_be_blocked(config.groups, config.type,
                                          consumer_groups,
                                          conf.hide_groups_header)

        -- update cache
        config.cache[consumer_groups] = to_be_blocked
      end
    end
  end

  if to_be_blocked == true then -- NOTE: we only catch the boolean here!
    return kong.response.exit(403, {
      message = "You cannot consume this service"
    })
  end

  if not conf.hide_groups_header and to_be_blocked then
    kong.service.request.set_header(consumer_id and
                                    constants.HEADERS.CONSUMER_GROUPS or
                                    constants.HEADERS.AUTHENTICATED_GROUPS,
                                    to_be_blocked)
  end
end


return ACLHandler
