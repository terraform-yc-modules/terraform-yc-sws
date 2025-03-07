## General
variable "name" {
  description = "Name for resources."
  type        = string
  default     = "testy"
}

variable "folder_id" {
  description = "Folder for SWS resources."
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels for resources."
  type        = map(string)
  default = {
    created_by = "terraform-yc-module"
  }
}

variable "description" {
  description = "Description for SWS resources."
  type        = string
  default     = null
}

### Security profile

variable "default_action" {
  description = "Default action (ALLOW or DENY)."
  type        = string
  default     = "ALLOW"

  validation {
    condition     = contains(["ALLOW", "DENY"], var.default_action)
    error_message = "Allowed values for default_action: ALLOW, DENY."
  }
}

variable "captcha_id" {
  description = "Captcha ID (optional). Set empty to use default."
  type        = string
  default     = null
}

variable "security_rules" {
  description = <<EOT
List of security rules for the Security Profile resource.

Each rule object supports:

- name (string, required): Name of the security rule.
- priority (number, required): Priority of the rule. Higher priority rules processed earlier.

Exactly one of the following blocks may be specified per rule:

1. smart_protection block (optional):
    - mode (string, required): Protection mode. Possible values: "FULL", "API".
    - condition block (optional): Conditions when this protection is applied (see detailed structure below).

2. waf block (optional):
    - mode (string, required): WAF mode. Possible values: "FULL", "API".
    - waf_profile_id (string, required): Associated WAF profile ID.
    - condition block (optional): Conditions when WAF rules are applied (see detailed structure below).

3. rule_condition block (optional):
    - action (string, required): Action to perform if condition matches. Possible values: "ALLOW", "DENY".
    - condition block (optional): Conditions when this action is applied (see detailed structure below).

Condition block structure (used in smart_protection, waf, and rule_condition):

- authority block (optional):
    - authorities (list of objects with attribute)

- http_method block (optional):
    - http_methods (list of objects with attribute)

- request_uri block (optional):
    - path block (optional)

    - queries (optional, list):
        - key (string, required): Query string key.
        - value block (optional)

- headers (optional, list):
    - name (string, required): HTTP header name.
    - value block (optional)

- source_ip block (optional):
    - ip_ranges_match block (optional):
        - ip_ranges (list of strings, optional): IP ranges to match.
    - ip_ranges_not_match block (optional):
        - ip_ranges (list of strings, optional): IP ranges to exclude.
    - geo_ip_match block (optional):
        - locations (list of strings, optional): ISO country codes to match.
    - geo_ip_not_match block (optional):
        - locations (list of strings, optional): ISO country codes to exclude.

EOT

  type = list(object({
    name     = string
    priority = number

    smart_protection = optional(object({
      mode = string
      condition = optional(object({
        authority = optional(object({
          authorities = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        http_method = optional(object({
          http_methods = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        request_uri = optional(object({
          path = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
          queries = optional(list(object({
            key = string
            value = optional(object({
              exact_match          = optional(string)
              exact_not_match      = optional(string)
              prefix_match         = optional(string)
              prefix_not_match     = optional(string)
              pire_regex_match     = optional(string)
              pire_regex_not_match = optional(string)
            }))
          })))
        }))
        headers = optional(list(object({
          name = string
          value = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        })))
        source_ip = optional(object({
          ip_ranges_match = optional(object({
            ip_ranges = list(string)
          }))
          ip_ranges_not_match = optional(object({
            ip_ranges = list(string)
          }))
          geo_ip_match = optional(object({
            locations = list(string)
          }))
          geo_ip_not_match = optional(object({
            locations = list(string)
          }))
        }))
      }))
    }), null)

    waf = optional(object({
      mode = string
      condition = optional(object({
        authority = optional(object({
          authorities = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        http_method = optional(object({
          http_methods = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        request_uri = optional(object({
          path = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
          queries = optional(list(object({
            key = string
            value = optional(object({
              exact_match          = optional(string)
              exact_not_match      = optional(string)
              prefix_match         = optional(string)
              prefix_not_match     = optional(string)
              pire_regex_match     = optional(string)
              pire_regex_not_match = optional(string)
            }))
          })))
        }))
        headers = optional(list(object({
          name = string
          value = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        })))
        source_ip = optional(object({
          ip_ranges_match = optional(object({
            ip_ranges = list(string)
          }))
          ip_ranges_not_match = optional(object({
            ip_ranges = list(string)
          }))
          geo_ip_match = optional(object({
            locations = list(string)
          }))
          geo_ip_not_match = optional(object({
            locations = list(string)
          }))
        }))
      }))
    }), null)

    rule_condition = optional(object({
      action = string
      condition = optional(object({
        authority = optional(object({
          authorities = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        http_method = optional(object({
          http_methods = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        request_uri = optional(object({
          path = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
          queries = optional(list(object({
            key = string
            value = optional(object({
              exact_match          = optional(string)
              exact_not_match      = optional(string)
              prefix_match         = optional(string)
              prefix_not_match     = optional(string)
              pire_regex_match     = optional(string)
              pire_regex_not_match = optional(string)
            }))
          })))
        }))
        headers = optional(list(object({
          name = string
          value = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        })))
        source_ip = optional(object({
          ip_ranges_match = optional(object({
            ip_ranges = list(string)
          }))
          ip_ranges_not_match = optional(object({
            ip_ranges = list(string)
          }))
          geo_ip_match = optional(object({
            locations = list(string)
          }))
          geo_ip_not_match = optional(object({
            locations = list(string)
          }))
        }))
      }))
    }), null)

  }))

  default = []
}

## WAF

variable "waf_core_rule_set" {
  description = "Basic rule set settings."
  type = object({
    inbound_anomaly_score = number
    paranoia_level        = number
    rule_set_name         = string
    rule_set_version      = string
    is_enabled            = bool
    is_blocking           = bool
  })
  default = {
    inbound_anomaly_score = 25
    paranoia_level        = 1
    rule_set_name         = "OWASP Core Ruleset"
    rule_set_version      = "4.0.0"
    is_enabled            = true
    is_blocking           = false
  }
}

variable "waf_rules" {
  description = "Additional rules for WAF profile."
  type = list(object({
    rule_id     = string
    is_enabled  = bool
    is_blocking = bool
  }))
  default = []
}

variable "waf_exclusion_rules" {
  description = "List of exclusion rules."
  type = list(object({
    name         = string
    description  = optional(string)
    log_excluded = optional(bool)
    exclude_rules = optional(object({
      exclude_all = optional(bool)
      rule_ids    = optional(list(string))
    }))
  }))
  default = []
}

variable "waf_analyze_request_body" {
  description = "Analyze request body settings."
  type = object({
    is_enabled        = bool
    size_limit        = optional(number)
    size_limit_action = optional(string)
  })
  default = {
    is_enabled = false
  }
}

### ARL

variable "arl_enabled" {
  description = "Advanced Rate Limiter enabled flag."
  type        = bool
  default     = false
}

variable "advanced_rate_limiter_rules" {
  description = "List of ARL rules with quotas and conditions."
  type = list(object({
    name        = string
    priority    = number
    description = optional(string)
    dry_run     = optional(bool)

    static_quota = optional(object({
      action = string
      limit  = number
      period = number
      condition = optional(object({
        authority = optional(object({
          authorities = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        http_method = optional(object({
          http_methods = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        request_uri = optional(object({
          path = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
          queries = optional(list(object({
            key = string
            value = optional(object({
              exact_match          = optional(string)
              exact_not_match      = optional(string)
              prefix_match         = optional(string)
              prefix_not_match     = optional(string)
              pire_regex_match     = optional(string)
              pire_regex_not_match = optional(string)
            }))
          })))
        }))
        headers = optional(list(object({
          name = string
          value = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        })))
        source_ip = optional(object({
          ip_ranges_match = optional(object({
            ip_ranges = list(string)
          }))
          ip_ranges_not_match = optional(object({
            ip_ranges = list(string)
          }))
          geo_ip_match = optional(object({
            locations = list(string)
          }))
          geo_ip_not_match = optional(object({
            locations = list(string)
          }))
        }))
      }))
    }))

    dynamic_quota = optional(object({
      action = string
      limit  = number
      period = number
      condition = optional(object({
        authority = optional(object({
          authorities = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        http_method = optional(object({
          http_methods = list(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        }))
        request_uri = optional(object({
          path = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
          queries = optional(list(object({
            key = string
            value = optional(object({
              exact_match          = optional(string)
              exact_not_match      = optional(string)
              prefix_match         = optional(string)
              prefix_not_match     = optional(string)
              pire_regex_match     = optional(string)
              pire_regex_not_match = optional(string)
            }))
          })))
        }))
        headers = optional(list(object({
          name = string
          value = optional(object({
            exact_match          = optional(string)
            exact_not_match      = optional(string)
            prefix_match         = optional(string)
            prefix_not_match     = optional(string)
            pire_regex_match     = optional(string)
            pire_regex_not_match = optional(string)
          }))
        })))
        source_ip = optional(object({
          ip_ranges_match = optional(object({
            ip_ranges = list(string)
          }))
          ip_ranges_not_match = optional(object({
            ip_ranges = list(string)
          }))
          geo_ip_match = optional(object({
            locations = list(string)
          }))
          geo_ip_not_match = optional(object({
            locations = list(string)
          }))
        }))
      }))
      characteristics = list(object({
        case_insensitive = optional(bool)
        simple_characteristic = optional(object({
          type = string
        }))
        key_characteristic = optional(object({
          type  = string
          value = string
        }))
      }))
    }))
  }))
  default = []
}
