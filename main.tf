### Datasource
data "yandex_client_config" "client" {}

data "yandex_sws_waf_rule_set_descriptor" "rule_set" {
  name    = var.waf_core_rule_set.rule_set_name
  version = var.waf_core_rule_set.rule_set_version
}

### Locals
locals {
  folder_id = var.folder_id == null ? data.yandex_client_config.client.folder_id : var.folder_id
}

### WAF
resource "yandex_sws_waf_profile" "this" {
  count       = one([for rule in var.security_rules : rule.waf if rule.waf != null]) != null ? 1 : 0
  name        = var.name
  folder_id   = local.folder_id
  labels      = var.labels
  description = var.description

  core_rule_set {
    inbound_anomaly_score = var.waf_core_rule_set.inbound_anomaly_score
    paranoia_level        = var.waf_core_rule_set.paranoia_level

    rule_set {
      name    = var.waf_core_rule_set.rule_set_name
      version = var.waf_core_rule_set.rule_set_version
    }
  }

  dynamic "rule" {
    for_each = [
      for rule in data.yandex_sws_waf_rule_set_descriptor.rule_set.rules : rule
      if rule.paranoia_level >= var.waf_core_rule_set.paranoia_level
    ]
    content {
      rule_id     = rule.value.id
      is_enabled  = var.waf_core_rule_set.is_enabled
      is_blocking = var.waf_core_rule_set.is_blocking
    }
  }

  dynamic "rule" {
    for_each = var.waf_rules
    content {
      rule_id     = rule.value.rule_id
      is_enabled  = rule.value.is_enabled
      is_blocking = rule.value.is_blocking
    }
  }

  dynamic "exclusion_rule" {
    for_each = var.waf_exclusion_rules
    content {
      name         = exclusion_rule.value.name
      description  = lookup(exclusion_rule.value, "description", null)
      log_excluded = lookup(exclusion_rule.value, "log_excluded", null)
      dynamic "condition" {
        for_each = exclusion_rule.value.condition != null ? [exclusion_rule.value.condition] : []
        content {
          # Authority
          dynamic "authority" {
            for_each = condition.value.authority != null ? [condition.value.authority] : []
            content {
              dynamic "authorities" {
                for_each = authority.value.authorities != null ? authority.value.authorities : []
                content {
                  exact_match          = authorities.value.exact_match
                  exact_not_match      = authorities.value.exact_not_match
                  prefix_match         = authorities.value.prefix_match
                  prefix_not_match     = authorities.value.prefix_not_match
                  pire_regex_match     = authorities.value.pire_regex_match
                  pire_regex_not_match = authorities.value.pire_regex_not_match
                }
              }
            }
          }

          # HTTP Method
          dynamic "http_method" {
            for_each = condition.value.http_method != null ? [condition.value.http_method] : []
            content {
              dynamic "http_methods" {
                for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                content {
                  exact_match          = http_methods.value.exact_match
                  exact_not_match      = http_methods.value.exact_not_match
                  prefix_match         = http_methods.value.prefix_match
                  prefix_not_match     = http_methods.value.prefix_not_match
                  pire_regex_match     = http_methods.value.pire_regex_match
                  pire_regex_not_match = http_methods.value.pire_regex_not_match
                }
              }
            }
          }

          # Request URI
          dynamic "request_uri" {
            for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
            content {
              dynamic "path" {
                for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                content {
                  exact_match          = path.value.exact_match
                  exact_not_match      = path.value.exact_not_match
                  prefix_match         = path.value.prefix_match
                  prefix_not_match     = path.value.prefix_not_match
                  pire_regex_match     = path.value.pire_regex_match
                  pire_regex_not_match = path.value.pire_regex_not_match
                }
              }

              dynamic "queries" {
                for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                content {
                  key = queries.value.key
                  dynamic "value" {
                    for_each = queries.value.value != null ? [queries.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }
            }
          }

          # Headers
          dynamic "headers" {
            for_each = condition.value.headers != null ? condition.value.headers : []
            content {
              name = headers.value.name
              dynamic "value" {
                for_each = headers.value.value != null ? [headers.value.value] : []
                content {
                  exact_match          = value.value.exact_match
                  exact_not_match      = value.value.exact_not_match
                  prefix_match         = value.value.prefix_match
                  prefix_not_match     = value.value.prefix_not_match
                  pire_regex_match     = value.value.pire_regex_match
                  pire_regex_not_match = value.value.pire_regex_not_match
                }
              }
            }
          }

          # Source IP
          dynamic "source_ip" {
            for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
            content {
              dynamic "ip_ranges_match" {
                for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                content {
                  ip_ranges = ip_ranges_match.value.ip_ranges
                }
              }

              dynamic "ip_ranges_not_match" {
                for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                content {
                  ip_ranges = ip_ranges_not_match.value.ip_ranges
                }
              }

              dynamic "geo_ip_match" {
                for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                content {
                  locations = geo_ip_match.value.locations
                }
              }

              dynamic "geo_ip_not_match" {
                for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                content {
                  locations = geo_ip_not_match.value.locations
                }
              }
            }
          }
        }
      }

      dynamic "exclude_rules" {
        for_each = exclusion_rule.value.exclude_rules != null ? [exclusion_rule.value.exclude_rules] : []
        content {
          exclude_all = exclusion_rule.value.exclude_rules.exclude_all
          rule_ids    = exclusion_rule.value.exclude_rules.rule_ids
        }
      }
    }
  }

  dynamic "analyze_request_body" {
    for_each = var.waf_analyze_request_body.is_enabled ? [var.waf_analyze_request_body] : []
    content {
      is_enabled        = analyze_request_body.value.is_enabled
      size_limit        = analyze_request_body.value.size_limit
      size_limit_action = analyze_request_body.value.size_limit_action
    }
  }
}

### Advanced Rate Limiter
resource "yandex_sws_advanced_rate_limiter_profile" "this" {
  count       = var.arl_enabled ? 1 : 0
  name        = var.name
  folder_id   = local.folder_id
  description = var.description
  labels      = var.labels

  dynamic "advanced_rate_limiter_rule" {
    for_each = var.advanced_rate_limiter_rules

    content {
      name        = advanced_rate_limiter_rule.value.name
      priority    = advanced_rate_limiter_rule.value.priority
      description = advanced_rate_limiter_rule.value.description
      dry_run     = advanced_rate_limiter_rule.value.dry_run

      dynamic "static_quota" {
        for_each = advanced_rate_limiter_rule.value.static_quota != null ? [advanced_rate_limiter_rule.value.static_quota] : []
        content {
          action = static_quota.value.action
          limit  = static_quota.value.limit
          period = static_quota.value.period

          dynamic "condition" {
            for_each = lookup(static_quota.value, "condition", null) != null ? [static_quota.value.condition] : []
            content {
              # Authority
              dynamic "authority" {
                for_each = condition.value.authority != null ? [condition.value.authority] : []
                content {
                  dynamic "authorities" {
                    for_each = authority.value.authorities != null ? authority.value.authorities : []
                    content {
                      exact_match          = authorities.value.exact_match
                      exact_not_match      = authorities.value.exact_not_match
                      prefix_match         = authorities.value.prefix_match
                      prefix_not_match     = authorities.value.prefix_not_match
                      pire_regex_match     = authorities.value.pire_regex_match
                      pire_regex_not_match = authorities.value.pire_regex_not_match
                    }
                  }
                }
              }

              # HTTP Method
              dynamic "http_method" {
                for_each = condition.value.http_method != null ? [condition.value.http_method] : []
                content {
                  dynamic "http_methods" {
                    for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                    content {
                      exact_match          = http_methods.value.exact_match
                      exact_not_match      = http_methods.value.exact_not_match
                      prefix_match         = http_methods.value.prefix_match
                      prefix_not_match     = http_methods.value.prefix_not_match
                      pire_regex_match     = http_methods.value.pire_regex_match
                      pire_regex_not_match = http_methods.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Request URI
              dynamic "request_uri" {
                for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
                content {
                  dynamic "path" {
                    for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                    content {
                      exact_match          = path.value.exact_match
                      exact_not_match      = path.value.exact_not_match
                      prefix_match         = path.value.prefix_match
                      prefix_not_match     = path.value.prefix_not_match
                      pire_regex_match     = path.value.pire_regex_match
                      pire_regex_not_match = path.value.pire_regex_not_match
                    }
                  }

                  dynamic "queries" {
                    for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                    content {
                      key = queries.value.key
                      dynamic "value" {
                        for_each = queries.value.value != null ? [queries.value.value] : []
                        content {
                          exact_match          = value.value.exact_match
                          exact_not_match      = value.value.exact_not_match
                          prefix_match         = value.value.prefix_match
                          prefix_not_match     = value.value.prefix_not_match
                          pire_regex_match     = value.value.pire_regex_match
                          pire_regex_not_match = value.value.pire_regex_not_match
                        }
                      }
                    }
                  }
                }
              }

              # Headers
              dynamic "headers" {
                for_each = condition.value.headers != null ? condition.value.headers : []
                content {
                  name = headers.value.name
                  dynamic "value" {
                    for_each = headers.value.value != null ? [headers.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Source IP
              dynamic "source_ip" {
                for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
                content {
                  dynamic "ip_ranges_match" {
                    for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                    content {
                      ip_ranges = ip_ranges_match.value.ip_ranges
                    }
                  }

                  dynamic "ip_ranges_not_match" {
                    for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                    content {
                      ip_ranges = ip_ranges_not_match.value.ip_ranges
                    }
                  }

                  dynamic "geo_ip_match" {
                    for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                    content {
                      locations = geo_ip_match.value.locations
                    }
                  }

                  dynamic "geo_ip_not_match" {
                    for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                    content {
                      locations = geo_ip_not_match.value.locations
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "dynamic_quota" {
        for_each = advanced_rate_limiter_rule.value.dynamic_quota != null ? [advanced_rate_limiter_rule.value.dynamic_quota] : []
        content {
          action = dynamic_quota.value.action
          limit  = dynamic_quota.value.limit
          period = dynamic_quota.value.period

          dynamic "condition" {
            for_each = lookup(dynamic_quota.value, "condition", null) != null ? [dynamic_quota.value.condition] : []
            content {
              # Authority
              dynamic "authority" {
                for_each = condition.value.authority != null ? [condition.value.authority] : []
                content {
                  dynamic "authorities" {
                    for_each = authority.value.authorities != null ? authority.value.authorities : []
                    content {
                      exact_match          = authorities.value.exact_match
                      exact_not_match      = authorities.value.exact_not_match
                      prefix_match         = authorities.value.prefix_match
                      prefix_not_match     = authorities.value.prefix_not_match
                      pire_regex_match     = authorities.value.pire_regex_match
                      pire_regex_not_match = authorities.value.pire_regex_not_match
                    }
                  }
                }
              }

              # HTTP Method
              dynamic "http_method" {
                for_each = condition.value.http_method != null ? [condition.value.http_method] : []
                content {
                  dynamic "http_methods" {
                    for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                    content {
                      exact_match          = http_methods.value.exact_match
                      exact_not_match      = http_methods.value.exact_not_match
                      prefix_match         = http_methods.value.prefix_match
                      prefix_not_match     = http_methods.value.prefix_not_match
                      pire_regex_match     = http_methods.value.pire_regex_match
                      pire_regex_not_match = http_methods.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Request URI
              dynamic "request_uri" {
                for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
                content {
                  dynamic "path" {
                    for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                    content {
                      exact_match          = path.value.exact_match
                      exact_not_match      = path.value.exact_not_match
                      prefix_match         = path.value.prefix_match
                      prefix_not_match     = path.value.prefix_not_match
                      pire_regex_match     = path.value.pire_regex_match
                      pire_regex_not_match = path.value.pire_regex_not_match
                    }
                  }

                  dynamic "queries" {
                    for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                    content {
                      key = queries.value.key
                      dynamic "value" {
                        for_each = queries.value.value != null ? [queries.value.value] : []
                        content {
                          exact_match          = value.value.exact_match
                          exact_not_match      = value.value.exact_not_match
                          prefix_match         = value.value.prefix_match
                          prefix_not_match     = value.value.prefix_not_match
                          pire_regex_match     = value.value.pire_regex_match
                          pire_regex_not_match = value.value.pire_regex_not_match
                        }
                      }
                    }
                  }
                }
              }

              # Headers
              dynamic "headers" {
                for_each = condition.value.headers != null ? condition.value.headers : []
                content {
                  name = headers.value.name
                  dynamic "value" {
                    for_each = headers.value.value != null ? [headers.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Source IP
              dynamic "source_ip" {
                for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
                content {
                  dynamic "ip_ranges_match" {
                    for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                    content {
                      ip_ranges = ip_ranges_match.value.ip_ranges
                    }
                  }

                  dynamic "ip_ranges_not_match" {
                    for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                    content {
                      ip_ranges = ip_ranges_not_match.value.ip_ranges
                    }
                  }

                  dynamic "geo_ip_match" {
                    for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                    content {
                      locations = geo_ip_match.value.locations
                    }
                  }

                  dynamic "geo_ip_not_match" {
                    for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                    content {
                      locations = geo_ip_not_match.value.locations
                    }
                  }
                }
              }
            }
          }

          dynamic "characteristic" {
            for_each = dynamic_quota.value.characteristic
            content {
              case_insensitive = characteristic.value.case_insensitive

              dynamic "simple_characteristic" {
                for_each = characteristic.value.simple_characteristic != null ? [characteristic.value.simple_characteristic] : []
                content {
                  type = simple_characteristic.value.type
                }
              }

              dynamic "key_characteristic" {
                for_each = characteristic.value.key_characteristic != null ? [characteristic.value.key_characteristic] : []
                content {
                  type  = key_characteristic.value.type
                  value = key_characteristic.value.value
                }
              }
            }
          }
        }
      }
    }
  }
}

### Security profile

resource "yandex_sws_security_profile" "this" {
  name                             = var.name
  folder_id                        = local.folder_id
  labels                           = var.labels
  description                      = var.description
  default_action                   = var.default_action
  captcha_id                       = var.captcha_id
  advanced_rate_limiter_profile_id = var.arl_enabled == true ? yandex_sws_advanced_rate_limiter_profile.this[0].id : null
  depends_on                       = [yandex_sws_waf_profile.this]

  dynamic "security_rule" {
    for_each = var.security_rules
    content {
      name     = security_rule.value.name
      priority = security_rule.value.priority
      dry_run  = security_rule.value.dry_run

      dynamic "smart_protection" {
        for_each = security_rule.value.smart_protection != null ? [security_rule.value.smart_protection] : []
        content {
          mode = smart_protection.value.mode
          dynamic "condition" {
            for_each = smart_protection.value.condition != null ? [smart_protection.value.condition] : []
            content {
              # Authority
              dynamic "authority" {
                for_each = condition.value.authority != null ? [condition.value.authority] : []
                content {
                  dynamic "authorities" {
                    for_each = authority.value.authorities != null ? authority.value.authorities : []
                    content {
                      exact_match          = authorities.value.exact_match
                      exact_not_match      = authorities.value.exact_not_match
                      prefix_match         = authorities.value.prefix_match
                      prefix_not_match     = authorities.value.prefix_not_match
                      pire_regex_match     = authorities.value.pire_regex_match
                      pire_regex_not_match = authorities.value.pire_regex_not_match
                    }
                  }
                }
              }

              # HTTP Method
              dynamic "http_method" {
                for_each = condition.value.http_method != null ? [condition.value.http_method] : []
                content {
                  dynamic "http_methods" {
                    for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                    content {
                      exact_match          = http_methods.value.exact_match
                      exact_not_match      = http_methods.value.exact_not_match
                      prefix_match         = http_methods.value.prefix_match
                      prefix_not_match     = http_methods.value.prefix_not_match
                      pire_regex_match     = http_methods.value.pire_regex_match
                      pire_regex_not_match = http_methods.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Request URI
              dynamic "request_uri" {
                for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
                content {
                  dynamic "path" {
                    for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                    content {
                      exact_match          = path.value.exact_match
                      exact_not_match      = path.value.exact_not_match
                      prefix_match         = path.value.prefix_match
                      prefix_not_match     = path.value.prefix_not_match
                      pire_regex_match     = path.value.pire_regex_match
                      pire_regex_not_match = path.value.pire_regex_not_match
                    }
                  }

                  dynamic "queries" {
                    for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                    content {
                      key = queries.value.key
                      dynamic "value" {
                        for_each = queries.value.value != null ? [queries.value.value] : []
                        content {
                          exact_match          = value.value.exact_match
                          exact_not_match      = value.value.exact_not_match
                          prefix_match         = value.value.prefix_match
                          prefix_not_match     = value.value.prefix_not_match
                          pire_regex_match     = value.value.pire_regex_match
                          pire_regex_not_match = value.value.pire_regex_not_match
                        }
                      }
                    }
                  }
                }
              }

              # Headers
              dynamic "headers" {
                for_each = condition.value.headers != null ? condition.value.headers : []
                content {
                  name = headers.value.name
                  dynamic "value" {
                    for_each = headers.value.value != null ? [headers.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Source IP
              dynamic "source_ip" {
                for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
                content {
                  dynamic "ip_ranges_match" {
                    for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                    content {
                      ip_ranges = ip_ranges_match.value.ip_ranges
                    }
                  }

                  dynamic "ip_ranges_not_match" {
                    for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                    content {
                      ip_ranges = ip_ranges_not_match.value.ip_ranges
                    }
                  }

                  dynamic "geo_ip_match" {
                    for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                    content {
                      locations = geo_ip_match.value.locations
                    }
                  }

                  dynamic "geo_ip_not_match" {
                    for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                    content {
                      locations = geo_ip_not_match.value.locations
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "waf" {
        for_each = security_rule.value.waf != null ? [security_rule.value.waf] : []
        content {
          mode           = waf.value.mode
          waf_profile_id = yandex_sws_waf_profile.this[0].id
          dynamic "condition" {
            for_each = waf.value.condition != null ? [waf.value.condition] : []
            content {
              # Authority
              dynamic "authority" {
                for_each = condition.value.authority != null ? [condition.value.authority] : []
                content {
                  dynamic "authorities" {
                    for_each = authority.value.authorities != null ? authority.value.authorities : []
                    content {
                      exact_match          = authorities.value.exact_match
                      exact_not_match      = authorities.value.exact_not_match
                      prefix_match         = authorities.value.prefix_match
                      prefix_not_match     = authorities.value.prefix_not_match
                      pire_regex_match     = authorities.value.pire_regex_match
                      pire_regex_not_match = authorities.value.pire_regex_not_match
                    }
                  }
                }
              }

              # HTTP Method
              dynamic "http_method" {
                for_each = condition.value.http_method != null ? [condition.value.http_method] : []
                content {
                  dynamic "http_methods" {
                    for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                    content {
                      exact_match          = http_methods.value.exact_match
                      exact_not_match      = http_methods.value.exact_not_match
                      prefix_match         = http_methods.value.prefix_match
                      prefix_not_match     = http_methods.value.prefix_not_match
                      pire_regex_match     = http_methods.value.pire_regex_match
                      pire_regex_not_match = http_methods.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Request URI
              dynamic "request_uri" {
                for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
                content {
                  dynamic "path" {
                    for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                    content {
                      exact_match          = path.value.exact_match
                      exact_not_match      = path.value.exact_not_match
                      prefix_match         = path.value.prefix_match
                      prefix_not_match     = path.value.prefix_not_match
                      pire_regex_match     = path.value.pire_regex_match
                      pire_regex_not_match = path.value.pire_regex_not_match
                    }
                  }

                  dynamic "queries" {
                    for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                    content {
                      key = queries.value.key
                      dynamic "value" {
                        for_each = queries.value.value != null ? [queries.value.value] : []
                        content {
                          exact_match          = value.value.exact_match
                          exact_not_match      = value.value.exact_not_match
                          prefix_match         = value.value.prefix_match
                          prefix_not_match     = value.value.prefix_not_match
                          pire_regex_match     = value.value.pire_regex_match
                          pire_regex_not_match = value.value.pire_regex_not_match
                        }
                      }
                    }
                  }
                }
              }

              # Headers
              dynamic "headers" {
                for_each = condition.value.headers != null ? condition.value.headers : []
                content {
                  name = headers.value.name
                  dynamic "value" {
                    for_each = headers.value.value != null ? [headers.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Source IP
              dynamic "source_ip" {
                for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
                content {
                  dynamic "ip_ranges_match" {
                    for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                    content {
                      ip_ranges = ip_ranges_match.value.ip_ranges
                    }
                  }

                  dynamic "ip_ranges_not_match" {
                    for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                    content {
                      ip_ranges = ip_ranges_not_match.value.ip_ranges
                    }
                  }

                  dynamic "geo_ip_match" {
                    for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                    content {
                      locations = geo_ip_match.value.locations
                    }
                  }

                  dynamic "geo_ip_not_match" {
                    for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                    content {
                      locations = geo_ip_not_match.value.locations
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "rule_condition" {
        for_each = security_rule.value.rule_condition != null ? [security_rule.value.rule_condition] : []
        content {
          action = rule_condition.value.action

          dynamic "condition" {
            for_each = rule_condition.value.condition != null ? [rule_condition.value.condition] : []
            content {
              # Authority
              dynamic "authority" {
                for_each = condition.value.authority != null ? [condition.value.authority] : []
                content {
                  dynamic "authorities" {
                    for_each = authority.value.authorities != null ? authority.value.authorities : []
                    content {
                      exact_match          = authorities.value.exact_match
                      exact_not_match      = authorities.value.exact_not_match
                      prefix_match         = authorities.value.prefix_match
                      prefix_not_match     = authorities.value.prefix_not_match
                      pire_regex_match     = authorities.value.pire_regex_match
                      pire_regex_not_match = authorities.value.pire_regex_not_match
                    }
                  }
                }
              }

              # HTTP Method
              dynamic "http_method" {
                for_each = condition.value.http_method != null ? [condition.value.http_method] : []
                content {
                  dynamic "http_methods" {
                    for_each = http_method.value.http_methods != null ? http_method.value.http_methods : []
                    content {
                      exact_match          = http_methods.value.exact_match
                      exact_not_match      = http_methods.value.exact_not_match
                      prefix_match         = http_methods.value.prefix_match
                      prefix_not_match     = http_methods.value.prefix_not_match
                      pire_regex_match     = http_methods.value.pire_regex_match
                      pire_regex_not_match = http_methods.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Request URI
              dynamic "request_uri" {
                for_each = condition.value.request_uri != null ? [condition.value.request_uri] : []
                content {
                  dynamic "path" {
                    for_each = request_uri.value.path != null ? [request_uri.value.path] : []
                    content {
                      exact_match          = path.value.exact_match
                      exact_not_match      = path.value.exact_not_match
                      prefix_match         = path.value.prefix_match
                      prefix_not_match     = path.value.prefix_not_match
                      pire_regex_match     = path.value.pire_regex_match
                      pire_regex_not_match = path.value.pire_regex_not_match
                    }
                  }

                  dynamic "queries" {
                    for_each = request_uri.value.queries != null ? request_uri.value.queries : []
                    content {
                      key = queries.value.key
                      dynamic "value" {
                        for_each = queries.value.value != null ? [queries.value.value] : []
                        content {
                          exact_match          = value.value.exact_match
                          exact_not_match      = value.value.exact_not_match
                          prefix_match         = value.value.prefix_match
                          prefix_not_match     = value.value.prefix_not_match
                          pire_regex_match     = value.value.pire_regex_match
                          pire_regex_not_match = value.value.pire_regex_not_match
                        }
                      }
                    }
                  }
                }
              }

              # Headers
              dynamic "headers" {
                for_each = condition.value.headers != null ? condition.value.headers : []
                content {
                  name = headers.value.name
                  dynamic "value" {
                    for_each = headers.value.value != null ? [headers.value.value] : []
                    content {
                      exact_match          = value.value.exact_match
                      exact_not_match      = value.value.exact_not_match
                      prefix_match         = value.value.prefix_match
                      prefix_not_match     = value.value.prefix_not_match
                      pire_regex_match     = value.value.pire_regex_match
                      pire_regex_not_match = value.value.pire_regex_not_match
                    }
                  }
                }
              }

              # Source IP
              dynamic "source_ip" {
                for_each = condition.value.source_ip != null ? [condition.value.source_ip] : []
                content {
                  dynamic "ip_ranges_match" {
                    for_each = source_ip.value.ip_ranges_match != null ? [source_ip.value.ip_ranges_match] : []
                    content {
                      ip_ranges = ip_ranges_match.value.ip_ranges
                    }
                  }

                  dynamic "ip_ranges_not_match" {
                    for_each = source_ip.value.ip_ranges_not_match != null ? [source_ip.value.ip_ranges_not_match] : []
                    content {
                      ip_ranges = ip_ranges_not_match.value.ip_ranges
                    }
                  }

                  dynamic "geo_ip_match" {
                    for_each = source_ip.value.geo_ip_match != null ? [source_ip.value.geo_ip_match] : []
                    content {
                      locations = geo_ip_match.value.locations
                    }
                  }

                  dynamic "geo_ip_not_match" {
                    for_each = source_ip.value.geo_ip_not_match != null ? [source_ip.value.geo_ip_not_match] : []
                    content {
                      locations = geo_ip_not_match.value.locations
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
