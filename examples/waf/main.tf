data "yandex_sws_waf_rule_set_descriptor" "rule_set" {
  name    = "OWASP Core Ruleset"
  version = "4.0.0"
}

module "yandex_sws" {
  source = "../../"
  name   = "waf"

  # ARL-профиль

  arl_enabled = true
  advanced_rate_limiter_rules = [
    {
      name     = "api-rate-limit"
      priority = 10
      static_quota = {
        action = "DENY"
        limit  = 10000
        period = 60
        condition = {
          request_uri = {
            path = {
              prefix_match = "/api/"
            }
          }
        }
      }
    },
  ]

  # Waf-профиль
  waf_core_rule_set = {
    inbound_anomaly_score = 25
    is_blocking           = false
    is_enabled            = true
    paranoia_level        = 1
    rule_set_name         = "OWASP Core Ruleset"
    rule_set_version      = "4.0.0"
  }
  waf_rules = [{
    is_blocking = false
    is_enabled  = false
    rule_id     = "owasp-crs-v4.0.0-id944152-attack-java"
  }]
  waf_analyze_request_body = {
    is_enabled        = true
    size_limit        = 8
    size_limit_action = "DENY"
  }
  waf_exclusion_rules = [
    {
      name         = "excluded-rules-list"
      log_excluded = true
      exclude_rules = {
        exclude_all = true
      }
      condition = {
        source_ip = {
          ip_ranges_match = {
            ip_ranges = ["1.2.33.44", "2.3.4.56"]
          }
        }
      }
    }
  ]


  # Профиль безопасности

  default_action = "DENY"
  security_rules = [{
    name     = "WAF-rule"
    priority = 88888

    waf = {
      mode = "API"
    }
  }]
}
