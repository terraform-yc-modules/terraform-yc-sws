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
    "inbound_anomaly_score" : 25,
    "is_blocking" : false,
    "is_enabled" : true,
    "paranoia_level" : 1,
    "rule_set_name" : "OWASP Core Ruleset",
    "rule_set_version" : "4.0.0"
  }
  waf_analyze_request_body = {
    "is_enabled" : true
    size_limit        = 8
    size_limit_action = "DENY"
  }


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
