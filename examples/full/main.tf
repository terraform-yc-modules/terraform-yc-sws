module "yandex_sws" {
  source = "../../"
  name   = "Full-sws"
  labels = {
    environment = "production"
    managed_by  = "terraform"
  }

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
    {
      name     = "geo-based-limit"
      priority = 30
      static_quota = {
        action = "DENY"
        limit  = 500
        period = 60
        condition = {
          source_ip = {
            geo_ip_match = {
              locations = ["ru", "kz"]
            }
          }
        }
      }
    },
    {
      name        = "login-protection"
      priority    = 5
      description = "Защита страницы авторизации от брутфорса"
      static_quota = {
        action = "DENY"
        limit  = 10
        period = 60
        condition = {
          request_uri = {
            path = {
              exact_match = "/login"
            }
          },
          http_method = {
            http_methods = [
              {
                exact_match = "POST"
              }
            ]
          }
        }
      }
    }
  ]

  # Waf-профиль
  waf_core_rule_set = {
    "inbound_anomaly_score" : 25,
    "is_blocking" : false,
    "is_enabled" : true,
    "paranoia_level" : 3,
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
  security_rules = [
    {
      name     = "smart-protection"
      priority = 99999
      smart_protection = {
        mode = "FULL"
      }
    },
    {
      name     = "waf-protection"
      priority = 88888
      waf = {
        mode = "FULL"
      }
    },
    {
      name     = "allow-specific-hosts"
      priority = 500
      rule_condition = {
        action = "ALLOW"
        condition = {
          authority = {
            authorities = [
              {
                exact_match = "example.com"
              },
              {
                exact_match = "api.example.com"
              }
            ]
          }
        }
      }
    },
    {
      name     = "block-delete-methods"
      priority = 1000
      rule_condition = {
        action = "DENY"
        condition = {
          http_method = {
            http_methods = [
              {
                exact_match = "DELETE"
              },
              {
                exact_match = "PUT"
              }
            ]
          }
        }
      }
    }
  ]
}
