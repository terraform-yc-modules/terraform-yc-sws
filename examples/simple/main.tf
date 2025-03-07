module "yandex_sws" {
  source = "../../"
  name   = "simple"

  # Профиль безопасности


  security_rules = [
    {
      name     = "smart-protection"
      priority = 99999
      smart_protection = {
        mode = "API"
      }
    }
  ]
  default_action = "DENY"
}
