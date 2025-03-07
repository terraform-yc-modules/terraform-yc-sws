output "waf_profile_id" {
  description = "ID созданного WAF профиля."
  value       = try(yandex_sws_waf_profile.this[0].id, null)
}
output "security_profile_id" {
  description = "The ID of the created security profile."
  value       = yandex_sws_security_profile.this.id
}

output "arl_profile_id" {
  description = "The ID of the created ARL profile."
  value       = try(yandex_sws_advanced_rate_limiter_profile.this[0].id, null)
}
