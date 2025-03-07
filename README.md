# Smart Web Security (SWS) Terraform module for Yandex.Cloud

## Features

- Create WAF and ARL profiles
- Create security profile
- You can use your own Captcha ID, or default one from Yandex Cloud will be used
- See different [examples](examples/)
  
### Condition block structure (used in smart_protection, waf, and rule_condition, advanced_rate_limiter_rules) [source link](https://github.com/yandex-cloud/cloudapi/blob/master/yandex/cloud/smartwebsecurity/v1/security_profile.proto):

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

### How to Configure Terraform for Yandex.Cloud

- Install [YC CLI](https://cloud.yandex.com/docs/cli/quickstart)
- Add environment variables for terraform authentication in Yandex.Cloud

```
export YC_TOKEN=$(yc iam create-token)
export YC_CLOUD_ID=$(yc config get cloud-id)
export YC_FOLDER_ID=$(yc config get folder-id)
```

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_yandex"></a> [yandex](#requirement\_yandex) | >= 0.101.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_yandex"></a> [yandex](#provider\_yandex) | 0.139.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [yandex_sws_advanced_rate_limiter_profile.this](https://registry.terraform.io/providers/yandex-cloud/yandex/latest/docs/resources/sws_advanced_rate_limiter_profile) | resource |
| [yandex_sws_security_profile.this](https://registry.terraform.io/providers/yandex-cloud/yandex/latest/docs/resources/sws_security_profile) | resource |
| [yandex_sws_waf_profile.this](https://registry.terraform.io/providers/yandex-cloud/yandex/latest/docs/resources/sws_waf_profile) | resource |
| [yandex_client_config.client](https://registry.terraform.io/providers/yandex-cloud/yandex/latest/docs/data-sources/client_config) | data source |
| [yandex_sws_waf_rule_set_descriptor.rule_set](https://registry.terraform.io/providers/yandex-cloud/yandex/latest/docs/data-sources/sws_waf_rule_set_descriptor) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_advanced_rate_limiter_rules"></a> [advanced\_rate\_limiter\_rules](#input\_advanced\_rate\_limiter\_rules) | List of ARL rules with quotas and conditions. | <pre>list(object({<br/>    name        = string<br/>    priority    = number<br/>    description = optional(string)<br/>    dry_run     = optional(bool)<br/><br/>    static_quota = optional(object({<br/>      action = string<br/>      limit  = number<br/>      period = number<br/>      condition = optional(object({<br/>        authority = optional(object({<br/>          authorities = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        http_method = optional(object({<br/>          http_methods = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        request_uri = optional(object({<br/>          path = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>          queries = optional(list(object({<br/>            key = string<br/>            value = optional(object({<br/>              exact_match          = optional(string)<br/>              exact_not_match      = optional(string)<br/>              prefix_match         = optional(string)<br/>              prefix_not_match     = optional(string)<br/>              pire_regex_match     = optional(string)<br/>              pire_regex_not_match = optional(string)<br/>            }))<br/>          })))<br/>        }))<br/>        headers = optional(list(object({<br/>          name = string<br/>          value = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        })))<br/>        source_ip = optional(object({<br/>          ip_ranges_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          ip_ranges_not_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          geo_ip_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>          geo_ip_not_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>        }))<br/>      }))<br/>    }))<br/><br/>    dynamic_quota = optional(object({<br/>      action = string<br/>      limit  = number<br/>      period = number<br/>      condition = optional(object({<br/>        authority = optional(object({<br/>          authorities = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        http_method = optional(object({<br/>          http_methods = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        request_uri = optional(object({<br/>          path = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>          queries = optional(list(object({<br/>            key = string<br/>            value = optional(object({<br/>              exact_match          = optional(string)<br/>              exact_not_match      = optional(string)<br/>              prefix_match         = optional(string)<br/>              prefix_not_match     = optional(string)<br/>              pire_regex_match     = optional(string)<br/>              pire_regex_not_match = optional(string)<br/>            }))<br/>          })))<br/>        }))<br/>        headers = optional(list(object({<br/>          name = string<br/>          value = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        })))<br/>        source_ip = optional(object({<br/>          ip_ranges_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          ip_ranges_not_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          geo_ip_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>          geo_ip_not_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>        }))<br/>      }))<br/>      characteristics = list(object({<br/>        case_insensitive = optional(bool)<br/>        simple_characteristic = optional(object({<br/>          type = string<br/>        }))<br/>        key_characteristic = optional(object({<br/>          type  = string<br/>          value = string<br/>        }))<br/>      }))<br/>    }))<br/>  }))</pre> | `[]` | no |
| <a name="input_arl_enabled"></a> [arl\_enabled](#input\_arl\_enabled) | Advanced Rate Limiter enabled flag. | `bool` | `false` | no |
| <a name="input_captcha_id"></a> [captcha\_id](#input\_captcha\_id) | Captcha ID (optional). Set empty to use default. | `string` | `null` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | Default action (ALLOW or DENY). | `string` | `"ALLOW"` | no |
| <a name="input_description"></a> [description](#input\_description) | Description for SWS resources. | `string` | `null` | no |
| <a name="input_folder_id"></a> [folder\_id](#input\_folder\_id) | Folder for SWS resources. | `string` | `null` | no |
| <a name="input_labels"></a> [labels](#input\_labels) | Labels for resources. | `map(string)` | <pre>{<br/>  "created_by": "terraform-yc-module"<br/>}</pre> | no |
| <a name="input_name"></a> [name](#input\_name) | Name for resources. | `string` | `"testy"` | no |
| <a name="input_security_rules"></a> [security\_rules](#input\_security\_rules) | List of security rules for the Security Profile resource.<br/><br/>Each rule object supports:<br/><br/>- name (string, required): Name of the security rule.<br/>- priority (number, required): Priority of the rule. Higher priority rules processed earlier.<br/><br/>Exactly one of the following blocks may be specified per rule:<br/><br/>1. smart\_protection block (optional):<br/>    - mode (string, required): Protection mode. Possible values: "FULL", "API".<br/>    - condition block (optional): Conditions when this protection is applied (see detailed structure below).<br/><br/>2. waf block (optional):<br/>    - mode (string, required): WAF mode. Possible values: "FULL", "API".<br/>    - waf\_profile\_id (string, required): Associated WAF profile ID.<br/>    - condition block (optional): Conditions when WAF rules are applied (see detailed structure below).<br/><br/>3. rule\_condition block (optional):<br/>    - action (string, required): Action to perform if condition matches. Possible values: "ALLOW", "DENY".<br/>    - condition block (optional): Conditions when this action is applied (see detailed structure below).<br/><br/>Condition block structure (used in smart\_protection, waf, and rule\_condition):<br/><br/>- authority block (optional):<br/>    - authorities (list of objects with attribute)<br/><br/>- http\_method block (optional):<br/>    - http\_methods (list of objects with attribute)<br/><br/>- request\_uri block (optional):<br/>    - path block (optional)<br/><br/>    - queries (optional, list):<br/>        - key (string, required): Query string key.<br/>        - value block (optional)<br/><br/>- headers (optional, list):<br/>    - name (string, required): HTTP header name.<br/>    - value block (optional)<br/><br/>- source\_ip block (optional):<br/>    - ip\_ranges\_match block (optional):<br/>        - ip\_ranges (list of strings, optional): IP ranges to match.<br/>    - ip\_ranges\_not\_match block (optional):<br/>        - ip\_ranges (list of strings, optional): IP ranges to exclude.<br/>    - geo\_ip\_match block (optional):<br/>        - locations (list of strings, optional): ISO country codes to match.<br/>    - geo\_ip\_not\_match block (optional):<br/>        - locations (list of strings, optional): ISO country codes to exclude. | <pre>list(object({<br/>    name     = string<br/>    priority = number<br/><br/>    smart_protection = optional(object({<br/>      mode = string<br/>      condition = optional(object({<br/>        authority = optional(object({<br/>          authorities = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        http_method = optional(object({<br/>          http_methods = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        request_uri = optional(object({<br/>          path = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>          queries = optional(list(object({<br/>            key = string<br/>            value = optional(object({<br/>              exact_match          = optional(string)<br/>              exact_not_match      = optional(string)<br/>              prefix_match         = optional(string)<br/>              prefix_not_match     = optional(string)<br/>              pire_regex_match     = optional(string)<br/>              pire_regex_not_match = optional(string)<br/>            }))<br/>          })))<br/>        }))<br/>        headers = optional(list(object({<br/>          name = string<br/>          value = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        })))<br/>        source_ip = optional(object({<br/>          ip_ranges_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          ip_ranges_not_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          geo_ip_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>          geo_ip_not_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>        }))<br/>      }))<br/>    }), null)<br/><br/>    waf = optional(object({<br/>      mode = string<br/>      condition = optional(object({<br/>        authority = optional(object({<br/>          authorities = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        http_method = optional(object({<br/>          http_methods = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        request_uri = optional(object({<br/>          path = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>          queries = optional(list(object({<br/>            key = string<br/>            value = optional(object({<br/>              exact_match          = optional(string)<br/>              exact_not_match      = optional(string)<br/>              prefix_match         = optional(string)<br/>              prefix_not_match     = optional(string)<br/>              pire_regex_match     = optional(string)<br/>              pire_regex_not_match = optional(string)<br/>            }))<br/>          })))<br/>        }))<br/>        headers = optional(list(object({<br/>          name = string<br/>          value = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        })))<br/>        source_ip = optional(object({<br/>          ip_ranges_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          ip_ranges_not_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          geo_ip_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>          geo_ip_not_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>        }))<br/>      }))<br/>    }), null)<br/><br/>    rule_condition = optional(object({<br/>      action = string<br/>      condition = optional(object({<br/>        authority = optional(object({<br/>          authorities = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        http_method = optional(object({<br/>          http_methods = list(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        }))<br/>        request_uri = optional(object({<br/>          path = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>          queries = optional(list(object({<br/>            key = string<br/>            value = optional(object({<br/>              exact_match          = optional(string)<br/>              exact_not_match      = optional(string)<br/>              prefix_match         = optional(string)<br/>              prefix_not_match     = optional(string)<br/>              pire_regex_match     = optional(string)<br/>              pire_regex_not_match = optional(string)<br/>            }))<br/>          })))<br/>        }))<br/>        headers = optional(list(object({<br/>          name = string<br/>          value = optional(object({<br/>            exact_match          = optional(string)<br/>            exact_not_match      = optional(string)<br/>            prefix_match         = optional(string)<br/>            prefix_not_match     = optional(string)<br/>            pire_regex_match     = optional(string)<br/>            pire_regex_not_match = optional(string)<br/>          }))<br/>        })))<br/>        source_ip = optional(object({<br/>          ip_ranges_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          ip_ranges_not_match = optional(object({<br/>            ip_ranges = list(string)<br/>          }))<br/>          geo_ip_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>          geo_ip_not_match = optional(object({<br/>            locations = list(string)<br/>          }))<br/>        }))<br/>      }))<br/>    }), null)<br/><br/>  }))</pre> | `[]` | no |
| <a name="input_waf_analyze_request_body"></a> [waf\_analyze\_request\_body](#input\_waf\_analyze\_request\_body) | Analyze request body settings. | <pre>object({<br/>    is_enabled        = bool<br/>    size_limit        = optional(number)<br/>    size_limit_action = optional(string)<br/>  })</pre> | <pre>{<br/>  "is_enabled": false<br/>}</pre> | no |
| <a name="input_waf_core_rule_set"></a> [waf\_core\_rule\_set](#input\_waf\_core\_rule\_set) | Basic rule set settings. | <pre>object({<br/>    inbound_anomaly_score = number<br/>    paranoia_level        = number<br/>    rule_set_name         = string<br/>    rule_set_version      = string<br/>    is_enabled            = bool<br/>    is_blocking           = bool<br/>  })</pre> | <pre>{<br/>  "inbound_anomaly_score": 25,<br/>  "is_blocking": false,<br/>  "is_enabled": true,<br/>  "paranoia_level": 1,<br/>  "rule_set_name": "OWASP Core Ruleset",<br/>  "rule_set_version": "4.0.0"<br/>}</pre> | no |
| <a name="input_waf_exclusion_rules"></a> [waf\_exclusion\_rules](#input\_waf\_exclusion\_rules) | List of exclusion rules. | <pre>list(object({<br/>    name         = string<br/>    description  = optional(string)<br/>    log_excluded = optional(bool)<br/>    exclude_rules = optional(object({<br/>      exclude_all = optional(bool)<br/>      rule_ids    = optional(list(string))<br/>    }))<br/>  }))</pre> | `[]` | no |
| <a name="input_waf_rules"></a> [waf\_rules](#input\_waf\_rules) | Additional rules for WAF profile. | <pre>list(object({<br/>    rule_id     = string<br/>    is_enabled  = bool<br/>    is_blocking = bool<br/>  }))</pre> | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arl_profile_id"></a> [arl\_profile\_id](#output\_arl\_profile\_id) | The ID of the created ARL profile. |
| <a name="output_security_profile_id"></a> [security\_profile\_id](#output\_security\_profile\_id) | The ID of the created security profile. |
| <a name="output_waf_profile_id"></a> [waf\_profile\_id](#output\_waf\_profile\_id) | ID созданного WAF профиля. |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
