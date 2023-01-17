#ifdef ACL_SUPP
#include "include/acl_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"

static bool
match_rule_content_str(acl_rule_ct *ct, const char *cmp_str)
{
	bool match = false;
	if (ct->type == ACL_RULE_ALL) {
		match = true;
	} else if (ct->type == ACL_RULE_SINGLE_STRING && cmp_str != NULL &&
	    strcmp(ct->value.str, cmp_str) == 0) {
		match = true;
	}
	return match;
}

bool
auth_acl(conf *config, acl_action_type act_type, conn_param *param,
    const char *topic)
{
	conn_param_clone(param);

	conf_acl *acl = &config->acl;

	bool match     = false;
	bool sub_match = true;
	bool result    = false;

	for (size_t i = 0; i < acl->rule_count; i++) {
		acl_rule *      rule   = acl->rules[i];
		acl_action_type action = rule->action;

		if (action != ACL_ALL && action != act_type) {
			continue;
		}

		switch (rule->rule_type) {
		case ACL_USERNAME:
			match = match_rule_content_str(&rule->rule_ct.ct,
			    (const char *) conn_param_get_username(param));
			break;

		case ACL_CLIENTID:
			match = match_rule_content_str(&rule->rule_ct.ct,
			    (const char *) conn_param_get_clientid(param));
			break;

		case ACL_AND:
			for (size_t j = 0; j < rule->rule_ct.array.count;
			     j++) {
				acl_sub_rule *sub_rule =
				    rule->rule_ct.array.rules[j];
				switch (sub_rule->rule_type) {
				case ACL_USERNAME:
					if (!match_rule_content_str(
					        &sub_rule->rule_ct,
					        (const char *)
					            conn_param_get_username(
					                param))) {
						sub_match = false;
						break;
					}
					break;

				case ACL_CLIENTID:
					if (!match_rule_content_str(
					        &sub_rule->rule_ct,
					        (const char *)
					            conn_param_get_clientid(
					                param))) {
						sub_match = false;
						break;
					}
					break;

					// TODO Not supported yet
					// case ACL_IPADDR:
					// 	break;

				default:
					break;
				}
				if (!sub_match) {
					break;
				}
			}
			if (sub_match) {
				match = true;
			}
			break;

		case ACL_OR:
			for (size_t j = 0; j < rule->rule_ct.array.count;
			     j++) {
				acl_sub_rule *sub_rule =
				    rule->rule_ct.array.rules[j];
				switch (sub_rule->rule_type) {
				case ACL_USERNAME:
					match |= match_rule_content_str(
					    &sub_rule->rule_ct,
					    (const char *)
					        conn_param_get_username(
					            param));
					break;

				case ACL_CLIENTID:
					match |= match_rule_content_str(
					    &sub_rule->rule_ct,
					    (const char *)
					        conn_param_get_clientid(
					            param));
					break;

					// TODO Not supported yet
					// case ACL_IPADDR:
					// 	break;

				default:
					break;
				}
				if (match) {
					break;
				}
			}
			break;

			// TODO Not supported yet
			// case ACL_IPADDR:
			// 	break;

		case ACL_NONE:
			match = true;
			break;

		default:
			break;
		}

		if (!match) {
			continue;
		}

		if (rule->topic_count > 0) {
			char **topic_array = rule->topics;
			bool   found       = false;
			for (size_t j = 0;
			     j < rule->topic_count && found != true; j++) {
				if (topic_filter(rule->topics[j], topic)) {
					found = true;
					break;
				}
			}
			if (found == false) {
				match = false;
				continue;
			}
		}

		result = rule->permit == ACL_ALLOW ? match : !match;

		break;
	}

	conn_param_free(param);

	// if (!match && config->acl_nomatch == ACL_ALLOW &&
	//     acl->rule_count > 0) {
	// 	return true;
	// } else {
	// 	return result;
	// }

	if (match) {
		return result;
	} else {
		return config->acl_nomatch == ACL_ALLOW ? true : result;
	}
}
#endif