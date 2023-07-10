# Access Control List

Access Control List (ACL) provides a more fine-grained approach to authorization. It defines rules that are matched from top to bottom. Once a rule is matched, its permission is applied, and the remaining rules are ignored.

## Configuration Items

| Name     | Type           | Required | Description                                  |
| -------- | -------------- | -------- | -------------------------------------------- |
| permit   | enum           | Yes      | permission: `allow` ,`deny`                  |
| action   | enum           | No       | operation : `publish`, `subscribe`, `pubsub` |
| topics   | Array[String]  | No       | Array of Topic                               |
| username | String         | No       | Username: "`#`" means all users              |
| clientid | String         | No       | ClientID: "`#`" means all client IDs         |
| and      | Array[Object]  | No       | `AND` operator                               |
| or       | Array[Object]  | No       | `OR` operator                                |

## Configuration Example

This configuration defines various rules for different users and topics, providing a flexible mechanism for managing permissions. Please write the rules in the correct format into the `nanomq_acl.conf` file and `include` it in `nanomq.conf`, as described in the [Access Control Introduction](introduction.md). 
example:
`acl = {include "/etc/nanomq_acl.conf"}`

```bash
rules = [
  ## Allow MQTT client using username "dashboard"  to subscribe to "$SYS/#" topics
  {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

  ## Deny "All Users" subscribe to "$SYS/#" "#" Topics
  {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

  ## Allow any other publish/subscribe operation
  {"permit": "allow"}
]
```

## Configure in KV format

Users wishing to use the KV configuration format can refer to the following structure and write their configurations into the `nanomq_old.conf` file. The relevant settings will take effect after NanoMQ is restarted. 

- For a complete list of configuration options, refer to [Configuration Description - v013](../config-description/v013.md)

**Syntax:**

```bash
acl.rule.<No>=<Spec>
```

**Example**

```bash
## Allow MQTT client using username "dashboard"  to subscribe to "$SYS/#" topics
acl.rule.1={"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}

## Deny "All Users" subscribe to "$SYS/#" "#" Topics
acl.rule.2={"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}

## Allow any other publish/subscribe operation
acl.rule.3={"permit": "allow"}
```

