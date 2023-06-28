# WebHook

NanoMQ 提供了可拓展到事件驱动型 WebHook 接口，用户可通过规则配置 WebHook 的触发事件或消息主题。Webhook 的配置文件位于 `etc/nanomq.conf`，具体配置项可查看[配置说明](../config-description/v014.md)。

## 启用 Webhook
添加 webhook 对应的选项到 `etc/nanomq.conf` 即可, 如下：

```bash
webhook {
    ......
}
```
**📢 注意** NanoMQ 从0.18开始，已删除 `enable` 选项，所以此处如果想要启用 `webhook` 的配置，只要将该模块加入配置文件中即可，如上。

## WebHook 规则

Webhook 触发规则是一个 JSON 字符串，其中可用的 Key 有：

- event ：字符串，取固定值
- topic ：字符串，表示一个主题过滤器，操作的主题只有与该主题匹配才能触发事件的转发

**语法**

```bash
## 格式示例
webhook.events = [
    ## 此处可以添加多条规则
    {
        <Rule>
    }
]
```

**示例**

我们希望将 `a/b/c` 和 `foo/#` 主题下的消息转发到 Web 服务器上，其配置应该为：

```bash
webhook.events = [
	{ 
		event = "on_message_publish"
		topic = "a/b/c"
	}
	{
		event = "on_message_publish"
		topic = "foo/#"
	}
]
```

## 触发事件

Naono目前支持三类触发事件：

| 名称                           | 说明         | 执行时机                     |
| ------------------------------| ------------ | ---------------------------- |
| on_client_connack             | 下发连接应答  | 服务端准备下发连接应答报文时 |
| on_client_disconnected        | 连接断开     | 客户端连接层在准备关闭时     |
| on_message_publish            | 消息发布     | 服务端在发布（路由）消息前   |

## 事件参数

事件触发时 Webhook 会按照配置将每个事件组成一个 HTTP 请求发送到 url 所配置的 Web 服务器上。其请求格式为：

```bash
URL: <url>      # 来自于配置中的 `url` 字段
Method: POST    # 固定为 POST 方法

Body: <JSON>    # Body 为 JSON 格式字符串
```

对于不同的事件，请求 Body 体内容有所不同，下表列举了各个事件中 Body 的参数列表：

**on_client_connack**

| Key       | 类型    | 说明                                        |
| --------- | ------- | ------------------------------------------- |
| action    | string  | 事件名称 固定为："client_connack"           |
| clientid  | string  | 客户端 ClientId                             |
| username  | string  | 客户端 Username，不存在时该值为 "undefined" |
| keepalive | integer | 客户端申请的心跳保活时间                    |
| proto_ver | integer | 协议版本号 （ 3 ｜ 4 ｜ 5 ）                |
| conn_ack  | string  | "success" 表示成功，其它表示失败的原因      |

**on_client_disconnected**

| Key      | 类型   | 说明                                        |
| -------- | ------ | ------------------------------------------- |
| action   | string | 事件名称 固定为："client_disconnected"      |
| clientid | string | 客户端 ClientId                             |
| username | string | 客户端 Username，不存在时该值为 "undefined" |
| reason   | string | 错误原因                                    |

**on_message_publish**

| Key            | 类型    | 说明                                         |
| -------------- | ------- | -------------------------------------------- |
| action         | string  | 事件名称 固定为："message_publish"           |
| from_client_id | string  | 发布端 ClientId                              |
| from_username  | string  | 发布端 Username ，不存在时该值为 "undefined" |
| topic          | string  | 取消订阅的主题                               |
| qos            | enum    | QoS 等级，可取 0、1、2                       |
| retain         | bool    | 是否为保留消息                               |
| payload        | string  | 消息 Payload                                 |
| ts             | integer | 消息的时间戳 (毫秒)                          |

## 配置多条触发规则

NanoMQ 支持通过配置文件定义多条触发规则，本节将通过定义两条 WebHook 触发规则为例进行演示：

- 规则 1: 当有消息发送到 "a/b/c" 主题时，触发 WebHook
- 规则 2：当有客户端连接时，触发 WebHook

示例配置如下：

```bash
webhook.events = [
	url = "http://127.0.0.1:80"
	headers.content-type = "application/json"
	body.encoding = plain
	pool_size = 32

	{ 
		event = "on_message_publish"
		topic = "a/b/c"
	}
	{
		event = "on_client_connack"
	}
]
```

其中，

`event`：WebHook 触发事件，类型为 string，支持的事件包括：

- `on_client_connack`：客户端建立连接
- `on_client_disconnected`：客户端断开连接
- `on_message_publish`：消息发布

`topic`：消息的发布主题，类型为 string