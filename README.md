# cloud

A small command line client for cloud provider APIs.

## Commands

Acquire temporary Aliyun STS credentials with `AssumeRole`:

```sh
cloud aliyun sts --role-arn 'acs:ram::1234567890123456:role/example'
```

The command prints the Aliyun STS JSON response, including the temporary
`AccessKeyId`, `AccessKeySecret`, and `SecurityToken`.

Generate a time-based one-time password for multi-factor authentication:

```sh
cloud mfa 'JBSWY3DPEHPK3PXP'
```

```text
--digits <DIGITS>                default: 6
--period <SECONDS>               default: 30
--algorithm <ALGORITHM>          default: sha1 (sha1, sha256, sha512)
```

STS settings are command arguments:

```text
--role-arn <ARN>                 required
--endpoint <ENDPOINT>            default: sts.aliyuncs.com
--role-session-name <NAME>       default: cloud
--duration <DURATION>            default: 1h (e.g. 12m, 12s, 1d)
--external-id <ID>
--policy <JSON>
```

## Configuration

The CLI first tries to load `~/.config/cloud/config.yaml` (or
`$XDG_CONFIG_HOME/cloud/config.yaml`). A missing file is allowed. Use
`--config <PATH>` or `CLOUD_CONFIG` to choose another path.

```yaml
aliyun:
  access_key_id: your-access-key-id
  access_key_secret: your-access-key-secret
```

Environment variables override the file. Nested settings can use the `CLOUD_`
prefix and a double underscore between path segments:

```sh
export CLOUD_ALIYUN__ACCESS_KEY_ID=your-access-key-id
export CLOUD_ALIYUN__ACCESS_KEY_SECRET=your-access-key-secret
```

Conventional names are also accepted:

```text
ALIYUN_ACCESS_KEY_ID
ALIYUN_ACCESS_KEY_SECRET
```

`ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET` are accepted
for credentials as well.
