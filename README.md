# TeslaOAuth2ClientAuth

[Tesla](https://github.com/teamon/tesla) middlewares for OAuth2 and OpenID Connect client
authentication

## Installation


```elixir
def deps do
  [
    {:tesla_oauth2_client_auth, "~> 0.2.0"}
  ]
end
```

## Support

|          Method         |                Implementation             | Protocol       |
|:-----------------------:|:-----------------------------------------:|:--------------:|
| `"none"`                | `TeslaOAuth2ClientAuth.None`              | OAuth2         |
| `"client_secret_basic"` | `TeslaOAuth2ClientAuth.ClientSecretBasic` | OAuth2         |
| `"client_secret_post"`  | `TeslaOAuth2ClientAuth.ClientSecretPost`  | OAuth2         |
| `"client_secret_jwt"`   | `TeslaOAuth2ClientAuth.ClientSecretJWT`   | OpenID Connect |
| `"private_key_jwt"`     | `TeslaOAuth2ClientAuth.PrivateKeyJWT`     | OpenID Connect |
