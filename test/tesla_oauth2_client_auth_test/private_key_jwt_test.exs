defmodule TeslaOAuth2ClientAuthTest.PrivateKeyJWT do
  use ExUnit.Case

  alias TeslaOAuth2ClientAuth.PrivateKeyJWT

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  test "valid request using client's JWKs" do
    client =
      Tesla.client(
        [
          {PrivateKeyJWT,
           %{
             client_id: "client1",
             client_config: client_config("client1"),
             server_metadata: server_metadata(),
             jwt_sig_alg: "ES256"
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})
    assert result.body["client_assertion_type"] == @assertion_type

    assertion = result.body["client_assertion"]

    jwk = client_config("client1")["jwks"]["keys"] |> List.first() |> JOSE.JWK.from_map()

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["ES256"], assertion)

    content = Jason.decode!(content)

    assert content["iss"] == "client1"
    assert content["sub"] == "client1"
    assert content["aud"] == server_metadata()["token_endpoint"]
    assert is_integer(content["exp"])
    assert is_integer(content["iat"])
    assert is_binary(content["jti"])
  end

  test "jti callback is called" do
    client =
      Tesla.client(
        [
          {PrivateKeyJWT,
           %{
             client_id: "client1",
             client_config: client_config("client1"),
             server_metadata: server_metadata(),
             jwt_sig_alg: "ES256",
             jwt_jti_callback: &TeslaOAuth2ClientAuthTest.Callback.jti_callback/1
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})

    assertion = result.body["client_assertion"]

    jwk = client_config("client1")["jwks"]["keys"] |> List.first() |> JOSE.JWK.from_map()

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["ES256"], assertion)

    content = Jason.decode!(content)

    assert content["jti"] == "some_generated_jti"
  end

  test "additional claims are added" do
    client =
      Tesla.client(
        [
          {PrivateKeyJWT,
           %{
             client_id: "client1",
             client_config: client_config("client1"),
             server_metadata: server_metadata(),
             jwt_sig_alg: "ES256",
             jwt_additional_claims: %{"some_claim" => "some_value"}
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})

    assertion = result.body["client_assertion"]

    jwk = client_config("client1")["jwks"]["keys"] |> List.first() |> JOSE.JWK.from_map()

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["ES256"], assertion)

    content = Jason.decode!(content)

    assert content["some_claim"] == "some_value"
  end

  test "raises on missing client id" do
    client =
      Tesla.client(
        [{PrivateKeyJWT, %{client_config: client_config("client1")}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config key" do
    client =
      Tesla.client(
        [{PrivateKeyJWT, %{client_id: "client1"}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config data" do
    client =
      Tesla.client(
        [{PrivateKeyJWT, %{client_id: "client1", client_config: %{}}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  defp client_config("client1") do
    %{
      "token_endpoint_auth_signing_alg" => "ES256",
      "jwks" => %{
        "keys" => [
          %{
            "crv" => "P-256",
            "d" => "bZa5NEa3OuDAxNs5LvpwPsYHBj0Tmkhr_dzynwUsarI",
            "kty" => "EC",
            "x" => "OpLxw9HqCn50523Rg6s59yE089s7f89HpAgMe9bn6RU",
            "y" => "nzMjJbOdAHQOVIT9KJXJCve_SVRC_3hIvmaX-fnze5g"
          }
        ]
      }
    }
  end

  defp server_metadata() do
    %{
      "token_endpoint" => "https://www.example.com/auth/token",
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"]
    }
  end
end
