defmodule TeslaOAuth2ClientAuthTest.ClientSecretPost do
  use ExUnit.Case

  alias TeslaOAuth2ClientAuth.ClientSecretPost

  test "send request with valid credentials" do
    client =
      Tesla.client(
        [{ClientSecretPost, %{client_config: client_config()}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})

    assert result.body["client_id"] == "client1"
    assert result.body["client_secret"] == "some secret"
  end

  test "raises on missing client id" do
    client =
      Tesla.client(
        [{ClientSecretPost, %{client_config: Map.delete(client_config(), "client_id")}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config key" do
    client =
      Tesla.client(
        [{ClientSecretPost, %{client_id: "client1"}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config data" do
    client =
      Tesla.client(
        [{ClientSecretPost, %{client_config: %{}}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises when body is not a map" do
    client =
      Tesla.client(
        [{ClientSecretPost, %{client_config: %{}}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise FunctionClauseError, fn ->
      Tesla.post(client, "/", "binary data")
    end
  end

  defp client_config() do
    %{
      "client_id" => "client1",
      "client_secret" => "some secret"
    }
  end
end
