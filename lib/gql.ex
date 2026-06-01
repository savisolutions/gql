defmodule GQL do
  @moduledoc """
  Simple GraphQL client.
  """

  @doc """
  Returns Finch `transport_opts` that keep full TLS verification while tolerating
  Erlang/OTP's overly strict extended key usage validation (CVE-2024-53846).

  Recent OTP releases (25.3.2.8+, 26.2+, 27.0+) reject otherwise-valid certificate
  chains whose intermediate CA carries an `extendedKeyUsage` extension, failing the
  handshake with `{:tls_alert, {:unsupported_certificate, ...key_usage_mismatch...}}`
  (see https://github.com/erlang/otp/issues/9329). These opts perform normal peer
  verification — trusted-root chain validation, certificate expiry, and hostname
  matching are all still enforced — but a custom `verify_fun` ignores *only* the
  spurious `:key_usage_mismatch` error. This keeps MITM protection intact, unlike
  `verify: :verify_none`.

  Intended for use with the `:finch_pools` application config:

      config :gql,
        finch_pools: %{
          default: [conn_opts: [transport_opts: GQL.lenient_eku_transport_opts()]]
        }

  Extra ssl options can be appended via `extra` (they take precedence on conflict).
  """
  @spec lenient_eku_transport_opts(keyword()) :: keyword()
  def lenient_eku_transport_opts(extra \\ []) do
    Keyword.merge(
      [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ],
        verify_fun: {&__MODULE__.verify_ignoring_eku_mismatch/3, []}
      ],
      extra
    )
  end

  @doc """
  `verify_fun` used by `lenient_eku_transport_opts/1`. Accepts only the spurious
  `:key_usage_mismatch` error (CVE-2024-53846); every other certificate problem is
  still rejected.
  """
  @spec verify_ignoring_eku_mismatch(
          :public_key.der_encoded() | :public_key.combined_cert(),
          {:bad_cert, term()} | {:extension, term()} | :valid | :valid_peer,
          term()
        ) :: {:valid, term()} | {:fail, term()} | {:unknown, term()}
  def verify_ignoring_eku_mismatch(_cert, {:bad_cert, {:key_usage_mismatch, _}}, state),
    do: {:valid, state}

  def verify_ignoring_eku_mismatch(_cert, {:bad_cert, reason}, _state), do: {:fail, reason}
  def verify_ignoring_eku_mismatch(_cert, {:extension, _}, state), do: {:unknown, state}
  def verify_ignoring_eku_mismatch(_cert, :valid, state), do: {:valid, state}
  def verify_ignoring_eku_mismatch(_cert, :valid_peer, state), do: {:valid, state}

  defmodule Behaviour do
    @moduledoc """
    Behaviour that `GQL` implements.
    """

    @callback query!(String.t(), keyword()) :: {map(), Mint.Types.headers()}
    @callback query(String.t(), keyword()) ::
                {:ok, map(), Mint.Types.headers()} | {:error, map, Mint.Types.headers()}
  end

  @behaviour Behaviour

  defmodule ConnectionError do
    @moduledoc """
    Error raised when a connection error occurs. See `Mint.TransportError` for list of possible
    values for the `reason` field.
    """

    defexception [:reason]

    def message(exception) do
      inspect(exception)
    end
  end

  defmodule GraphQLError do
    @moduledoc """
    Error raised when response contains GraphQL errors.
    """

    defexception [:body]

    def message(exception), do: inspect(exception)
  end

  defmodule ServerError do
    @moduledoc """
    Error raised when server returns 5xx HTTP status code.
    """

    defexception [:response, :status]

    def message(exception), do: "Server responded with HTTP status: #{exception.status}"
  end

  @query_opts_validation [
    finch_mod: [
      type: :atom,
      default: Finch,
      doc: false
    ],
    headers: [
      type: {:list, :any},
      default: [],
      doc: "HTTP headers to include."
    ],
    http_options: [
      type: :keyword_list,
      doc: "Options to be passed to `Finch.request/3`.",
      default: [receive_timeout: 30_000]
    ],
    variables: [
      type: :any,
      default: [],
      doc: "Keyword list or map of variables."
    ],
    url: [
      type: :string,
      required: true,
      doc: "URL to which the request is made."
    ]
  ]

  @doc """
  Like `query/2`, except raises `GQL.GraphQLError` if the server returns errors.
  """
  @impl true
  @spec query!(String.t(), keyword()) :: {map(), Mint.Types.headers()}
  def query!(query, opts) do
    case query(query, opts) do
      {:ok, body, headers} -> {body, headers}
      {:error, body, _headers} -> raise %GraphQLError{body: body}
    end
  end

  @doc """
  Queries a GraphQL endpoint. Returns `{:ok, body, headers}` upon success or `{:error, body,
  headers}` if the response contains an "errors" key.

  An exception will be raised for exceptional errors:

  * `GQL.ConnectionError` if the HTTP client returns a connection error such as a timeout.
  * `GQL.ServerError` if the server responded with a 5xx code.

  ## Options

  #{NimbleOptions.docs(@query_opts_validation)}
  """
  @impl true
  @spec query(String.t(), keyword()) ::
          {:ok, map(), Mint.Types.headers()} | {:error, map, Mint.Types.headers()}
  def query(query, opts) do
    opts = NimbleOptions.validate!(opts, @query_opts_validation)

    body = %{query: query, variables: Map.new(opts[:variables])}
    headers = [{"content-type", "application/json"}] ++ opts[:headers]

    Finch.build(:post, opts[:url], headers, Jason.encode!(body))
    |> opts[:finch_mod].request(GQL.Finch, opts[:http_options])
    |> case do
      {:ok, %Finch.Response{status: status} = resp} when status >= 200 and status < 500 ->
        handle_body(Jason.decode!(resp.body), resp.headers)

      {:ok, %Finch.Response{} = resp} ->
        raise %ServerError{response: resp, status: resp.status}

      {:error, %Mint.TransportError{reason: reason}} ->
        raise %ConnectionError{reason: reason}
    end
  end

  defp handle_body(%{"errors" => _} = body, headers) do
    # Return error if response body contains errors. In this case the HTTP status is inconsistent
    # between different APIs. Github and SpaceX return errors with HTTP 200 status. Shopify
    # returns errors with HTTP 400 status.
    {:error, body, headers}
  end

  defp handle_body(%{} = body, headers) do
    {:ok, body, headers}
  end
end
