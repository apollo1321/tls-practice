#include <CLI/CLI.hpp>

#include <fmt/color.h>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>

#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

template <class Callback>
struct OnScopeExit {
  explicit OnScopeExit(Callback callback) noexcept : callback(std::move(callback)) {
  }

  ~OnScopeExit() {
    callback();
  }

  struct MacroHelper {
    template <class T>
    auto operator|(T callback) {
      return OnScopeExit<T>(std::move(callback));
    }
  };

  Callback callback;
};

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#define DEFER auto CAT(defer_, __LINE__) = OnScopeExit<int>::MacroHelper{} | [&]()

std::string MakeGetHttpRequest(std::string_view host, std::string_view resource) {
  return fmt::format(
      "GET {} HTTP/1.1\r\n"
      "Host: {}\r\n"
      "Connection: close\r\n\r\n",
      resource, host);
}

void SendRequestToServer(std::string_view host, std::string_view resource, int tls_version,
                         std::string_view ciphersuites, std::string_view keylog_path,
                         bool print_chain) {
  //============================================================================
  // Log config
  //============================================================================

  fmt::print(fmt::emphasis::bold, "Config:\n");
  fmt::print("\tHost: {}\n", host);
  fmt::print("\tResourse: {}\n", resource);
  fmt::print("\tTLS: {}\n", tls_version == TLS1_2_VERSION ? "1.2" : "1.3");
  if (!ciphersuites.empty()) {
    fmt::print("\tCiphersuites: {}\n", ciphersuites);
  }
  if (!keylog_path.empty()) {
    fmt::print("\tKeylog path: {}\n", keylog_path);
  }
  fmt::print("\n");

  //============================================================================
  // Set up ssl context
  //============================================================================

  SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!ssl_ctx) {
    throw std::runtime_error("could not create ssl context");
  }
  DEFER {
    SSL_CTX_free(ssl_ctx);
  };

  BIO* keylog_out{};
  if (!keylog_path.empty()) {
    keylog_out = BIO_new_file(keylog_path.data(), "a");
    SSL_CTX_set_app_data(ssl_ctx, keylog_out);
    SSL_CTX_set_keylog_callback(ssl_ctx, [](const SSL* ssl, const char* line) {
      SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
      BIO* keylog_out = static_cast<BIO*>(SSL_CTX_get_app_data(ssl_ctx));
      BIO_puts(keylog_out, line);
      BIO_puts(keylog_out, "\n");
    });
  }
  DEFER {
    BIO_free(keylog_out);
  };

  if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
    throw std::runtime_error("cannot set up trust ca");
  }

  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);

  if (!SSL_CTX_set_min_proto_version(ssl_ctx, tls_version) ||
      !SSL_CTX_set_max_proto_version(ssl_ctx, tls_version)) {
    throw std::runtime_error("could not select tls version in context");
  }

  if (!ciphersuites.empty()) {
    int ret = 0;
    if (tls_version == TLS1_3_VERSION) {
      ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites.data());
    } else {
      ret = SSL_CTX_set_cipher_list(ssl_ctx, ciphersuites.data());
    }
    if (!ret) {
      throw std::runtime_error("cannot use selected ciphersuites");
    }
  }

  //============================================================================
  // Resolving host && connecting to endpoint
  //============================================================================

  BIO* bio = BIO_new_connect((std::string(host) + ":443").data());
  DEFER {
    BIO_free(bio);
  };

  if (BIO_do_connect(bio) <= 0) {
    ERR_print_errors_fp(stdout);
    throw std::runtime_error("connection error");
  }

  fmt::print(fmt::emphasis::bold, "Connected to: {}:{}\n\n",
             BIO_ADDR_hostname_string(BIO_get_conn_address(bio), 1), BIO_get_conn_port(bio));

  //============================================================================
  // Performing handshake
  //============================================================================

  BIO* ssl_bio = BIO_new_ssl(ssl_ctx, 1);
  DEFER {
    BIO_free(ssl_bio);
  };
  BIO_push(ssl_bio, bio);

  SSL* ssl{};
  BIO_get_ssl(ssl_bio, &ssl);
  BIO_up_ref(ssl_bio);
  SSL_set_tlsext_host_name(ssl, host.data());
  DEFER {
    SSL_free(ssl);
  };

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  if (BIO_do_handshake(ssl_bio) <= 0) {
    ERR_print_errors_fp(stdout);
    throw std::runtime_error("handshake error");
  }

  int err = SSL_get_verify_result(ssl);
  if (err != X509_V_OK) {
    throw std::runtime_error(
        fmt::format("Certificate verification error: {}", X509_verify_cert_error_string(err)));
  }
  if (!SSL_get_peer_certificate(ssl)) {
    throw std::runtime_error("No certificate was presented by the server\n");
  }

  fmt::print(fmt::emphasis::bold, "Handshake has been completed\n");
  fmt::print("{}: {}\n\n", fmt::styled("Cipher", fmt::emphasis::bold),
             SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

  if (print_chain) {
    stack_st_X509* chain = SSL_get0_verified_chain(ssl);
    fmt::print(fmt::emphasis::bold, "Certificate chain:\n");
    for (int i = 0; i < sk_X509_num(chain); ++i) {
      X509* cert = sk_X509_value(chain, i);
      if (!cert) {
        throw std::runtime_error("unexpected state");
      }
      X509_print_fp(stdout, cert);
    }
  }

  fmt::print("\n");

  //============================================================================
  // Performing request
  //============================================================================

  auto request = MakeGetHttpRequest(host, resource);
  fmt::print(fmt::emphasis::bold, "Sending request:\n");
  fmt::print("{}\n", request);

  if (BIO_puts(ssl_bio, request.data()) <= 0) {
    fmt::print("Error while sending request to server\n");
    ERR_print_errors_fp(stdout);
    throw std::runtime_error("error while sending request");
  }
  BIO_flush(ssl_bio);

  //============================================================================
  // Reading response
  //============================================================================

  std::array<uint8_t, 2048> buffer;
  std::string response;
  while (true) {
    int len = BIO_read(ssl_bio, buffer.data(), buffer.size());
    if (len <= 0) {
      break;
    }
    response.insert(response.end(), buffer.begin(), buffer.begin() + len);
  }

  fmt::print(fmt::emphasis::bold, "Received response:\n");
  fmt::print("{}\n", response);

  //============================================================================
  // Shutdown
  //============================================================================

  fmt::print(fmt::emphasis::bold, "Start graceful shutdown\n");
  BIO_ssl_shutdown(ssl_bio);

  if (ERR_peek_error()) {
    fmt::print(fmt::emphasis::bold, "Errors while shutdown\n:");
    ERR_print_errors_fp(stdout);
  }
}

void ListSupportedCiphers(int tls_version) {
  SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!ssl_ctx) {
    throw std::runtime_error("cannot create SSL ctx");
  }
  DEFER {
    SSL_CTX_free(ssl_ctx);
  };

  if (!SSL_CTX_set_min_proto_version(ssl_ctx, tls_version) ||
      !SSL_CTX_set_max_proto_version(ssl_ctx, tls_version)) {
    throw std::runtime_error("cannot set ctx SSL version");
  }

  SSL* ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    throw std::runtime_error("cannot create SSL connection");
  }
  DEFER {
    SSL_free(ssl);
  };

  stack_st_SSL_CIPHER* ciphers = SSL_get1_supported_ciphers(ssl);
  if (!ciphers) {
    throw std::runtime_error("cannot get supported ciphers");
  }
  DEFER {
    sk_SSL_CIPHER_free(ciphers);
  };

  std::vector<std::string> result;

  fmt::print(fmt::emphasis::bold, "Ciphersuites for TLS {}:\n",
             tls_version == TLS1_2_VERSION ? "1.2" : "1.3");
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
    auto cipher = sk_SSL_CIPHER_value(ciphers, i);
    if (!cipher) {
      throw std::runtime_error("unexpected state");
    }
    char* descr = SSL_CIPHER_description(cipher, nullptr, 0);
    fmt::print("{}", descr);
    DEFER {
      OPENSSL_free(descr);
    };
    result.emplace_back(descr);
  }
}

int main(int argc, char** argv) {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  try {
    CLI::App app{"Simple https client"};

    std::string host;
    auto* host_opt = app.add_option("host", host, "target host");

    std::string tls_version_str;
    app.add_option("-v", tls_version_str, "set TLS version")
        ->check(CLI::IsMember{{"tls1_2", "tls1_3"}})
        ->default_val("tls1_3");

    std::string ciphersuites;
    app.add_option("-c,--ciphersuites", ciphersuites, "set list of ciphersuites separated by ':'");

    bool list_ciphers{};
    app.add_flag("-l,--list", list_ciphers, "list supported ciphersuites for given tls");

    std::string resource;
    app.add_option("-r,--resource", resource, "http get resource")->default_val("/");

    std::string key_path;
    app.add_option("-k,--keylogfile", key_path, "path to key log");

    bool print_chain{};
    app.add_flag("--chain", print_chain, "print tls connection certificate chain");

    CLI11_PARSE(app, argc, argv);

    int tls_version = tls_version_str == "tls1_2" ? TLS1_2_VERSION : TLS1_3_VERSION;

    if (list_ciphers) {
      ListSupportedCiphers(tls_version);
    } else {
      if (host.empty()) {
        return app.exit(CLI::RequiredError("host"), std::cerr, std::cerr);
      }

      SendRequestToServer(host, resource, tls_version, ciphersuites, key_path, print_chain);
    }

  } catch (std::exception& e) {
    fmt::print(fmt::fg(fmt::terminal_color::red) | fmt::emphasis::bold, "Error: {}\n", e.what());
    return 1;
  }

  fmt::print("\n");

  return 0;
}
