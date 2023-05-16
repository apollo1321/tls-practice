#include <CLI/CLI.hpp>

#include <asio.hpp>

#include <fmt/color.h>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

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

const auto kSuccessStyle = fmt::fg(fmt::terminal_color::green) | fmt::emphasis::bold;
const auto kWarningStyle = fmt::fg(fmt::terminal_color::yellow) | fmt::emphasis::bold;
const auto kFailStyle = fmt::fg(fmt::terminal_color::red) | fmt::emphasis::bold;
const auto kDebugStyle = fmt::fg(fmt::terminal_color::bright_black);
const auto kHeaderStyle = fmt::fg(fmt::terminal_color::blue) | fmt::emphasis::bold;

void PrintHeader(std::string_view header) {
  fmt::print(kHeaderStyle,
             "=================================\n"
             "{}\n"
             "=================================\n\n",
             header);
}

class HttpsClientApp {
 public:
  HttpsClientApp(std::string host, int tls_version, std::string ciphersuites) noexcept
      : host_{std::move(host)},
        tls_version_{tls_version},
        socket_{io_context_},
        ciphersuites_{std::move(ciphersuites)} {
  }

  void ResolveEndpoints() {
    PrintHeader("Resolving");

    asio::ip::tcp::resolver resolver(io_context_);
    endpoints_ = resolver.resolve(host_, "443");

    fmt::print(kSuccessStyle, "Endpoints have been resolved:\n");

    for (const auto& endpoint : endpoints_) {
      fmt::print("{}\n", fmt::streamed(endpoint.endpoint()));
    }
    fmt::print("\n");
  }

  void ConnectToSomeEndpoint() {
    PrintHeader("Connecting");

    for (const auto& endpoint : endpoints_) {
      fmt::print("Trying connect to: {}\n", fmt::streamed(endpoint.endpoint()));
      asio::error_code errc{};
      socket_.connect(endpoint.endpoint(), errc);
      if (errc) {
        fmt::print(kFailStyle, "Failed: {}\n", errc.message());
      } else {
        fmt::print(kSuccessStyle, "Connected to: {}\n\n", fmt::streamed(endpoint.endpoint()));
        break;
      }
    }

    if (!socket_.is_open()) {
      throw std::runtime_error("could not connect to any endpoint");
    }
  }

  void MakeHandShake() {
    PrintHeader("Handshake");

    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) {
      throw std::runtime_error("could not create ssl context");
    }
    if (!SSL_CTX_set_min_proto_version(ssl_ctx_, tls_version_) ||
        !SSL_CTX_set_max_proto_version(ssl_ctx_, tls_version_)) {
      throw std::runtime_error("could not select tls version in context");
    }

    if (!ciphersuites_.empty()) {
      int ret = 0;
      if (tls_version_ == TLS1_3_VERSION) {
        ret = SSL_CTX_set_ciphersuites(ssl_ctx_, ciphersuites_.data());
      } else {
        ret = SSL_CTX_set_cipher_list(ssl_ctx_, ciphersuites_.data());
      }
      if (!ret) {
        throw std::runtime_error("cannot use selected ciphersuites");
      }
    }

    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) {
      throw std::runtime_error("could not create ssl connection");
    }
    if (!SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE) ||
        !SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)) {
      throw std::runtime_error("could not set ssl mode");
    }

    BIO* int_bio{};
    if (!BIO_new_bio_pair(&int_bio, 0, &ext_bio_, 0)) {
      throw std::runtime_error("could not create bio pair");
    }
    SSL_set_bio(ssl_, int_bio, int_bio);

    HandshakeImpl();
    if (read_begin_ != read_end_) {
      throw std::runtime_error("buffer has not been read completely");
    }

    fmt::print(kSuccessStyle, "\nHandshake has been completed\n");
    char* cipher_descr = SSL_CIPHER_description(SSL_get_current_cipher(ssl_), nullptr, 0);
    DEFER {
      OPENSSL_free(cipher_descr);
    };
    /* fmt::print("{}: {}", fmt::styled("Cipher", fmt::emphasis::bold), cipher_descr); */
    /* SSL_SESSION_print(BIO_new_fp(stdout, BIO_NOCLOSE), SSL_get_session(ssl_)); */
    SSL_SESSION_print_fp(stdout, SSL_get_session(ssl_));
  }

  std::string MakeGetHttpRequest(const std::string& resource) {
    auto request = fmt::format(
        "GET {} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Connection: close\r\n\r\n",
        resource, host_);
  }

  ~HttpsClientApp() {
    BIO_free(ext_bio_);
    SSL_free(ssl_);
    SSL_CTX_free(ssl_ctx_);
  }

 private:
  void HandshakeImpl() {
    auto print_dbg = [](auto&&... values) {
      fmt::print(kDebugStyle, values...);
    };

    while (true) {
      int err = SSL_get_error(ssl_, SSL_connect(ssl_));
      print_dbg("SSL_connect result: {}\n", SSLErrorDescription(err));
      if (BIO_pending(ext_bio_) > 0) {
        int cnt = BIO_read(ext_bio_, write_buffer_.data(), write_buffer_.size());
        if (cnt < 0) {
          throw std::runtime_error("unexpected BIO_read error");
        }
        print_dbg("Start writing {} bytes to socket\n", cnt);
        size_t socket_cnt = asio::write(
            socket_,
            asio::buffer(write_buffer_.data(), std::min<size_t>(cnt, write_buffer_.size())));
        print_dbg("Write {} bytes to socket\n", socket_cnt);
        continue;
      }
      switch (err) {
        case SSL_ERROR_NONE:
          // finished
          return;
        case SSL_ERROR_WANT_READ: {
          if (read_begin_ == read_end_) {
            print_dbg("Start reading some bytes from socket\n");
            size_t cnt = socket_.read_some(asio::buffer(read_buffer_));
            print_dbg("Read {} bytes from socket\n", cnt);
            if (cnt == 0) {
              throw std::runtime_error("cannot read data from socket");
            }
            read_begin_ = 0;
            read_end_ = cnt;
          }
          int bio_cnt =
              BIO_write(ext_bio_, read_buffer_.data() + read_begin_, read_end_ - read_begin_);
          if (bio_cnt <= 0 || bio_cnt > read_end_ - read_begin_) {
            throw std::runtime_error("unexpected BIO_write error");
          }
          read_begin_ += bio_cnt;
          break;
        }
        case SSL_ERROR_WANT_WRITE:
          break;
        default: {
          while (auto err = ERR_get_error()) {
            fmt::print(kFailStyle, "Error: {}::{}\n", ERR_lib_error_string(err),
                       ERR_reason_error_string(err));
          }
          throw std::runtime_error("unexpected SSL error");
        }
      }
    }
  }

  static std::string SSLErrorDescription(int error) {
    switch (error) {
      case SSL_ERROR_NONE:
        return "SSL_ERROR_NONE";
      case SSL_ERROR_ZERO_RETURN:
        return "SSL_ERROR_ZERO_RETURN";
        break;
      case SSL_ERROR_WANT_READ:
        return "SSL_ERROR_WANT_READ";
        break;
      case SSL_ERROR_WANT_WRITE:
        return "SSL_ERROR_WANT_WRITE";
        break;
      case SSL_ERROR_WANT_CONNECT:
        return "SSL_ERROR_WANT_CONNECT";
        break;
      case SSL_ERROR_WANT_ACCEPT:
        return "SSL_ERROR_WANT_ACCEPT";
        break;
      case SSL_ERROR_SYSCALL:
        return "SSL_ERROR_SYSCALL";
        break;
      case SSL_ERROR_SSL:
        return "SSL_ERROR_SSL";
        break;
      default:
        throw std::runtime_error("unknown SSL error " + std::to_string(error));
    }
  }

 private:
  std::string host_;
  int tls_version_{};
  asio::io_context io_context_;
  asio::ip::tcp::socket socket_;
  std::string ciphersuites_;

  asio::ip::tcp::resolver::results_type endpoints_;

  SSL_CTX* ssl_ctx_{};
  SSL* ssl_{};

  BIO* ext_bio_{};

  static constexpr size_t kBufferSize = 2048;

  std::array<uint8_t, kBufferSize> write_buffer_;

  size_t read_begin_{};
  size_t read_end_{};
  std::array<uint8_t, kBufferSize> read_buffer_;
};

std::vector<std::string> GetSupportedCiphers(int tls_version) {
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

  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
    auto cipher = sk_SSL_CIPHER_value(ciphers, i);
    if (!cipher) {
      throw std::runtime_error("unexpected state");
    }
    char* descr = SSL_CIPHER_description(cipher, nullptr, 0);
    DEFER {
      OPENSSL_free(descr);
    };
    result.emplace_back(descr);
  }

  return result;
}

int main(int argc, char** argv) {
  ::SSL_library_init();
  ::SSL_load_error_strings();
  ::OpenSSL_add_all_algorithms();

  try {
    CLI::App app{"Simple https client"};

    std::string host;
    auto* host_opt = app.add_option("host", host, "target host");

    std::string tls_version_str;
    app.add_option("-v", tls_version_str, "set TLS version")
        ->check(CLI::IsMember{{"tls1_2", "tls1_3"}})
        ->default_str("tls1_3");

    std::string ciphersuites;
    app.add_option("-c,--ciphersuites", ciphersuites, "set list of ciphersuites separated by ':'");

    bool list_ciphers{};
    app.add_flag("-l,--list", list_ciphers, "list supported ciphersuites for given tls");

    CLI11_PARSE(app, argc, argv);

    int tls_version = tls_version_str == "tls1_2" ? TLS1_2_VERSION : TLS1_3_VERSION;

    if (list_ciphers) {
      auto ciphers = GetSupportedCiphers(tls_version);
      fmt::print(kSuccessStyle, "Supported ciphers for {}: \n", tls_version_str);
      for (const auto& name : ciphers) {
        fmt::print("{}", name);
      }
    } else {
      if (host.empty()) {
        throw std::runtime_error("host is not set");
      }
      PrintHeader("Config");
      fmt::print("Host: {}\n", fmt::styled(host, fmt::emphasis::bold));
      fmt::print("TLS: {}\n", fmt::styled(tls_version_str, fmt::emphasis::bold));
      if (!ciphersuites.empty()) {
        fmt::print("Ciphersuites: {}\n", fmt::styled(ciphersuites, fmt::emphasis::bold));
      }

      HttpsClientApp client(host, tls_version, ciphersuites);

      client.ResolveEndpoints();
      client.ConnectToSomeEndpoint();
      client.MakeHandShake();
    }

  } catch (std::exception& e) {
    fmt::print(kFailStyle, "Error: {}\n", e.what());
    return 1;
  }

  fmt::print("\n");

  return 0;
}
