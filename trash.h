
enum class SSLVersion {
  TLS_1_2 = TLS1_2_VERSION,
  TLS_1_3 = TLS1_3_VERSION,
};

struct Ciphers {
  Ciphers(stack_st_SSL_CIPHER* ciphers) : ciphers{ciphers} {
  }

  int GetSize() const {
    return sk_SSL_CIPHER_num(ciphers);
  }

  std::string GetDescription(int index) const {
    auto value = sk_SSL_CIPHER_value(ciphers, index);
    char* descr = SSL_CIPHER_description(value, nullptr, 0);
    std::string result(descr);
    OPENSSL_free(descr);
    return result;
  }

  stack_st_SSL_CIPHER* ciphers{};
};

struct SSLContext {
  SSLContext(SSLVersion version) : ctx{SSL_CTX_new(TLS_client_method()), SSL_CTX_free} {
    if (!ctx) {
      throw std::runtime_error("cannot create new SSL context");
    }
    if (!SSL_CTX_set_min_proto_version(ctx.get(), static_cast<int>(version)) ||
        !SSL_CTX_set_max_proto_version(ctx.get(), static_cast<int>(version))) {
      throw std::runtime_error("could not set TLS version in SSL context");
    }
  }

  Ciphers GetCiphers() const {
    return Ciphers(SSL_CTX_get_ciphers(ctx.get()));
  }

  std::unique_ptr<SSL_CTX, void (*)(SSL_CTX*)> ctx;
};

int main(int argc, char** argv) {
  ::SSL_library_init();
  ::SSL_load_error_strings();
  ::OpenSSL_add_all_algorithms();

  try {
    SSLContext context(SSLVersion::TLS_1_3);
    auto cipherList = context.GetCiphers();
    for (int i = 0; i < cipherList.GetSize(); ++i) {
      fmt::print("{}", cipherList.GetDescription(i));
    }
  }
}
