#include "../include/salticidae/config.h"
#ifdef SALTICIDAE_CBINDINGS
#include "../include/salticidae/crypto.h"

using namespace salticidae;

extern "C" {

x509_t *x509_new_from_pem_file(const char *pem_fname, const char *passwd, SalticidaeCError *cerror) {
    SALTICIDAE_CERROR_TRY(cerror)
    std::string tmp;
    if (passwd) tmp = passwd;
    auto ret = new x509_t(x509_t::create_from_pem_file(pem_fname, passwd ? &tmp : nullptr));
    OPENSSL_cleanse(&tmp[0], tmp.size());
    return std::move(ret);
    SALTICIDAE_CERROR_CATCH(cerror)
    return nullptr;
}

x509_t *x509_new_from_der(const bytearray_t *der, SalticidaeCError *cerror) {
    SALTICIDAE_CERROR_TRY(cerror)
    return new x509_t(x509_t::create_from_der(*der));
    SALTICIDAE_CERROR_CATCH(cerror)
    return nullptr;
}

void x509_free(const x509_t *self) { delete self; }

pkey_t *x509_get_pubkey(const x509_t *self) {
    return new pkey_t(self->get_pubkey());
}

bytearray_t *x509_get_der(const x509_t *self) {
    return new bytearray_t(self->get_der());
}

pkey_t *pkey_new_privkey_from_pem_file(const char *pem_fname, const char *passwd, SalticidaeCError *cerror) {
    SALTICIDAE_CERROR_TRY(cerror)
    std::string tmp;
    if (passwd) tmp = passwd;
    auto ret = new pkey_t(pkey_t::create_privkey_from_pem_file(pem_fname, passwd ? &tmp: nullptr));
    OPENSSL_cleanse(&tmp[0], tmp.size());
    return std::move(ret);
    SALTICIDAE_CERROR_CATCH(cerror)
    return nullptr;
}

pkey_t *pkey_new_privkey_from_der(const bytearray_t *der, SalticidaeCError *cerror) {
    SALTICIDAE_CERROR_TRY(cerror)
    return new pkey_t(pkey_t::create_privkey_from_der(*der));
    SALTICIDAE_CERROR_CATCH(cerror)
    return nullptr;
}

void pkey_free(const pkey_t *self) { delete self; }

bytearray_t *pkey_get_pubkey_der(const pkey_t *self) {
    return new bytearray_t(self->get_pubkey_der());
}

bytearray_t *pkey_get_privkey_der(const pkey_t *self) {
    return new bytearray_t(self->get_privkey_der());
}

void id_to_address160(const uint8_t *sha_digest, uint8_t *ripemd_digest) {
    class RIPEMD d;
    d.update(sha_digest, 32);
    bytearray_t digest = d.digest();
    uint8_t *digdata = digest.data();
    for (int i=0; i<22; i++) {
        ripemd_digest[i] = digdata[i];
    }
}

}

#endif
