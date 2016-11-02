#ifndef __x509_h
#define __x509_h

// Include header for addon version, node/v8 inclusions, etc.
#include <addon.h>
#include <node_version.h>
#include <nan.h>
#include <string>

// OpenSSL headers
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bn.h>

using namespace v8;

NAN_METHOD(get_altnames);
NAN_METHOD(get_subject);
NAN_METHOD(get_issuer);
NAN_METHOD(parse_cert);
NAN_METHOD(verify);

Local<Value> try_parse(const std::string& dataString);
Local<Value> verify(const std::string& dataString);
Local<Value> parse_date(ASN1_TIME *date);
Local<Value> parse_serial(ASN1_INTEGER *serial);
Local<Value> parse_name(X509_NAME *subject);

const char* real_name(const char *data);
char* trim(char *data, int len);

#endif
