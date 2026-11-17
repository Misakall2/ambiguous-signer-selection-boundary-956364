# node-jose #

[![Greenkeeper badge](https://badges.greenkeeper.io/cisco/node-jose.svg)](https://greenkeeper.io/)
[![Build Status](https://travis-ci.org/cisco/node-jose.svg?branch=master)](https://travis-ci.org/cisco/node-jose)

A JavaScript implementation of the JSON Object Signing and Encryption (JOSE) for current web browsers and node.js-based servers.  This library implements (wherever possible) all algorithms, formats, and options in [JWS](https://tools.ietf.org/html/rfc7515 "Jones, M., J. Bradley and N. Sakimura, 'JSON Web Signature (JWS)' RFC 7515, May 2015"), [JWE](https://tools.ietf.org/html/rfc7516 "Jones, M. and J. Hildebrand 'JSON Web Encryption (JWE)', RFC 7516, May 2015"), [JWK](https://tools.ietf.org/html/rfc7517 "Jones, M., 'JSON Web Key (JWK)', RFC 7517, May 2015"), and [JWA](https://tools.ietf.org/html/rfc7518 "Jones, M., 'JSON Web Algorithms (JWA)', RFC 7518, May 2015") and uses native cryptographic support ([WebCrypto API](http://www.w3.org/TR/WebCryptoAPI/) or node.js' "[crypto](https://nodejs.org/api/crypto.html)" module) where feasible.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Installing](#installing)
- [Basics](#basics)
- [Keys and Key Stores](#keys-and-key-stores)
  - [Obtaining a KeyStore](#obtaining-a-keystore)
  - [Exporting a KeyStore](#exporting-a-keystore)
  - [Retrieving Keys](#retrieving-keys)
  - [Searching for Keys](#searching-for-keys)
  - [Managing Keys](#managing-keys)
  - [Importing and Exporting a Single Key](#importing-and-exporting-a-single-key)
  - [Obtaining a Key's Thumbprint](#obtaining-a-keys-thumbprint)
- [Signatures](#signatures)
  - [Keys Used for Signing and Verifying](#keys-used-for-signing-and-verifying)
  - [Signing Content](#signing-content)
  - [Verifying a JWS](#verifying-a-jws)
    - [Key Selection and Duplicate Key Identifiers](#key-selection-and-duplicate-key-identifiers)
    - [Allowing (or Disallowing) Signature Algorithms](#allowing-or-disallowing-signature-algorithms)
    - [Handling `crit` Header Members](#handling-crit-header-members)
- [Encryption](#encryption)
  - [Keys Used for Encrypting and Decrypting](#keys-used-for-encrypting-and-decrypting)
  - [Encrypting Content](#encrypting-content)
  - [Decrypting a JWE](#decrypting-a-jwe)
    - [Allowing (or Disallowing) Encryption Algorithms](#allowing-or-disallowing-encryption-algorithms)
    - [Handling `crit` Header Members](#handling-crit-header-members-1)
- [Useful Utilities](#useful-utilities)
  - [Converting to Buffer](#converting-to-buffer)
  - [URI-Safe Base64](#uri-safe-base64)
  - [Random Bytes](#random-bytes)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installing ##

To install the latest from [NPM](https://npmjs.com/):

```shell
  npm install node-jose
```

Or to install a specific release:

```shell
  npm install node-jose@0.3.0
```

Alternatively, the latest unpublished code can be installed directly from the repository:

```shell
  npm install git+https://github.com/cisco/node-jose.git
```

## Basics ##

Require the library as normal:

```javascript
var jose = require('node-jose');
```

This library uses [Promises](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) for nearly every operation.

This library supports [Browserify](http://browserify.org/) and [Webpack](https://webpack.github.io/).  To use in a web browser, `require('node-jose')` and bundle with the rest of your app.

The content to be signed/encrypted -- or returned from being verified/decrypted -- are [Buffer](https://nodejs.org/api/buffer.html) objects.

## Keys and Key Stores ##

The `jose.JWK` namespace deals with JWK and JWK-sets.

* `jose.JWK.Key` is a logical representation of a JWK, and is the "raw" entry point for various cryptographic operations (e.g., sign, verify, encrypt, decrypt).
* `jose.JWK.KeyStore` represents a collection of Keys.

Creating a JWE or JWS ultimately require one or more explicit Key objects.

Processing a JWE or JWS relies on a KeyStore.

### Obtaining a KeyStore ###
To create an empty keystore:

```javascript
keystore = jose.JWK.createKeyStore();
```

To import a JWK-set as a keystore:

```javascript
// {input} is a String or JSON object representing the JWK-set
jose.JWK.asKeyStore(input).
     then(function(result) {
       // {result} is a jose.JWK.KeyStore
       keystore = result;
     });
```

### Exporting a KeyStore ###

To export the public keys of a keystore as a JWK-set:

```javascript
output = keystore.toJSON();
```

To export **all** the keys of a keystore:

```javascript
output = keystore.toJSON(true);
```

### Retrieving Keys ###

To retrieve a key from a keystore:

```javascript
// by 'kid'
key = keystore.get(kid);
```

This retrieves the first key that matches the given {kid}.  If multiple keys have the same {kid}, you can further narrow what to retrieve:

```javascript
// ... and by 'kty'
key = keystore.get(kid, { kty: 'RSA' });

// ... and by 'use'
key = keystore.get(kid, { use: 'enc' });

// ... and by 'alg'
key = keystore.get(kid, { use: 'RSA-OAEP' });

// ... and by 'kty' and 'use'
key = keystore.get(kid, { kty: 'RSA', use: 'enc' });

// same as above, but with a single {props} argument
key = keystore.get({ kid: kid, kty: 'RSA', use: 'enc' });
```

`get()` and `all()` keep their original semantics: they are public queries and
may return several keys with the same `kid`.  For security-sensitive selection,
use `candidates()`, which resolves to a frozen snapshot taken after any pending
import has settled:

```javascript
keystore.candidates({ kid: kid }).
        then(function(keys) {
          // {keys} is a frozen Array of every matching Key; consumers decide
          // whether zero, one, or several matches are acceptable.
        });
```

Key signature verification only proceeds when exactly one distinct candidate
remains; see [Key Selection and Duplicate Key Identifiers](#key-selection-and-duplicate-key-identifiers).

### Searching for Keys ###

To retrieve all the keys from a keystore:

```javascript
everything = keystore.all();
```

`all()` can be filtered much like `get()`:

```javascript
// filter by 'kid'
everything = keystore.all({ kid: kid });

// filter by 'kty'
everything = keystore.all({ kty: 'RSA' });

// filter by 'use'
everything = keystore.all({ use: 'enc' });

// filter by 'alg'
everything = keystore.all({ alg: 'RSA-OAEP' });

// filter by 'kid' + 'kty' + 'alg'
everything = keystore.all({ kid: kid, kty: 'RSA', alg: 'RSA-OAEP' });
```

### Managing Keys ###

To import an existing Key (as a JSON object or Key instance):

```javascript
// input is either a:
// *  jose.JWK.Key to copy from; or
// *  JSON object representing a JWK; or
keystore.add(input).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });
```

To import and existing Key from a PEM or DER:

```javascript
// input is either a:
// *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
// *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
// form is either a:
// * "json" for a JSON stringified JWK
// * "private" for a DER encoded 'raw' private key
// * "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
// * "public" for a DER encoded SPKI public key (alternate to 'spki')
// * "spki" for a DER encoded SPKI public key
// * "pkix" for a DER encoded PKIX X.509 certificate
// * "x509" for a DER encoded PKIX X.509 certificate
// * "pem" for a PEM encoded of PKCS8 / SPKI / PKIX
keystore.add(input, form).
        then(function(result) {
          // {result} is a jose.JWK.Key
        });
```

To generate a new Key:

```javascript
// first argument is the key type (kty)
// second is the key size (in bits) or named curve ('crv') for "EC"
keystore.generate("oct", 256).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });

// ... with properties
var props = {
  kid: 'gBdaS-G8RLax2qgObTD94w',
  alg: 'A256GCM',
  use: 'enc'
};
keystore.generate("oct", 256, props).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });
```

To remove a Key from its Keystore:
```javascript
keystore.remove(key);
// NOTE: key.keystore does not change!!
```

A key is visible only after `add()` resolves.  Importing and querying
concurrently cannot expose a half-built collection: `candidates()` waits for any
import already in flight before taking its snapshot.

### Importing and Exporting a Single Key ###

To create a single "stand alone" key:

```javascript
jose.JWK.createKey("oct", 256, { alg: "A256GCM" }).
         then(function(result) {
           // {result} is a jose.JWK.Key
           // {result.keystore} is a unique jose.JWK.KeyStore
         });
```


To import a single Key:

```javascript
// where input is either a:
// *  jose.JWK.Key instance
// *  JSON Object representation of a JWK
jose.JWK.asKey(input).
        then(function(result) {
          // {result} is a jose.JWK.Key
          // {result.keystore} is a unique jose.JWK.KeyStore
        });

// where input is either a:
// *  String serialization of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
// *  Buffer of a JSON JWK/(base64-encoded) PEM/(binary-encoded) DER
// form is either a:
// * "json" for a JSON stringified JWK
// * "pkcs8" for a DER encoded (unencrypted!) PKCS8 private key
// * "spki" for a DER encoded SPKI public key
// * "pkix" for a DER encoded PKIX X.509 certificate
// * "x509" for a DER encoded PKIX X.509 certificate
// * "pem" for a PEM encoded of PKCS8 / SPKI / PKIX
jose.JWK.asKey(input, form).
        then(function(result) {
          // {result} is a jose.JWK.Key
          // {result.keystore} is a unique jose.JWK.KeyStore
        });
```

To export the public portion of a Key as a JWK:

```javascript
var output = key.toJSON();
```

To export the public **and** private portions of a Key:

```javascript
var output = key.toJSON(true);
```

### Obtaining a Key's Thumbprint ###

To get or calculate a [RFC 7638](https://tools.ietf.org/html/rfc7638) thumbprint for a key:

```javascript
// where hash is a supported algorithm, currently one of:
// * SHA-1
// * SHA-256
// * SHA-384
// * SHA-512
key.thumbprint(hash).
    then(function(print) {
      // {print} is a Buffer containing the thumbprint binary value
    });
```

When importing or generating a key that does not have a "kid" defined, a
"SHA-256" thumbprint is calculated and used as the "kid".

## Signatures ##

### Keys Used for Signing and Verifying ###

When signing content, the key is expected to meet one of the following:

1. A secret key (e.g, `"kty":"oct"`)
2. The **private** key from a PKI (`"kty":"EC"` or `"kty":"RSA"`) key pair

When verifying content, the key is expected to meet one of the following:

1. A secret key (e.g, `"kty":"oct"`)
2. The **public** key from a PKI (`"kty":"EC"` or `"kty":"RSA"`) key pair


### Signing Content ###

At its simplest, to create a JWS:

```javascript
// {input} is a Buffer
jose.JWS.createSign(key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON object -- JWS using the JSON General Serialization
        });
```

The JWS is signed using the preferred algorithm appropriate for the given Key.  The preferred algorithm is the first item returned by `key.algorithms("sign")`.

To create a JWS using another serialization format:

```javascript
jose.JWS.createSign({ format: 'flattened' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON object -- JWS using the JSON Flattened Serialization
        });

jose.JWS.createSign({ format: 'compact' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a String -- JWS using the Compact Serialization
        });
```

To create a JWS using a specific algorithm:
```javascript
jose.JWS.createSign({ fields: { alg: 'PS256' } }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS for a specified content type:

```javascript
jose.JWS.createSign({ fields: { cty: 'jwk+json' } }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS from String content:

```javascript
jose.JWS.createSign(key).
        update(input, "utf8").
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS with multiple signatures:

```javascript
// {keys} is an Array of jose.JWK.Key instances
jose.JWS.createSign(keys).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

### Verifying a JWS ###

To verify a JWS, and retrieve the payload:

```javascript
jose.JWS.createVerify(keystore).
        verify(input).
        then(function(result) {
          // {result} is a Object with:
          // *  header: the combined 'protected' and 'unprotected' header members
          // *  payload: Buffer of the signed content
          // *  signature: Buffer of the verified signature
          // *  key: The key used to verify the signature
        });
```

To verify using an implied Key:

```javascript
// {key} can be:
// *  jose.JWK.Key
// *  JSON object representing a JWK
jose.JWS.createVerify(key).
        verify(input).
        then(function(result) {
          // ...
        });
```

To verify using a key embedded in the JWS:

```javascript
jose.JWS.createVerify().
        verify(input, { allowEmbeddedKey: true }).
        then(function(result) {
          // ...
        });
```

Alternatively, a cached `createVerify()` can be configured to allow an embedded key:

```javascript
var verifier = jose.JWS.createVerify({ allowEmbeddedKey: true });

verifier.verify(input).
         then(function(result) {
           // ...
         });
```

The key can be embedded using either 'jwk' or 'x5c', and can be located in either the JWS Unprotected Header or JWS Protected Header.

**NOTE:** `verify()` will use the embedded key (if found and permitted) instead of any other key.

#### Key Selection and Duplicate Key Identifiers ####

When verifying with a KeyStore, the verifier resolves a key in three steps:

1. gather the trusted candidates whose `kid` matches the header (all candidates when the header has no `kid`);
2. keep only keys that may verify (`use` absent or `"sig"`, and `key_ops` absent or containing `"verify"`) and that support the header's `alg`;
3. require **exactly one distinct key** among those candidates.

If step 3 finds more than one *different* key -- for example, two keys that share a `kid` -- verification is refused with an `ERR_JWS_KEY_AMBIGUOUS` error. The candidates are **not** tried one by one; selection never depends on import order. Two copies of the same key (same key material, imported twice) are not ambiguous. A key that shares the requested `kid` but has a different `use` (such as `"enc"`) is not a candidate; it never creates ambiguity for signature verification.

For a JWS with several signatures, an ambiguous or conflicting trusted set aborts the whole verification instead of being treated as "this signature did not match"; otherwise a later signature could hide the defect. Other failures (a missing key, an unsupported algorithm, a bad signature) are per signature, and a message is accepted when one signature verifies.

`kid` is treated as an opaque string. It is never interpreted as a property name, a file path, or a URL, and a `jku` or `x5u` header never causes a download.

The verifier reads candidates through `keystore.candidates(props, local)`, which resolves to a frozen snapshot taken after any in-flight `add()` calls have settled. A later `add()` or `remove()` affects subsequent lookups immediately, but never changes a candidate set already handed to a running verification.

Errors carry a stable `code` property so callers can distinguish cases without matching on message text:

| `code` | Meaning |
| --- | --- |
| `ERR_JWS_ALG_NOT_ALLOWED` | The header's `alg` is outside the caller's `algorithms` policy. |
| `ERR_JWS_ALG_UNSUPPORTED` | A candidate exists, but no trusted key can use that `alg`. |
| `ERR_JWS_KEY_NOT_FOUND` | No trusted key (or permitted embedded key) matches. |
| `ERR_JWS_KEY_AMBIGUOUS` | More than one distinct trusted key matches; refused. |
| `ERR_JWS_KEY_CONFLICT` | Embedded key material contradicts the header (e.g. `kid` or both `jwk`/`x5c`). |
| `ERR_JWS_HEADER_INVALID` | Malformed or duplicated protected/unprotected header fields. |
| `ERR_JWS_SIGNATURE_INVALID` | Exactly one key was selected, but the signature did not verify. |

Error messages and the `details` object list only public descriptors (`kid`, `kty`, `alg`, `use`, and a candidate count). They never include the payload, the full serialized message, private key parameters, or the contents of an embedded key.

**Compatibility note.** Verification previously accepted whichever key `keystore.get()` returned first, so a set containing two distinct keys with the same `kid` could verify or fail depending on import order. Such a set is now refused with `ERR_JWS_KEY_AMBIGUOUS` until it is disambiguated. A set with one usable key per `kid` -- the normal case -- is unaffected, and existing signatures keep verifying.

To migrate a set whose `kid`s are duplicated across generations:

```javascript
// 1. Keep public queries as-is; they still return every match.
keystore.all({ kid: "shared-kid" });   // => [oldKey, newKey]

// 2. Retire the key that should no longer authenticate.
keystore.remove(oldKey);

// 3. Verify again; exactly one candidate remains.
jose.JWS.createVerify(keystore).verify(input).
        then(function(result) { /* ... */ },
             function(err) {
               // distinguish failures by code, never by message text
               if (err.code === "ERR_JWS_KEY_AMBIGUOUS") {
                 // still two usable keys for this kid/alg
               }
             });
```

Alternatively, scope the verifier to a key-specific keystore (`keystore.temp()` plus the single intended key), or give each generation a distinct `kid`. An offline, runnable version of this scenario lives in [`examples/ambiguous-kid-migration.js`](examples/ambiguous-kid-migration.js) (`node examples/ambiguous-kid-migration.js`).

#### Allowing (or Disallowing) Signature Algorithms ###

To restrict what signature algorithms are allowed when verifying, add the `algorithms` member to the `options` Object.  The `algorithms` member is either a string or an array of strings, where the string value(s) can be one of the following:

* `"*"`: accept all supported algorithms
* **`<alg name>`** (e.g., `"PS256"`): accept the specific algorithm (can have a single '*' to match a range of algorithms)
* **`!<alg name>`** (e.g., `"!RS256"`): *do not* accept the specific algorithm (can have a single '*' to match a range of algorithms)

The negation is intended to be used with the wildcard accept string, and disallow takes precedence over allowed.

To only accept RSA-PSS sigatures:

```javascript
var opts = {
  algorithms: ["PS*"]
};
jose.JWS.createVerify(key, opts).
        verify(input).
        then(function(result) {
          // ...
        });
```

To accept any algorithm, but disallow HMAC-based signatures:

```javascript
var opts = {
  algorithms: ["*", "!HS*"]
};
jose.JWS.createVerify(key, opts).
        verify(input).
        then(function(result) {
          // ...
        });
```

#### Handling `crit` Header Members ####

To accept 'crit' field members, add the `handlers` member to the options Object.  The `handlers` member is itself an Object, where its member names are the `crit` header member, and the value is one of:

* `Function`: takes the JWE decrypt output (just prior to decrypting) and returns a Promise for the processing of the member.
* `Object`: An object with the following `Function` members:
  * "prepare" -- takes the JWE decrypt output (just prior to decrypting) and returns a Promise for the processing of the member.
  * "complete" -- takes the JWE decrypt output (immediately after decrypting) and returns a Promise for the processing of the member.

**NOTE** If the handler function returns a promise, the fulfilled value is ignored.  It is expected these handler functions will modify the provided value directly.

To perform additional (pre-verify) processing on a `crit` header member:

```javascript
var opts = {
  handlers: {
    "exp": function(jws) {
      // {jws} is the JWS verify output, pre-verification
      jws.header.exp = new Date(jws.header.exp);
    }
  }
};
jose.JWS.createVerify(key, opts).
        verify(input).
        then(function(result) {
          // ...
        });
```

To perform additional (post-verify) processing on a `crit` header member:

```javascript
var opts = {
  handlers: {
    "exp": {
      complete: function(jws) {
        // {jws} is the JWS verify output, post-verification
        jws.header.exp = new Date(jws.header.exp);
      }
    }
  }
};
jose.JWS.createVerify(key, opts).
        verify(input).
        then(function(result) {
          // ...
        });
```


## Encryption ##


### Keys Used for Encrypting and Decrypting ###

When encrypting content, the key is expected to meet one of the following:

1. A secret key (e.g, `"kty":"oct"`)
2. The **public** key from a PKI (`"kty":"EC"` or `"kty":"RSA"`) key pair

When decrypting content, the key is expected to meet one of the following:

1. A secret key (e.g, `"kty":"oct"`)
2. The **private** key from a PKI (`"kty":"EC"` or `"kty":"RSA"`) key pair


### Encrypting Content ###

At its simplest, to create a JWE:

```javascript
// {input} is a Buffer
jose.JWE.createEncrypt(key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON Object -- JWE using the JSON General Serialization
        });
```

How the JWE content is encrypted depends on the provided Key.

* If the Key only supports content encryption algorithms, then the preferred algorithm is used to encrypt the content and the key encryption algorithm (i.e., the "alg" member) is set to "dir".  The preferred algorithm is the first item returned by `key.algorithms("encrypt")`.
* If the Key supports key management algorithms, then the JWE content is encrypted using "A128CBC-HS256" by default, and the Content Encryption Key is encrypted using the preferred algorithms for the given Key.  The preferred algorithm is the first item returned by `key.algorithms("wrap")`.


To create a JWE using a different serialization format:

```javascript
jose.JWE.createEncrypt({ format: 'compact' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a String -- JWE using the Compact Serialization
        });

jose.JWE.createEncrypt({ format: 'flattened' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON Object -- JWE using the JSON Flattened Serialization
        });
```

To create a JWE and compressing the content before encrypting:

```javascript
jose.JWE.createEncrypt({ zip: true }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWE for a specific content type:

```javascript
jose.JWE.createEncrypt({ fields: { cty : 'jwk+json' } }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWE with multiple recipients:

```javascript
// {keys} is an Array of jose.JWK.Key instances
jose.JWE.createEncrypt(keys).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

### Decrypting a JWE ###

To decrypt a JWE, and retrieve the plaintext:

```javascript
jose.JWE.createDecrypt(keystore).
        decrypt(input).
        then(function(result) {
          // {result} is a Object with:
          // *  header: the combined 'protected' and 'unprotected' header members
          // *  protected: an array of the member names from the "protected" member
          // *  key: Key used to decrypt
          // *  payload: Buffer of the decrypted content
          // *  plaintext: Buffer of the decrypted content (alternate)
        });
```

To decrypt a JWE using an implied key:

```javascript
jose.JWE.createDecrypt(key).
        decrypt(input).
        then(function(result) {
          // ....
        });
```

#### Allowing (or Disallowing) Encryption Algorithms ###

To restrict what encryption algorithms are allowed when verifying, add the `algorithms` member to the `options` Object.  The `algorithms` member is either a string or an array of strings, where the string value(s) can be one of the following:

* `"*"`: accept all supported algorithms
* **`<alg name>`** (e.g., `"A128KW"`): accept the specific algorithm (can have a single '*' to match a range of similar algorithms)
* **`!<alg name>`** (e.g., `"!RSA1_5"`): *do not* accept the specific algorithm (can have a single '*' to match a range of similar algorithms)

The negation is intended to be used with the wildcard accept string, and disallow takes precedence over allowed.

To only accept "dir" and AES-GCM encryption:

```javascript
var opts = {
  algorithms: ["dir", "A*GCM"]
};
jose.JWE.createDecrypt(key, opts).
        decrypt(input).
        then(function(result) {
          // ...
        });
```

To accept any algorithm, but disallow RSA-based encryption:

```javascript
var opts = {
  algorithms: ["*", "!RSA*"]
};
jose.JWS.createVerify(key, opts).
        verify(input).
        then(function(result) {
          // ...
        });
```

#### Handling `crit` Header Members ####

To accept 'crit' field members, add the `handlers` member to the options Object.  The `handlers` member is itself an Object, where its member names are the `crit` header member, and the value is one of:

* `Function`: takes the JWE decrypt output (just prior to decrypting) and returns a Promise for the processing of the member.
* `Object`: An object with the following `Function` members:
  * "prepare" -- takes the JWE decrypt output (just prior to decrypting) and returns a Promise for the processing of the member.
  * "complete" -- takes the JWE decrypt output (immediately after decrypting) and returns a Promise for the processing of the member.

**NOTE** If the handler function returns a promise, the fulfilled value is ignored.  It is expected these handler functions will modify the provided value directly.

To perform additional (pre-decrypt) processing on a `crit` header member:

```javascript
var opts = {
  handlers: {
    "exp": function(jwe) {
      // {jwe} is the JWE decrypt output, pre-decryption
      jwe.header.exp = new Date(jwe.header.exp);
    }
  }
};
jose.JWE.createDecrypt(key, opts).
        decrypt(input).
        then(function(result) {
          // ...
        });
```

To perform additional (post-decrypt) processing on a `crit` header member:

```javascript
var opts = {
  handlers: {
    "exp": {
      complete: function(jwe) {
        // {jwe} is the JWE decrypt output, post-decryption
        jwe.header.exp = new Date(jwe.header.exp);
      }
    }
  }
};
jose.JWE.createDecrypt(key, opts).
        decrypt(input).
        then(function(result) {
          // ...
        });
```

## Useful Utilities ##

### Converting to Buffer ###

To convert a [Typed Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays), [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer), or Array of Numbers to a Buffer:

```javascript
buff = jose.util.asBuffer(input);
```

### URI-Safe Base64 ###

This exposes [urlsafe-base64](https://github.com/RGBboy/urlsafe-base64)'s `encode` and `decode` methods as `encode` and `decode` (respectively).

To convert from a Buffer to a base64uri-encoded String:

```javascript
var output = jose.util.base64url.encode(input);
```

To convert a String to a base64uri-encoded String:

```javascript
// explicit encoding
output = jose.util.base64url.encode(input, "utf8");

// implied "utf8" encoding
output = jose.util.base64url.encode(input);
```

To convert a base64uri-encoded String to a Buffer:

```javascript
var output = jose.util.base64url.decode(input);
```

### Random Bytes ###

To generate a Buffer of octets, regardless of platform:

```javascript
// argument is size (in bytes)
var rnd = jose.util.randomBytes(32);
```

This function uses:

* `crypto.randomBytes()` on node.js
* `crypto.getRandomValues()` on modern browsers
* A PRNG based on AES and SHA-1 for older platforms
