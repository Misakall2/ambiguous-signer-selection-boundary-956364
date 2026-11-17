/*!
 * jws/verify.js - Verifies from a JWS
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var clone = require("lodash/clone"),
    merge = require("../util/merge"),
    base64url = require("../util/base64url"),
    AlgConfig = require("../util/algconfig"),
    JWK = require("../jwk");

var DEFAULT_OPTIONS = {
  algorithms: "*",
  allowEmbeddedKey: false
};

/**
 * Errors that must abort verification outright.  An ambiguous or conflicting
 * trusted set is a configuration/trust failure, not "this signature did not
 * match"; moving on to another signature would hide it.
 */
var TERMINAL_CODES = {
  ERR_JWS_KEY_AMBIGUOUS: true,
  ERR_JWS_KEY_CONFLICT: true,
  ERR_JWS_HEADER_INVALID: true
};

/**
 * Ranks non-terminal failures so the most informative one is reported when
 * every signature has been tried.
 */
var ERROR_RANK = {
  ERR_JWS_KEY_NOT_FOUND: 3,
  ERR_JWS_ALG_UNSUPPORTED: 2,
  ERR_JWS_SIGNATURE_INVALID: 1
};

function rankError(err) {
  return (err && ERROR_RANK[err.code]) || 0;
}

/**
 * Creates an Error carrying a stable, machine-readable classification.
 *
 * The message never includes the JWS payload, key material, or the contents
 * of an embedded key.  Only identifiers and descriptors that are already
 * public (such as "kid", "kty", "alg", and "use") are recorded.
 */
function selectionError(code, message, details) {
  var err = new Error(message);
  Object.defineProperty(err, "code", {
    value: code,
    enumerable: true,
    configurable: true
  });
  Object.defineProperty(err, "details", {
    value: details || {},
    enumerable: true,
    configurable: true
  });
  return err;
}

/**
 * Describes a candidate key for diagnostics.  Private fields (e.g. "d", "p",
 * "q", "k") are deliberately never copied.
 */
function describeKey(key) {
  var result = {};
  ["kid", "kty", "alg", "use"].forEach(function(name) {
    var value = key && key[name];
    if ("string" === typeof value && value) {
      result[name] = value;
    }
  });
  return result;
}

function useAllowsVerify(key) {
  return !!key && (!key.use || "sig" === key.use);
}

function keyOpsAllowVerify(key) {
  if (!key || "function" !== typeof key.get) {
    return true;
  }
  var ops = key.get("key_ops");
  if (!Array.isArray(ops)) {
    return true;
  }
  return -1 !== ops.indexOf("verify");
}

function usableForVerify(key) {
  return useAllowsVerify(key) && keyOpsAllowVerify(key);
}

function supportsVerifyAlg(key, alg) {
  return !!(key &&
            "function" === typeof key.supports &&
            key.supports(alg, "verify"));
}

function listCandidates(keystore, props) {
  // Prefer the keystore's candidate view: it waits for in-flight imports and
  // returns an immutable snapshot.  Fall back to the long-standing "all()"
  // query for third-party keystore implementations.
  if (keystore && "function" === typeof keystore.candidates) {
    return keystore.candidates(props);
  }
  var found;
  if (keystore && "function" === typeof keystore.all) {
    found = keystore.all(props) || [];
  } else {
    found = [];
  }
  return Promise.resolve(Object.freeze(found.slice()));
}

/**
 * Collapses duplicate entries that hold the same key material.  Two copies of
 * one key are not an identity ambiguity; two different keys are.
 */
function distinctByIdentity(candidates) {
  return Promise.all(candidates.map(function(key) {
    var promise;
    if (key && "function" === typeof key.thumbprint) {
      promise = Promise.resolve(key.thumbprint("SHA-256"));
    } else {
      promise = Promise.resolve(null);
    }
    return promise.then(function(print) {
      var id = null;
      if (Buffer.isBuffer(print) || print instanceof Uint8Array) {
        id = (key.kty || "") + ":" + base64url.encode(Buffer.from(print));
      }
      return { key: key, id: id };
    }, function() {
      return { key: key, id: null };
    });
  })).then(function(items) {
    var seen = Object.create(null);
    var distinct = [];
    items.forEach(function(item) {
      if (item.id) {
        if (seen[item.id]) {
          return;
        }
        seen[item.id] = true;
      }
      distinct.push(item.key);
    });
    return distinct;
  });
}

/**
 * Filters the trusted collection down to exactly one candidate, or rejects.
 *
 * Selection is never a trial-and-error loop: when more than one distinct key
 * can honor the signature, verification stops instead of trying them in turn.
 */
function selectKeystoreKey(keystore, header, alg) {
  var kid = header.kid;
  if (kid !== undefined && kid !== null && "string" !== typeof kid) {
    if ("number" === typeof kid) {
      // tolerate numeric identifiers (see issues/109)
      kid = String(kid);
    } else {
      return Promise.reject(selectionError("ERR_JWS_HEADER_INVALID",
                                          "Invalid 'kid' header",
                                          { header: "kid" }));
    }
  }
  if ("" === kid) {
    kid = undefined;
  }

  // The trusted set is filtered by identifier first; "use", "key_ops", and the
  // algorithm are applied below so each rejection reason stays distinguishable.
  var props = {};
  if (kid !== undefined) {
    props.kid = kid;
  }

  return listCandidates(keystore, props).then(function(candidates) {
    var usable = candidates.filter(usableForVerify);
    if (!usable.length) {
      throw selectionError("ERR_JWS_KEY_NOT_FOUND",
                           "no key found",
                           { alg: alg, kid: kid });
    }

    var supported = usable.filter(function(key) {
      return supportsVerifyAlg(key, alg);
    });
    if (!supported.length) {
      throw selectionError("ERR_JWS_ALG_UNSUPPORTED",
                           "unsupported algorithm: " + alg,
                           { alg: alg, kid: kid });
    }

    return distinctByIdentity(supported).then(function(distinct) {
      if (1 === distinct.length) {
        return distinct[0];
      }
      // Refuse: do not guess which of several usable keys signed the message.
      throw selectionError("ERR_JWS_KEY_AMBIGUOUS",
                           "multiple keys match the signature",
                           {
                             alg: alg,
                             kid: kid,
                             candidates: distinct.map(describeKey)
                           });
    });
  });
}

/**
 * Resolves a key embedded in the JOSE header.  Embedded keys are a separate
 * trust source: they are only accepted when the caller opts in, and once
 * accepted they are the only candidate (never mixed with the keystore).
 */
function selectEmbeddedKey(header, alg) {
  var sources = [];
  if (header.jwk !== undefined && header.jwk !== null) {
    sources.push("jwk");
  }
  if (header.x5c !== undefined && header.x5c !== null) {
    sources.push("x5c");
  }
  if (!sources.length) {
    return Promise.resolve(null);
  }
  if (1 < sources.length) {
    return Promise.reject(selectionError("ERR_JWS_KEY_CONFLICT",
                                        "multiple embedded key sources",
                                        { sources: sources }));
  }

  var promise;
  if ("jwk" === sources[0]) {
    promise = JWK.asKey(header.jwk);
  } else {
    var cert = Array.isArray(header.x5c) ? header.x5c[0] : header.x5c;
    if ("string" !== typeof cert) {
      return Promise.reject(selectionError("ERR_JWS_HEADER_INVALID",
                                          "Invalid 'x5c' header",
                                          { header: "x5c" }));
    }
    promise = JWK.asKey(Buffer.from(cert, "base64"), "pkix");
  }

  return promise.then(function(key) {
    // For an embedded "jwk", an asserted "kid" must identify that same key;
    // otherwise the message claims one identity while carrying another.
    // "x5c" derives its "kid" from the certificate subject, so it is not
    // compared here.  In both cases, the embedded key must honor "alg".
    if ("jwk" === sources[0] &&
        undefined !== header.kid &&
        null !== header.kid &&
        "" !== header.kid &&
        key.kid &&
        String(header.kid) !== key.kid) {
      throw selectionError("ERR_JWS_KEY_CONFLICT",
                           "embedded key does not match 'kid'",
                           { kid: String(header.kid), source: sources[0] });
    }
    if (key.alg && key.alg !== alg) {
      throw selectionError("ERR_JWS_KEY_CONFLICT",
                           "embedded key does not match 'alg'",
                           { alg: alg, source: sources[0] });
    }
    if (!usableForVerify(key)) {
      throw selectionError("ERR_JWS_KEY_NOT_FOUND",
                           "no key found",
                           { alg: alg, source: sources[0] });
    }
    if (!supportsVerifyAlg(key, alg)) {
      throw selectionError("ERR_JWS_ALG_UNSUPPORTED",
                           "unsupported algorithm: " + alg,
                           { alg: alg, source: sources[0] });
    }
    return key;
  }, function() {
    // The embedded key could not be imported; do not echo its contents.
    throw selectionError("ERR_JWS_KEY_NOT_FOUND",
                         "no key found",
                         { alg: alg, source: sources[0] });
  });
}

/**
 * @class JWS.Verifier
 * @classdesc Parser of signed content.
 *
 * @description
 * **NOTE:** this class cannot be instantiated directly. Instead call {@link
 * JWS.createVerify}.
 */
var JWSVerifier = function(ks, globalOpts) {
  var assumedKey,
      keystore;

  if (JWK.isKey(ks)) {
    assumedKey = ks;
    keystore = assumedKey.keystore;
  } else if (JWK.isKeyStore(ks)) {
    keystore = ks;
  } else {
    keystore = JWK.createKeyStore();
  }

  // Never merge into the shared defaults: one verifier's options must not
  // change the policy observed by another (or by a later verifier).
  globalOpts = merge({}, DEFAULT_OPTIONS, globalOpts);

  Object.defineProperty(this, "defaultKey", {
    value: assumedKey || undefined,
    enumerable: true
  });
  Object.defineProperty(this, "keystore", {
    value: keystore,
    enumerable: true
  });

  Object.defineProperty(this, "verify", {
    value: function(input, opts) {
      opts = merge({}, globalOpts, opts || {});
      var extraHandlers = opts.handlers || {};
      var handlerKeys = Object.keys(extraHandlers);
      var algSpec = new AlgConfig(opts.algorithms);

      if ("string" === typeof input) {
        input = input.split(".");
        input = {
          payload: input[1],
          signatures: [
            {
              protected: input[0],
              signature: input[2]
            }
          ]
        };
      } else if (!input || "object" !== typeof input) {
        throw new Error("invalid input");
      }

      // fixup "flattened JSON" to look like "general JSON"
      if (input.signature) {
        input.signatures = [
          {
            protected: input.protected || undefined,
            header: input.header || undefined,
            signature: input.signature
          }
        ];
      }

      // ensure signatories exists
      var sigList = input.signatures || [{}];

      // combine fields and decode signature per signatory
      sigList = sigList.map(function(s) {
        var header = clone(s.header || {});
        var protect = s.protected ?
                      JSON.parse(base64url.decode(s.protected, "utf8")) :
                      {};
        // Reject an unprotected header that tries to restate a protected one;
        // otherwise an attacker-supplied duplicate could change key choice.
        var conflicting = Object.keys(protect).filter(function(name) {
          return name in header;
        });
        if (conflicting.length) {
          return Promise.reject(selectionError(
              "ERR_JWS_HEADER_INVALID",
              "protected and unprotected headers overlap",
              { header: conflicting.sort() }
          ));
        }
        header = merge(header, protect);
        var signature = base64url.decode(s.signature);

        // process allowed algorithims
        if (!algSpec.match(header.alg)) {
          return Promise.reject(selectionError(
              "ERR_JWS_ALG_NOT_ALLOWED",
              "Algorithm not allowed: " + header.alg,
              { alg: header.alg }
          ));
        }

        // process "crit" first
        var crit = protect.crit;
        if (crit) {
          if (!Array.isArray(crit)) {
            return Promise.reject(selectionError(
                "ERR_JWS_HEADER_INVALID",
                "Invalid 'crit' header",
                { header: "crit" }
            ));
          }
          for (var idx = 0; crit.length > idx; idx++) {
            if (-1 === handlerKeys.indexOf(crit[idx])) {
              return Promise.reject(new Error(
                  "Critical extension is not supported: " + crit[idx]
              ));
            }
          }
        }
        protect = Object.keys(protect);

        return Promise.resolve({
          protected: protect,
          aad: s.protected || "",
          header: header,
          signature: signature
        });
      });

      var promise = Promise.all(sigList);
      promise = promise.then(function(sigList) {
        return new Promise(function(resolve, reject) {
          var pending = sigList.slice();
          var lastError;
          var processSig = function() {
            var sig = pending.shift();
            if (!sig) {
              // Every signature was tried and none verified.  Report the most
              // informative classification instead of a generic failure, and
              // never echo the payload.
              reject(lastError || selectionError("ERR_JWS_KEY_NOT_FOUND",
                                                 "no key found",
                                                 {}));
              return;
            }
            // Each signatory gets its own object; handlers must not be able to
            // mutate state observed by another verification attempt.
            var current = merge({}, sig, {
              payload: input.payload
            });
            var p = Promise.resolve(current);
            // find the key
            p = p.then(function(sig) {
              var algKey;
              if (opts.allowEmbeddedKey) {
                algKey = selectEmbeddedKey(sig.header, sig.header.alg);
              } else {
                algKey = Promise.resolve(null);
              }
              return algKey.then(function(k) {
                if (k) {
                  sig.key = k;
                  return sig;
                }
                // No embedded key was used; all trust must come from the
                // caller-supplied key or keystore.
                if (assumedKey) {
                  if (!usableForVerify(assumedKey)) {
                    return Promise.reject(selectionError(
                        "ERR_JWS_KEY_NOT_FOUND",
                        "no key found",
                        { alg: sig.header.alg }
                    ));
                  }
                  if (!supportsVerifyAlg(assumedKey, sig.header.alg)) {
                    return Promise.reject(selectionError(
                        "ERR_JWS_ALG_UNSUPPORTED",
                        "unsupported algorithm: " + sig.header.alg,
                        { alg: sig.header.alg }
                    ));
                  }
                  // An explicitly supplied Key is authoritative: it is the
                  // only candidate and is never widened by the keystore.
                  sig.key = assumedKey;
                  return sig;
                }
                return selectKeystoreKey(keystore, sig.header, sig.header.alg).
                    then(function(key) {
                      sig.key = key;
                      return sig;
                    });
              });
            });

            // process any prepare-verify handlers
            p = p.then(function(sig) {
              var processing = [];
              handlerKeys.forEach(function(h) {
                h = extraHandlers[h];
                var p;
                if ("function" === typeof h) {
                  p = h(sig);
                } else if ("object" === typeof h && "function" === typeof h.prepare) {
                  p = h.prepare(sig);
                }
                if (p) {
                  processing.push(Promise.resolve(p));
                }
              });
              return Promise.all(processing).then(function() {
                // don't actually care about individual handler results
                // assume {sig} is updated
                return sig;
              });
            });

            // prepare verify inputs
            p = p.then(function(sig) {
              var aad = sig.aad || "",
                  payload = sig.payload || "";
              var content = Buffer.alloc(1 + aad.length + payload.length),
                  pos = 0;
              content.write(aad, pos, "ascii");
              pos += aad.length;
              content.write(".", pos, "ascii");
              pos++;

              if (Buffer.isBuffer(payload)) {
                payload.copy(content, pos);
              } else {
                content.write(payload, pos, "binary");
              }
              sig.content = content;
              return sig;
            });

            p = p.then(function(sig) {
              return sig.key.verify(sig.header.alg,
                                    sig.content,
                                    sig.signature).
                  catch(function(err) {
                    if (err && err.code) {
                      throw err;
                    }
                    // Algorithm-level rejection: a key was available and the
                    // algorithm was allowed, so this is a signature failure.
                    throw selectionError("ERR_JWS_SIGNATURE_INVALID",
                                         "signature verification failed",
                                         { alg: sig.header.alg });
                  });
            });

            p = p.then(function(result) {
              if (!result || !result.valid) {
                throw selectionError("ERR_JWS_SIGNATURE_INVALID",
                                     "signature verification failed",
                                     { alg: current.header.alg });
              }
              var payload = current.payload;
              payload = base64url.decode(payload);
              return {
                protected: current.protected,
                header: current.header,
                payload: payload,
                signature: result.mac,
                key: current.key
              };
            });

            // process any post-verify handlers
            p = p.then(function(jws) {
              var processing = [];
              handlerKeys.forEach(function(h) {
                h = extraHandlers[h];
                var p;
                if ("object" === typeof h && "function" === typeof h.complete) {
                  p = h.complete(jws);
                }
                if (p) {
                  processing.push(Promise.resolve(p));
                }
              });
              return Promise.all(processing).then(function() {
                // don't actually care about individual handler results
                // assume {jws} is updated
                return jws;
              });
            });
            p.then(resolve, function(err) {
              // Refuse to continue past a trust/selection defect: trying the
              // next signature would only mask it.
              if (err && TERMINAL_CODES[err.code]) {
                reject(err);
                return;
              }
              if (!lastError || rankError(err) > rankError(lastError)) {
                lastError = err;
              }
              processSig();
            });
          };
          processSig();
        });
      });
      return promise;
    }
  });
};

/**
 * @description
 * Creates a new JWS.Verifier with the given Key or KeyStore.
 *
 * @param {JWK.Key|JWK.KeyStore} ks The Key or KeyStore to use for verification.
 * @returns {JWS.Verifier} The new Verifier.
 */
function createVerify(ks, opts) {
  var vfy = new JWSVerifier(ks, opts);

  return vfy;
}

module.exports = {
  verifier: JWSVerifier,
  createVerify: createVerify
};
