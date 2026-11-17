/*!
 * test/jws/ambiguous-signer-test.js - Candidate selection boundary tests
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");

var JWS = require("../../lib/jws");
var JWK = require("../../lib/jwk");
var JWKStore = require("../../lib/jwk/keystore.js");

var assert = chai.assert;

var PAYLOAD = Buffer.from("selection boundary payload", "utf8");
var SHARED = "shared-kid";

function signWith(key, options) {
  var opts = options || { format: "compact", protect: "*" };
  return JWS.createSign(opts, key).final(PAYLOAD, "utf8");
}

// "keystore.add()" copies the key, so tests must retain the stored instances.
function keystoreWith(keys) {
  var ks = JWK.createKeyStore();
  var stored = [];
  var promise = Promise.resolve();
  (keys || []).forEach(function(key) {
    promise = promise.then(function() {
      return ks.add(key).then(function(copy) {
        stored.push(copy);
      });
    });
  });
  return promise.then(function() {
    return { keystore: ks, keys: stored };
  });
}

function expectedRejection(promise, code) {
  return promise.then(function() {
    assert.ok(false, "unexpected verification success");
  }, function(err) {
    assert.instanceOf(err, Error);
    assert.equal(err.code, code, "unexpected error: " + err.message);
    return err;
  });
}

function assertSameKey(actual, expected, message) {
  // Keys are copied on import; compare the RFC 7638 identity instead.
  return Promise.all([
    actual.thumbprint("SHA-256"),
    expected.thumbprint("SHA-256")
  ]).then(function(prints) {
    assert.deepEqual(prints[0], prints[1], message);
    assert.equal(actual.kid, expected.kid, message);
  });
}

function base64urlJSON(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeJSON(value) {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
}

function cloneJSON(value) {
  return JSON.parse(JSON.stringify(value));
}

describe("jws/ambiguous signer selection", function() {
  var keyA,
      keyB,
      otherKid,
      encKey,
      signature;

  before(function() {
    // Two freshly generated keys of the same type, each with the same "kid",
    // plus a differently-identified key and a same-"kid" key with use "enc".
    return Promise.all([
      JWK.createKey("EC", "P-256", { kid: SHARED, alg: "ES256", use: "sig" }),
      JWK.createKey("EC", "P-256", { kid: SHARED, alg: "ES256", use: "sig" }),
      JWK.createKey("EC", "P-256", { kid: "other-kid", alg: "ES256", use: "sig" }),
      JWK.createKey("EC", "P-256", { kid: SHARED, use: "enc" })
    ]).then(function(keys) {
      keyA = keys[0];
      keyB = keys[1];
      otherKid = keys[2];
      encKey = keys[3];
      return signWith(keyA);
    }).then(function(result) {
      signature = result;
    });
  });

  describe("duplicate identifiers", function() {
    it("rejects when two distinct keys share the requested 'kid'", function() {
      return keystoreWith([keyA, keyB]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(signature),
            "ERR_JWS_KEY_AMBIGUOUS"
        ).then(function(err) {
          assert.equal(err.details.kid, SHARED);
          assert.equal(err.details.alg, "ES256");
          assert.lengthOf(err.details.candidates, 2);
        });
      });
    });

    it("rejects regardless of import order", function() {
      return Promise.all([
        keystoreWith([keyA, keyB]),
        keystoreWith([keyB, keyA])
      ]).then(function(stores) {
        return Promise.all(stores.map(function(store) {
          return expectedRejection(
              JWS.createVerify(store.keystore).verify(signature),
              "ERR_JWS_KEY_AMBIGUOUS"
          ).then(function(err) {
            assert.lengthOf(err.details.candidates, 2);
          });
        }));
      });
    });

    it("never exercises a candidate when the set is ambiguous", function() {
      var attempts = 0;
      function probe(real) {
        return {
          kty: real.kty,
          kid: real.kid,
          alg: real.alg,
          use: real.use,
          toJSON: function(isPrivate) {
            return real.toJSON(isPrivate);
          },
          supports: function(alg, mode) {
            attempts++;
            return real.supports(alg, mode);
          },
          verify: function() {
            attempts++;
            return real.verify.apply(real, arguments);
          },
          thumbprint: function(hash) {
            return real.thumbprint(hash);
          }
        };
      }

      return keystoreWith([keyA, keyB]).then(function(store) {
        return store.keystore.candidates({ kid: SHARED });
      }).then(function(candidates) {
        assert.lengthOf(candidates, 2);
        var wrapped = candidates.map(probe);
        // A minimal keystore-shaped object that only exposes the candidate view.
        var ks = {
          candidates: function() {
            return Promise.resolve(Object.freeze(wrapped));
          },
          all: function() {
            return wrapped.slice();
          },
          get: function() {
            return null;
          },
          add: function() {
            return Promise.reject(new Error("read-only"));
          },
          remove: function() {},
          generate: function() {
            return Promise.reject(new Error("read-only"));
          }
        };
        return expectedRejection(
            JWS.createVerify(ks).verify(signature),
            "ERR_JWS_KEY_AMBIGUOUS"
        ).then(function() {
          assert.equal(attempts, 2,
                       "only the capability checks may run; no verify attempts");
        });
      });
    });

    it("does not treat a repeated import of the same key as ambiguous", function() {
      return keystoreWith([keyA, keyA]).then(function(store) {
        assert.lengthOf(store.keystore.all({ kid: SHARED }), 2);
        return JWS.createVerify(store.keystore).verify(signature);
      }).then(function(result) {
        assert.equal(result.payload.toString("utf8"),
                     PAYLOAD.toString("utf8"));
        assert.equal(result.key.kid, SHARED);
      });
    });

    it("does not treat a same-'kid' key with another 'use' as a candidate", function() {
      return keystoreWith([keyA, encKey]).then(function(store) {
        assert.lengthOf(store.keystore.all({ kid: SHARED }), 2);
        return JWS.createVerify(store.keystore).verify(signature).
            then(function(result) {
              assert.equal(result.payload.toString("utf8"),
                           PAYLOAD.toString("utf8"));
              return assertSameKey(result.key, keyA);
            });
      });
    });

    it("accepts the same pair in either order when only one can verify", function() {
      return Promise.all([
        keystoreWith([keyA, otherKid]),
        keystoreWith([otherKid, keyA])
      ]).then(function(stores) {
        return Promise.all(stores.map(function(store) {
          return JWS.createVerify(store.keystore).verify(signature);
        }));
      }).then(function(results) {
        return Promise.all(results.map(function(result) {
          return assertSameKey(result.key, keyA);
        }));
      });
    });
  });

  describe("identifier filtering", function() {
    var signatureNoKid;
    before(function() {
      return signWith({ key: keyA, reference: false }, {
        format: "compact",
        protect: "*"
      }).then(function(result) {
        signatureNoKid = result;
      });
    });

    it("rejects an unknown 'kid'", function() {
      return keystoreWith([keyA]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(
                resign({ alg: "ES256", kid: "missing-kid" })
            ),
            "ERR_JWS_KEY_NOT_FOUND"
        ).then(function(err) {
          assert.equal(err.details.kid, "missing-kid");
        });
      });
    });

    it("selects by algorithm when the header omits 'kid' and one key fits", function() {
      return JWK.createKey("EC", "P-384", {
        kid: "p384", alg: "ES384", use: "sig"
      }).then(function(p384) {
        return keystoreWith([keyA, p384]);
      }).then(function(store) {
        // The no-kid signature is real; the P-384 key cannot honor ES256.
        return JWS.createVerify(store.keystore).verify(signatureNoKid);
      }).then(function(result) {
        return assertSameKey(result.key, keyA);
      });
    });

    it("rejects when the header omits 'kid' and several keys fit", function() {
      return keystoreWith([keyA, keyB, otherKid]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(signatureNoKid),
            "ERR_JWS_KEY_AMBIGUOUS"
        ).then(function(err) {
          assert.lengthOf(err.details.candidates, 3);
        });
      });
    });

    it("rejects a disallowed algorithm before any key selection", function() {
      return keystoreWith([keyA]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(
                signature, { algorithms: ["RS256"] }),
            "ERR_JWS_ALG_NOT_ALLOWED"
        );
      });
    });

    it("rejects an algorithm no trusted key supports", function() {
      return keystoreWith([keyA]).then(function(store) {
        // The caller allows ES*, but the shared key is P-256/ES256 only.
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(
                resign({ alg: "ES384", kid: SHARED }),
                { algorithms: "ES*" }
            ),
            "ERR_JWS_ALG_UNSUPPORTED"
        );
      });
    });

    it("treats 'kid' as an opaque identifier, not a path or property", function() {
      var hostile = [
        "__proto__",
        "constructor",
        "prototype",
        "/etc/passwd",
        "https://keys.example.test/set.json",
        "../" + SHARED
      ];
      return Promise.all(hostile.map(function(kid) {
        return JWK.createKey("oct", 256, { kid: kid, alg: "HS256" });
      })).then(function(keys) {
        return keystoreWith(keys);
      }).then(function(store) {
        assert.lengthOf(store.keystore.all(), hostile.length);
        hostile.forEach(function(kid) {
          assert.lengthOf(store.keystore.all({ kid: kid }), 1);
        });
        // A missing id is not resolved from Object.prototype; identifiers that
        // happen to name a prototype member only match keys that carry them.
        assert.isNull(store.keystore.get("toString"));
        assert.isNull(store.keystore.get("hasOwnProperty"));
        assert.lengthOf(store.keystore.all({ kid: "constructor" }), 1);
        assert.lengthOf(store.keystore.all({ kid: "__proto__" }), 1);
        return keystoreWith([keyA]);
      }).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(resign({
              alg: "ES256",
              kid: "https://keys.example.test/set.json"
            })),
            "ERR_JWS_KEY_NOT_FOUND"
        );
      });
    });
  });

  describe("mutating the collection", function() {
    it("sees the new candidate set after a key is removed", function() {
      return keystoreWith([keyA, keyB]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(signature),
            "ERR_JWS_KEY_AMBIGUOUS"
        ).then(function() {
          store.keystore.remove(store.keys[1]);
          return JWS.createVerify(store.keystore).verify(signature);
        }).then(function(result) {
          return assertSameKey(result.key, keyA);
        });
      });
    });

    it("stops using a removed key immediately", function() {
      return keystoreWith([keyA]).then(function(store) {
        return JWS.createVerify(store.keystore).verify(signature).
            then(function() {
              store.keystore.remove(store.keys[0]);
              return expectedRejection(
                  JWS.createVerify(store.keystore).verify(signature),
                  "ERR_JWS_KEY_NOT_FOUND"
              );
            });
      });
    });

    it("does not publish a half-finished import", function() {
      // A registry whose imports stay pending until the test releases them.
      var registry = new JWKStore.KeyRegistry();
      var release;
      var gate = new Promise(function(resolve) {
        release = resolve;
      });
      registry.register({
        kty: "GATED",
        prepare: function() {
          return gate.then(function() {
            return {
              publicKey: function() {
                return { length: 256 };
              },
              privateKey: function() {
                return { length: 256 };
              },
              algorithms: function() {
                return [];
              }
            };
          });
        },
        generate: function() {
          return Promise.reject(new Error("not supported"));
        }
      });

      var store = new JWKStore.KeyStore(registry);
      var adding = store.add({ kty: "GATED", kid: SHARED });

      // The import is still in flight, so the candidate view must remain
      // pending rather than expose a half-built collection.
      var settledEarly = false;
      var pendingView = store.candidates({ kid: SHARED }).then(function(keys) {
        settledEarly = true;
        return keys;
      });

      return Promise.resolve().then(function() {
        assert.isFalse(settledEarly, "candidate view resolved too early");
        release();
        return pendingView;
      }).then(function(keys) {
        assert.isTrue(settledEarly);
        assert.lengthOf(keys, 1);
        return adding;
      }).then(function(key) {
        assert.equal(key.kid, SHARED);
        return store.candidates({ kid: SHARED });
      }).then(function(keys) {
        assert.lengthOf(keys, 1);
      });
    });

    it("releases waiting lookups when an import fails", function() {
      var registry = new JWKStore.KeyRegistry();
      var fail;
      var gate = new Promise(function(resolve, reject) {
        fail = reject;
      });
      registry.register({
        kty: "GATED",
        prepare: function() {
          return gate;
        },
        generate: function() {
          return Promise.reject(new Error("not supported"));
        }
      });

      var store = new JWKStore.KeyStore(registry);
      var adding = store.add({ kty: "GATED", kid: SHARED });
      var view = store.candidates({ kid: SHARED });

      return Promise.resolve().then(function() {
        fail(new Error("import failed"));
        return adding.then(function() {
          assert.ok(false, "the import should have failed");
        }, function(err) {
          assert.equal(err.message, "import failed");
        });
      }).then(function() {
        return view;
      }).then(function(keys) {
        assert.lengthOf(keys, 0);
        // The store is usable again after the failed import.
        return store.candidates({ kid: "anything" });
      }).then(function(keys) {
        assert.lengthOf(keys, 0);
      });
    });

    it("keeps a candidate snapshot immutable across later mutations", function() {
      return keystoreWith([keyA, keyB]).then(function(store) {
        return store.keystore.candidates({ kid: SHARED }).
            then(function(snapshot) {
              assert.lengthOf(snapshot, 2);
              assert.isFrozen(snapshot);
              assert.throws(function() {
                snapshot.push(keyA);
              }, TypeError);
            });
      });
    });

    it("imports a whole set the same way as adding keys one at a time", function() {
      var set = { keys: [keyA.toJSON(true), keyB.toJSON(true)] };
      var viaSet = JWK.asKeyStore(set);
      var viaAdds = keystoreWith([keyA, keyB]).then(function(store) {
        return store.keystore;
      });
      return Promise.all([viaSet, viaAdds]).then(function(stores) {
        var setStore = stores[0],
            addStore = stores[1];
        assert.deepEqual(setStore.toJSON(true), addStore.toJSON(true));
        // Both import paths refuse the same ambiguous set.
        return Promise.all([
          expectedRejection(
              JWS.createVerify(setStore).verify(signature),
              "ERR_JWS_KEY_AMBIGUOUS"),
          expectedRejection(
              JWS.createVerify(addStore).verify(signature),
              "ERR_JWS_KEY_AMBIGUOUS")
        ]);
      });
    });
  });

  describe("explicit single keys", function() {
    it("uses the provided Key alone, ignoring other keys in its keystore", function() {
      // The keystore behind keyA holds an ambiguous duplicate, but an explicit
      // Key is the only candidate for this verifier.
      return keystoreWith([keyA, keyB]).then(function(store) {
        var vfy = JWS.createVerify(store.keys[0]);
        assert.strictEqual(vfy.defaultKey, store.keys[0]);
        return vfy.verify(signature);
      }).then(function(result) {
        return assertSameKey(result.key, keyA);
      });
    });

    it("does not fall back to the keystore when the provided Key is wrong", function() {
      return keystoreWith([keyA, keyB]).then(function(store) {
        // keyB's signature cannot verify keyA's message; no fallback is allowed.
        return expectedRejection(
            JWS.createVerify(store.keys[1]).verify(signature),
            "ERR_JWS_SIGNATURE_INVALID"
        );
      });
    });
  });

  describe("multiple signatures", function() {
    it("still verifies when only one signature has a usable key", function() {
      return Promise.all([
        JWK.createKey("oct", 512, { kid: "multi-a", alg: "HS512" }),
        JWK.createKey("oct", 512, { kid: "multi-b", alg: "HS512" })
      ]).then(function(keys) {
        var a = keys[0], b = keys[1];
        var jws = JWS.createSign({ format: "general" }, [{ key: a }, { key: b }]);
        jws.update(PAYLOAD);
        return jws.final().then(function(result) {
          return keystoreWith([b]).then(function(store) {
            return JWS.createVerify(store.keystore).verify(result);
          });
        });
      }).then(function(result) {
        assert.equal(result.key.kid, "multi-b");
      });
    });

    it("does not hide an ambiguous set by falling through to another signature", function() {
      return Promise.all([
        JWK.createKey("oct", 512, { kid: SHARED, alg: "HS512" }),
        JWK.createKey("oct", 512, { kid: SHARED, alg: "HS512" }),
        JWK.createKey("oct", 512, { kid: "multi-b", alg: "HS512" })
      ]).then(function(keys) {
        var ambiguous = keys.slice(0, 2), usable = keys[2];
        var jws = JWS.createSign({ format: "general" },
                                 [{ key: ambiguous[0] }, { key: usable }]);
        jws.update(PAYLOAD);
        var signaturePromise = jws.final();
        return Promise.all([signaturePromise, keystoreWith(ambiguous.concat([usable]))]);
      }).then(function(values) {
        var result = values[0], store = values[1];
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(result),
            "ERR_JWS_KEY_AMBIGUOUS"
        );
      });
    });
  });

  describe("parent and child collections", function() {
    it("reports ambiguity across a child and its parent", function() {
      return keystoreWith([keyA]).then(function(parent) {
        var child = parent.keystore.temp();
        return child.add(keyB).then(function() {
          assert.lengthOf(child.all({ kid: SHARED }), 2);
          return expectedRejection(
              JWS.createVerify(child).verify(signature),
              "ERR_JWS_KEY_AMBIGUOUS"
          );
        });
      });
    });

    it("resolves a child-only key when the parent has none", function() {
      return keystoreWith([otherKid]).then(function(parent) {
        var child = parent.keystore.temp();
        return child.add(keyA).then(function() {
          return JWS.createVerify(child).verify(signature);
        }).then(function(result) {
          return assertSameKey(result.key, keyA);
        });
      });
    });

    it("resolves a parent key through a child with no local match", function() {
      return keystoreWith([keyA]).then(function(parent) {
        var child = parent.keystore.temp();
        return JWS.createVerify(child).verify(signature);
      }).then(function(result) {
        return assertSameKey(result.key, keyA);
      });
    });

    it("keeps each lookup's result independent of later changes", function() {
      return keystoreWith([keyA, keyB]).then(function(parent) {
        var child = parent.keystore.temp();
        return child.add(keyB).then(function() {
          return child.candidates({ kid: SHARED });
        }).then(function(snapshot) {
          assert.lengthOf(snapshot, 3, "two local copies plus the parent key");
          child.remove(parent.keys[1]);
          parent.keystore.remove(parent.keys[1]);
          assert.lengthOf(snapshot, 3, "snapshot must not be mutated");
          return child.candidates({ kid: SHARED });
        }).then(function(fresh) {
          assert.lengthOf(fresh, 2);
        });
      });
    });

    it("does not leak a parent's key into a local-only query", function() {
      return keystoreWith([keyA]).then(function(parent) {
        var child = parent.keystore.temp();
        return child.candidates({ kid: SHARED }, true).then(function(keys) {
          assert.lengthOf(keys, 0);
          return child.candidates({ kid: SHARED }, false);
        }).then(function(keys) {
          assert.lengthOf(keys, 1);
        });
      });
    });
  });

  describe("embedded key policy", function() {
    var embedded;
    before(function() {
      var jws = JWS.createSign(
          { format: "flattened", protect: false },
          { key: keyA, reference: "jwk" }
      );
      jws.update(PAYLOAD);
      return jws.final().then(function(result) {
        embedded = result;
      });
    });

    it("rejects an embedded key unless explicitly allowed", function() {
      return expectedRejection(
          JWS.createVerify(JWK.createKeyStore()).verify(embedded),
          "ERR_JWS_KEY_NOT_FOUND"
      );
    });

    it("verifies with an embedded key when allowed", function() {
      return JWS.createVerify(JWK.createKeyStore()).
          verify(embedded, { allowEmbeddedKey: true }).
          then(function(result) {
            assert.equal(result.payload.toString("utf8"),
                         PAYLOAD.toString("utf8"));
            assert.equal(result.key.kty, "EC");
          });
    });

    it("honors the per-verifier option as well as the per-call option", function() {
      var verifier = JWS.createVerify(JWK.createKeyStore(),
                                      { allowEmbeddedKey: true });
      return verifier.verify(embedded).then(function(result) {
        assert.equal(result.payload.toString("utf8"),
                     PAYLOAD.toString("utf8"));
      });
    });

    it("prefers the embedded key over the trusted collection when allowed", function() {
      return keystoreWith([otherKid]).then(function(store) {
        return JWS.createVerify(store.keystore).
            verify(embedded, { allowEmbeddedKey: true });
      }).then(function(result) {
        return assertSameKey(result.key, keyA);
      });
    });

    it("rejects an embedded key whose 'kid' names a different key", function() {
      var tampered = cloneJSON(embedded);
      tampered.header = cloneJSON(tampered.header || {});
      tampered.header.kid = "other-kid";
      return expectedRejection(
          JWS.createVerify(JWK.createKeyStore()).
              verify(tampered, { allowEmbeddedKey: true }),
          "ERR_JWS_KEY_CONFLICT"
      );
    });

    it("rejects a message carrying both 'jwk' and 'x5c'", function() {
      var tampered = cloneJSON(embedded);
      tampered.header = cloneJSON(tampered.header || {});
      tampered.header.x5c = ["not-a-certificate"];
      return expectedRejection(
          JWS.createVerify(JWK.createKeyStore()).
              verify(tampered, { allowEmbeddedKey: true }),
          "ERR_JWS_KEY_CONFLICT"
      );
    });

    it("never downloads a key from 'jku' or 'x5u'", function() {
      var tampered = cloneJSON(embedded);
      tampered.header = cloneJSON(tampered.header || {});
      tampered.header.jku = "https://keys.example.test/set.json";
      tampered.header.x5u = "https://keys.example.test/cert.pem";
      // Without an embedded key there is nothing to select; the remote
      // references are ignored rather than fetched.
      delete tampered.header.jwk;
      return expectedRejection(
          JWS.createVerify(JWK.createKeyStore()).
              verify(tampered, { allowEmbeddedKey: true }),
          "ERR_JWS_KEY_NOT_FOUND"
      );
    });
  });

  describe("error diagnostics", function() {
    it("never echoes the payload, key material, or the full message", function() {
      return keystoreWith([keyA, keyB]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(signature),
            "ERR_JWS_KEY_AMBIGUOUS"
        );
      }).then(function(err) {
        var text = JSON.stringify({
          message: err.message,
          details: err.details
        });
        assert.notInclude(text, PAYLOAD.toString("utf8"));
        assert.notInclude(text, keyA.toJSON(true).d);
        assert.notInclude(text, keyB.toJSON(true).d);
        assert.notInclude(text, keyA.toJSON(true).x);
        assert.notInclude(text, signature);
      });
    });

    it("separates failure, unknown 'kid', ambiguity, and disallowed algorithms", function() {
      return keystoreWith([keyA]).then(function(store) {
        var ks = store.keystore;
        return Promise.all([
          expectedRejection(
              JWS.createVerify(ks).verify(tamper(signature)),
              "ERR_JWS_SIGNATURE_INVALID"
          ),
          expectedRejection(
              JWS.createVerify(ks).verify(
                  resign({ alg: "ES256", kid: "absent" })
              ),
              "ERR_JWS_KEY_NOT_FOUND"
          ),
          keystoreWith([keyA, keyB]).then(function(other) {
            return expectedRejection(
                JWS.createVerify(other.keystore).verify(signature),
                "ERR_JWS_KEY_AMBIGUOUS"
            );
          }),
          expectedRejection(
              JWS.createVerify(ks).verify(signature, { algorithms: "HS*" }),
              "ERR_JWS_ALG_NOT_ALLOWED"
          )
        ]);
      });
    });

    it("rejects duplicate protected and unprotected header fields", function() {
      var parts = signature.split(".");
      var protectedJSON = decodeJSON(parts[0]);
      var flattened = {
        payload: parts[1],
        protected: parts[0],
        header: { kid: protectedJSON.kid },
        signature: parts[2]
      };
      return keystoreWith([keyA]).then(function(store) {
        return expectedRejection(
            JWS.createVerify(store.keystore).verify(flattened),
            "ERR_JWS_HEADER_INVALID"
        );
      });
    });

    it("gives each lookup its own immutable candidate result", function() {
      return keystoreWith([keyA]).then(function(store) {
        var ks = store.keystore;
        return Promise.all([
          ks.candidates({ kid: SHARED }),
          ks.candidates({ kid: SHARED })
        ]).then(function(views) {
          assert.notStrictEqual(views[0], views[1]);
          assert.strictEqual(views[0][0], views[1][0]);
          assert.lengthOf(views[0], 1);
          return JWS.createVerify(ks).verify(signature);
        }).then(function(result) {
          return assertSameKey(result.key, keyA);
        });
      });
    });
  });

  // Takes the original protected header, replaces it with {header}, and keeps
  // the original signature.  The signature no longer matches, so only key
  // selection is exercised.
  function resign(header) {
    var parts = signature.split(".");
    return [base64urlJSON(header), parts[1], parts[2]].join(".");
  }

  function tamper(compact) {
    var parts = compact.split(".");
    return [parts[0], parts[1], parts[2].slice(0, -4) + "AAAA"].join(".");
  }
});
