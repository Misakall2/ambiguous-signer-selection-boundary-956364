#!/usr/bin/env node
/*!
 * examples/ambiguous-kid-migration.js - Offline demonstration of the key
 * selection boundary for duplicate key identifiers.
 *
 * Everything here runs locally: keys are generated with node-jose itself and
 * no network or authorization service is involved.
 */
"use strict";

var jose = require("../lib");

var PAYLOAD = Buffer.from("offline selection boundary demo", "utf8");

function fingerprint(key) {
  return key.thumbprint("SHA-256").then(function(print) {
    return print.toString("hex").slice(0, 16);
  });
}

function buildKeystore(keys) {
  var ks = jose.JWK.createKeyStore();
  var chain = Promise.resolve();
  keys.forEach(function(key) {
    chain = chain.then(function() {
      return ks.add(key);
    });
  });
  return chain.then(function() {
    return ks;
  });
}

function tryVerify(label, keystore, signature) {
  return jose.JWS.createVerify(keystore).verify(signature).then(function(result) {
    console.log("  " + label + ": ACCEPTED payload=" +
                JSON.stringify(result.payload.toString("utf8")) +
                " kid=" + result.key.kid);
    return { label: label, accepted: true, key: result.key };
  }, function(err) {
    console.log("  " + label + ": REJECTED code=" + err.code +
                " message=" + JSON.stringify(err.message));
    if (err.details && err.details.candidates) {
      var described = err.details.candidates.map(function(c) {
        return c.kid + "/" + c.kty + "/" + c.alg;
      });
      console.log("    candidates: " + described.join(", "));
    }
    return { label: label, accepted: false, code: err.code };
  });
}

function main() {
  var keyA, keyB, encKey, otherKid, signature;

  console.log("== 1. Generate two same-type keys that share a 'kid' ==");
  return Promise.all([
    jose.JWK.createKey("EC", "P-256", { kid: "shared-kid", alg: "ES256", use: "sig" }),
    jose.JWK.createKey("EC", "P-256", { kid: "shared-kid", alg: "ES256", use: "sig" }),
    jose.JWK.createKey("EC", "P-256", { kid: "shared-kid", use: "enc" }),
    jose.JWK.createKey("EC", "P-256", { kid: "rotation-2024", alg: "ES256", use: "sig" })
  ]).then(function(keys) {
    keyA = keys[0];
    keyB = keys[1];
    encKey = keys[2];
    otherKid = keys[3];
    return Promise.all([fingerprint(keyA), fingerprint(keyB)]);
  }).then(function(prints) {
    console.log("  key A thumbprint: " + prints[0]);
    console.log("  key B thumbprint: " + prints[1]);
    return jose.JWS.createSign({ format: "compact", protect: "*" }, keyA).
        final(PAYLOAD, "utf8");
  }).then(function(result) {
    signature = result;

    console.log("");
    console.log("== 2. Behaviour before the fix (import order decided the key) ==");
    console.log("  The old verifier called keystore.get(), which returns the");
    console.log("  first match. With A first the signature verified; with B first");
    console.log("  verification failed with 'no key found' -- the same message");
    console.log("  set, the same message body, a different verdict.");

    return buildKeystore([keyA, keyB]);
  }).then(function(ks) {
    console.log("");
    console.log("== 3. Both import orders now refuse the ambiguous set ==");
    return tryVerify("A then B", ks, signature).then(function() {
      return buildKeystore([keyB, keyA]);
    }).then(function(reversed) {
      return tryVerify("B then A", reversed, signature);
    });
  }).then(function() {
    console.log("");
    console.log("== 4. A same-'kid' key with use 'enc' is not a candidate ==");
    return buildKeystore([keyA, encKey]);
  }).then(function(ks) {
    return tryVerify("A + enc key", ks, signature);
  }).then(function() {
    console.log("");
    console.log("== 5. Resolving the ambiguity: remove the unused duplicate ==");
    return buildKeystore([keyA, keyB]).then(function(ks) {
      var found = ks.all({ kid: "shared-kid" });
      // Remove the copy imported second (keyB); keys are copied on import.
      ks.remove(found[1]);
      return tryVerify("after remove", ks, signature);
    });
  }).then(function() {
    console.log("");
    console.log("== 6. A clean single-candidate set keeps verifying ==");
    return jose.JWS.createSign({ format: "compact", protect: "*" }, otherKid).
        final(PAYLOAD, "utf8");
  }).then(function(rotationSignature) {
    return buildKeystore([otherKid, encKey]).then(function(ks) {
      return tryVerify("single candidate", ks, rotationSignature);
    });
  }).then(function() {
    console.log("");
    console.log("== 7. Distinguishing the failure classes ==");
    return buildKeystore([keyA]);
  }).then(function(ks) {
    var verify = jose.JWS.createVerify(ks);
    var parts = signature.split(".");
    var header = JSON.parse(Buffer.from(parts[0], "base64").toString("utf8"));
    header.kid = "unknown-kid";
    var unknown = [
      Buffer.from(JSON.stringify(header), "utf8").toString("base64url"),
      parts[1],
      parts[2]
    ].join(".");
    var damaged = [parts[0], parts[1], parts[2].slice(0, -4) + "AAAA"].join(".");

    return verify.verify(unknown).then(function() {
      console.log("  unknown kid: UNEXPECTED SUCCESS");
    }, function(err) {
      console.log("  unknown kid: " + err.code);
    }).then(function() {
      return verify.verify(damaged).then(function() {
        console.log("  damaged signature: UNEXPECTED SUCCESS");
      }, function(err) {
        console.log("  damaged signature: " + err.code);
      });
    }).then(function() {
      return verify.verify(signature, { algorithms: ["RS256"] }).then(function() {
        console.log("  disallowed algorithm: UNEXPECTED SUCCESS");
      }, function(err) {
        console.log("  disallowed algorithm: " + err.code);
      });
    });
  }).then(function() {
    console.log("");
    console.log("== 8. Migration summary ==");
    console.log("  * keystore.get()/all() are unchanged public queries.");
    console.log("  * Verification now requires exactly one distinct candidate.");
    console.log("  * Ensure each 'kid' identifies one key per purpose; otherwise");
    console.log("    remove the stale key (as in step 5) or scope the verifier to a");
    console.log("    key-specific keystore.");
    console.log("  * Inspect err.code (ERR_JWS_KEY_AMBIGUOUS, ...) instead of text.");
  });
}

main().catch(function(err) {
  console.error("demo failed:", err && err.stack || err);
  process.exit(1);
});
