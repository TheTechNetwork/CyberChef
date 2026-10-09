/**
 * JWT resources
 *
 * @author mt3571 [mt3571@protonmail.com]
 * @copyright Crown Copyright 2020
 * @license Apache-2.0
 */

import r from "jsrsasign";


/**
 * List of the JWT algorithms that can be used
 */
export const JWT_ALGORITHMS = [
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "None"
];

/**
 * The curve each ECDSA algorithm requires, by its OpenSSL name
 */
const ES_CURVES = {
    ES256: "prime256v1",
    ES384: "secp384r1",
    ES512: "secp521r1"
};

/**
 * The algorithms each type of asymmetric key can be used with
 */
const KEY_TYPE_ALGORITHMS = {
    "ec": ["ES256", "ES384", "ES512"],
    "rsa": ["RS256", "PS256", "RS384", "PS384", "RS512", "PS512"]
};

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

/**
 * Creates an error named like those thrown by the jsonwebtoken library.
 *
 * @param {string} message
 * @param {string} [name="JsonWebTokenError"]
 * @returns {Error}
 */
function jwtError(message, name="JsonWebTokenError") {
    const err = new Error(message);
    err.name = name;
    return err;
}

/**
 * Decodes a base64url string as UTF-8.
 *
 * @param {string} b64u
 * @returns {string}
 */
function b64uToUtf8(b64u) {
    return new TextDecoder().decode(new Uint8Array(r.b64toBA(r.b64utob64(b64u))));
}

/**
 * Serialises a header or payload the way JWS does.
 *
 * @param {*} obj
 * @returns {string}
 */
function jwsString(obj) {
    if (typeof obj === "string") return obj;
    if (typeof obj === "number") return obj.toString();
    return JSON.stringify(obj);
}

/**
 * Whether a value is a plain object (not an array, null, or class instance).
 *
 * @param {*} obj
 * @returns {boolean}
 */
function isPlainObject(obj) {
    if (Object.prototype.toString.call(obj) !== "[object Object]") return false;
    const proto = Object.getPrototypeOf(obj);
    return proto === null || proto === Object.prototype;
}

/**
 * Parses a PEM-encoded key. Returns undefined if it isn't one, in which case
 * the key is treated as an HMAC secret.
 *
 * @param {string} pem
 * @returns {Object|undefined} {key, type, private}
 */
function parseAsymmetricKey(pem) {
    let key;
    try {
        key = r.KEYUTIL.getKey(pem);
    } catch (err) {
        // jsrsasign can't read PKCS#1 "RSA PUBLIC KEY" PEMs, so read the modulus and exponent
        try {
            const hex = r.pemtohex(pem, "RSA PUBLIC KEY");
            key = new r.RSAKey();
            key.setPublic(r.ASN1HEX.getVbyList(hex, 0, [0], "02"), r.ASN1HEX.getVbyList(hex, 0, [1], "02"));
        } catch (err) {
            return undefined;
        }
    }
    let type;
    if (key instanceof r.RSAKey) type = "rsa";
    else if (key instanceof r.KJUR.crypto.ECDSA) type = "ec";
    else if (key instanceof r.KJUR.crypto.DSA) type = "dsa";
    return {key, type, private: !!key.isPrivate};
}

/**
 * Returns the public half of a parsed key, so private keys can verify too.
 *
 * @param {Object} key - As returned by parseAsymmetricKey
 * @returns {Object} jsrsasign public key
 */
function publicKeyOf(key) {
    if (!key.private) return key.key;
    if (key.type === "rsa") {
        const pub = new r.RSAKey();
        pub.setPublic(key.key.n.toString(16), key.key.e.toString(16));
        return pub;
    }
    if (key.type === "ec") {
        return new r.KJUR.crypto.ECDSA({
            curve: key.key.curveName,
            pub: key.key.pubKeyHex || key.key.generatePublicKeyHex()
        });
    }
    return key.key;
}

/**
 * Checks that an asymmetric key can be used with the given algorithm.
 *
 * @param {string} alg
 * @param {Object} key - As returned by parseAsymmetricKey
 * @throws {Error} if it can't
 */
function validateAsymmetricKey(alg, key) {
    if (!key) return;
    const allowed = KEY_TYPE_ALGORITHMS[key.type];
    if (!allowed) {
        throw new Error(`Unknown key type "${key.type}".`);
    }
    if (!allowed.includes(alg)) {
        throw new Error(`"alg" parameter for "${key.type}" key type must be one of: ${allowed.join(", ")}.`);
    }
    if (key.type === "ec") {
        const params = r.KJUR.crypto.ECParameterDB.getByName(key.key.curveName);
        const curve = params ? params.name : key.key.curveName;
        const opensslCurve = curve === "secp256r1" ? "prime256v1" : curve;
        if (opensslCurve !== ES_CURVES[alg]) {
            throw new Error(`"alg" parameter "${alg}" requires curve "${ES_CURVES[alg]}".`);
        }
    }
}

/**
 * Decodes a JWT without verifying it.
 *
 * @param {string} token
 * @param {boolean} [json=false] - Parse the payload as JSON even if the header doesn't say it is a JWT
 * @returns {Object|null} {header, payload, signature}, or null if the token is malformed
 */
export function decodeJWT(token, json=false) {
    if (typeof token !== "string" || !JWS_REGEX.test(token)) return null;
    const [encodedHeader, encodedPayload, signature] = token.split(".");

    let header;
    try {
        header = JSON.parse(b64uToUtf8(encodedHeader));
    } catch (err) {
        return null;
    }
    if (!header) return null;

    let payload = b64uToUtf8(encodedPayload);
    if (header.typ === "JWT" || json) {
        payload = JSON.parse(payload);
    } else {
        try {
            const obj = JSON.parse(payload);
            if (obj !== null && typeof obj === "object") payload = obj;
        } catch (err) {}
    }

    return {header, payload, signature};
}

/**
 * Signs a JWT.
 *
 * @param {*} payload
 * @param {string} secretOrPrivateKey - HMAC secret or PEM-encoded private key
 * @param {string} algorithm
 * @param {Object} [extraHeader={}]
 * @returns {string}
 */
export function signJWT(payload, secretOrPrivateKey, algorithm, extraHeader={}) {
    const isObjectPayload = typeof payload === "object";
    const header = Object.assign({
        alg: algorithm,
        typ: isObjectPayload ? "JWT" : undefined
    }, extraHeader);

    if (!secretOrPrivateKey && algorithm !== "none") {
        throw new Error("secretOrPrivateKey must have a value");
    }

    const key = parseAsymmetricKey(secretOrPrivateKey);
    const privateKey = key && key.private ? key : undefined;

    if (header.alg.startsWith("HS") && privateKey) {
        throw new Error(`secretOrPrivateKey must be a symmetric key when using ${header.alg}`);
    } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
        if (!privateKey) {
            throw new Error(`secretOrPrivateKey must be an asymmetric key when using ${header.alg}`);
        }
        if (!header.alg.startsWith("ES") && privateKey.type === "rsa" && privateKey.key.n.bitLength() < 2048) {
            throw new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`);
        }
    }

    if (isObjectPayload) {
        if (!isPlainObject(payload)) {
            throw new Error("Expected \"payload\" to be a plain object.");
        }
        for (const claim of ["iat", "exp", "nbf"]) {
            if (claim in payload && typeof payload[claim] !== "number") {
                throw new Error(`"${claim}" should be a number of seconds`);
            }
        }
        payload = Object.assign({}, payload);
        payload.iat = payload.iat || Math.floor(Date.now() / 1000);
    }

    if (!isPlainObject(extraHeader)) {
        throw new Error("\"header\" must be an object");
    }

    validateAsymmetricKey(header.alg, privateKey);

    const sHeader = jwsString(header),
        sPayload = jwsString(payload);

    const signingInput = `${r.utf8tob64u(sHeader)}.${r.utf8tob64u(sPayload)}`;
    if (header.alg === "none") {
        return `${signingInput}.`;
    }
    if (header.alg.startsWith("ES")) {
        // JWS.sign doesn't always pad P-521 signatures to the 132 bytes JWS requires
        const bits = header.alg.slice(2);
        const sig = new r.KJUR.crypto.Signature({alg: `SHA${bits}withECDSA`});
        sig.init(privateKey.key);
        sig.updateString(signingInput);
        const rs = r.KJUR.crypto.ECDSA.parseSigHexInHexRS(sig.sign());
        const hexLen = {"256": 64, "384": 96, "512": 132}[bits];
        const toFixed = int => int.replace(/^(?:00)+/, "").padStart(hexLen, "0");
        return `${signingInput}.${r.hextob64u(toFixed(rs.r) + toFixed(rs.s))}`;
    }
    return r.KJUR.jws.JWS.sign(
        header.alg,
        sHeader,
        sPayload,
        privateKey ? privateKey.key : {utf8: secretOrPrivateKey}
    );
}

/**
 * Verifies a JWT's signature and its "nbf" and "exp" claims.
 *
 * @param {string} token
 * @param {string} secretOrPublicKey - HMAC secret or PEM-encoded public key
 * @param {string[]} algorithms - Algorithms to accept
 * @returns {*} The payload
 */
export function verifyJWT(token, secretOrPublicKey, algorithms) {
    if (!token) {
        throw jwtError("jwt must be provided");
    }
    const parts = token.split(".");
    if (parts.length !== 3) {
        throw jwtError("jwt malformed");
    }

    const decoded = decodeJWT(token);
    if (!decoded) {
        throw jwtError("invalid token");
    }
    const {header, payload} = decoded;

    const hasSignature = parts[2].trim() !== "";
    if (!hasSignature && secretOrPublicKey) {
        throw jwtError("jwt signature is required");
    }
    if (hasSignature && !secretOrPublicKey) {
        throw jwtError("secret or public key must be provided");
    }

    if (algorithms.indexOf(header.alg) === -1) {
        throw jwtError("invalid algorithm");
    }

    // Any key that parses (public, private or certificate) can verify
    const key = parseAsymmetricKey(secretOrPublicKey);
    if (header.alg.startsWith("HS") && key) {
        throw jwtError(`secretOrPublicKey must be a symmetric key when using ${header.alg}`);
    } else if (/^(?:RS|PS|ES)/.test(header.alg) && !key) {
        throw jwtError(`secretOrPublicKey must be an asymmetric key when using ${header.alg}`);
    }

    validateAsymmetricKey(header.alg, key);

    let valid;
    if (header.alg === "none") {
        valid = parts[2] === "";
    } else {
        try {
            valid = r.KJUR.jws.JWS.verify(token, key ? publicKeyOf(key) : {utf8: secretOrPublicKey}, [header.alg]);
        } catch (err) {
            valid = false;
        }
    }
    if (!valid) {
        throw jwtError("invalid signature");
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.nbf !== "undefined") {
        if (typeof payload.nbf !== "number") {
            throw jwtError("invalid nbf value");
        }
        if (payload.nbf > now) {
            throw jwtError("jwt not active", "NotBeforeError");
        }
    }
    if (typeof payload.exp !== "undefined") {
        if (typeof payload.exp !== "number") {
            throw jwtError("invalid exp value");
        }
        if (now >= payload.exp) {
            throw jwtError("jwt expired", "TokenExpiredError");
        }
    }

    return payload;
}
