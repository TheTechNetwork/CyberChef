/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import forge from "node-forge";

/**
 * The LAN Manager hashing algorithm only uses the first 14 characters of the
 * uppercased password.
 */
const LM_HASH_MAX_LENGTH = 14;

/**
 * Spreads a 7-byte (56-bit) key over the 8 bytes DES expects, leaving the
 * low (parity) bit of each byte clear. DES ignores the parity bits.
 *
 * @param {number[]} key56
 * @returns {string} The 8-byte key as a binary string
 */
function expandDESKey(key56) {
    const key64 = [];
    for (let i = 0; i < 8; i++) {
        const hi = i > 0 ? key56[i - 1] << (8 - i) : 0;
        const lo = i < 7 ? key56[i] >> i : 0;
        key64.push((hi | lo) & 0xfe);
    }
    return String.fromCharCode(...key64);
}

/**
 * LM Hash operation
 */
class LMHash extends Operation {

    /**
     * LMHash constructor
     */
    constructor() {
        super();

        this.name = "LM Hash";
        this.module = "Crypto";
        this.description = "An LM Hash, or LAN Manager Hash, is a deprecated way of storing passwords on old Microsoft operating systems. It is particularly weak and can be cracked in seconds on modern hardware using rainbow tables.";
        this.infoURL = "https://wikipedia.org/wiki/LAN_Manager#Password_hashing_algorithm";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // Uppercase *before* truncating to 14 characters. Some characters
        // expand when uppercased (e.g. "ß" -> "SS"), which must not push the
        // password past 14 bytes (#1807).
        const password = input.toUpperCase().slice(0, LM_HASH_MAX_LENGTH);

        // Null-pad to 14 bytes, keeping the low byte of each character
        const key = new Array(LM_HASH_MAX_LENGTH).fill(0);
        for (let i = 0; i < password.length; i++) {
            key[i] = password.charCodeAt(i) & 0xff;
        }

        // Each 7-byte half is a DES key that encrypts the magic "KGS!@#$%"
        let hash = "";
        for (const half of [key.slice(0, 7), key.slice(7)]) {
            const cipher = forge.cipher.createCipher("DES-ECB", expandDESKey(half));
            cipher.start();
            cipher.update(forge.util.createBuffer("KGS!@#$%"));
            cipher.finish(() => true); // No padding
            hash += cipher.output.toHex();
        }
        return hash.toUpperCase();
    }

}

export default LMHash;
