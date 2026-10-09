/**
 * Checks that the code paths which avoid loading the codepage package give the
 * same results as the package itself.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../../lib/TestRegister.mjs";
import it from "../../assertionHandler.mjs";
import assert from "assert";
import cptable from "codepage";
import { CHR_ENC_CODE_PAGES, chrEncWidth } from "../../../../src/core/lib/ChrEnc.mjs";
import MIMEDecoding from "../../../../src/core/operations/MIMEDecoding.mjs";

/**
 * The previous, codepage-based, implementation of chrEncWidth.
 *
 * @param {number} page
 * @returns {number}
 */
function codepageChrEncWidth(page) {
    const pageStr = page.toString();
    if (Object.prototype.hasOwnProperty.call(cptable, pageStr))
        return cptable[pageStr].dec.length > 256 ? 2 : 1;
    if (cptable.utils.cache.sbcs.includes(pageStr)) return 1;
    if (cptable.utils.cache.dbcs.includes(pageStr)) return 2;
    if (Object.prototype.hasOwnProperty.call(cptable.utils.magic, pageStr))
        return cptable.utils.encode(page, "a").length;
    return 0;
}

const MIME_CHARSETS = ["utf-8", "us-ascii"];
for (let i = 1; i <= 16; i++) MIME_CHARSETS.push(`iso-8859-${i}`);

/**
 * @param {string} charset
 * @returns {number}
 */
function mimeCharsetPage(charset) {
    if (charset === "utf-8") return 65001;
    if (charset === "us-ascii") return 20127;
    return 28590 + parseInt(charset.split("-")[2], 10);
}

const MIME_SAMPLES = [[]];
for (let b = 0; b < 256; b++) MIME_SAMPLES.push([b], [0x41, b, 0x42], [b, 0]);
MIME_SAMPLES.push(
    [0, 0x41, 0x42],
    [0xEF, 0xBB, 0xBF, 0x41],
    [0xE4, 0xB8, 0x8D, 0xE8, 0xA6, 0x81],
    [0xF0, 0x9F, 0x98, 0x80],
    [0xE4, 0xB8],
    [0xC3, 0x28],
    [0xED, 0xA0, 0x80],
    [0xF8, 0x88, 0x80, 0x80, 0x80]
);

TestRegister.addApiTests([
    it("ChrEnc: chrEncWidth matches the codepage package", () => {
        assert.strictEqual(chrEncWidth(0), 1);
        assert.strictEqual(chrEncWidth("65001"), 0);
        assert.strictEqual(chrEncWidth(12345), 0);
        for (const name in CHR_ENC_CODE_PAGES) {
            const page = CHR_ENC_CODE_PAGES[name];
            assert.strictEqual(chrEncWidth(page), codepageChrEncWidth(page), name);
        }
    }),

    it("MIME Decoding: charset conversion matches the codepage package", async () => {
        const op = new MIMEDecoding();
        for (const charset of MIME_CHARSETS) {
            const page = mimeCharsetPage(charset);
            for (const bytes of MIME_SAMPLES) {
                const str = bytes.map(b => String.fromCharCode(b)).join("");
                for (const input of [bytes, str]) {
                    let expected, actual;
                    try {
                        expected = cptable.utils.decode(page, input);
                    } catch (err) {
                        expected = err.message;
                    }
                    try {
                        actual = await op.convertFromCharset(charset, input);
                    } catch (err) {
                        actual = err.message;
                    }
                    assert.strictEqual(actual, expected, `${charset} ${JSON.stringify(bytes)} ${typeof input}`);
                }
            }
        }
    }),
]);
