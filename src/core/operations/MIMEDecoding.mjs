/**
 * @author mshwed [m@ttshwed.com]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import { fromHex } from "../lib/Hex.mjs";
import { fromBase64 } from "../lib/Base64.mjs";

/**
 * ISO-8859 parts for which the TextDecoder mapping is identical to the codepage
 * package's. Parts 1, 9 and 11 are aliased to Windows code pages by TextDecoder,
 * and parts 12 and 16 are not supported by every TextDecoder implementation.
 */
const TEXT_DECODER_ISO_8859_PARTS = [2, 3, 4, 5, 6, 7, 8, 10, 13, 14, 15];

/**
 * MIME Decoding operation
 */
class MIMEDecoding extends Operation {

    /**
     * MIMEDecoding constructor
     */
    constructor() {
        super();

        this.name = "MIME Decoding";
        this.module = "Default";
        this.description = "Enables the decoding of MIME message header extensions for non-ASCII text";
        this.infoURL = "https://tools.ietf.org/html/rfc2047";
        this.inputType = "byteArray";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * @param {byteArray} input
     * @param {Object[]} args
     * @returns {string}
     */
    async run(input, args) {
        const mimeEncodedText = Utils.byteArrayToUtf8(input);
        const encodedHeaders = mimeEncodedText.replace(/\r\n/g, "\n");

        const decodedHeader = await this.decodeHeaders(encodedHeaders);

        return decodedHeader;
    }

    /**
     * Decode MIME header strings
     *
     * @param headerString
     */
    async decodeHeaders(headerString) {
        // No encoded words detected
        let i = headerString.indexOf("=?");
        if (i === -1) return headerString;

        let decodedHeaders = headerString.slice(0, i);
        let header = headerString.slice(i);

        let isBetweenWords = false;
        let start, cur, charset, encoding, j, end, text;
        while (header.length > -1) {
            start = header.indexOf("=?");
            if (start === -1) break;
            cur = start + "=?".length;

            i = header.slice(cur).indexOf("?");
            if (i === -1) break;

            charset = header.slice(cur, cur + i);
            cur += i + "?".length;

            if (header.length < cur + "Q??=".length) break;

            encoding = header[cur];
            cur += 1;

            if (header[cur] !== "?") break;

            cur += 1;

            j = header.slice(cur).indexOf("?=");
            if (j === -1) break;

            text = header.slice(cur, cur + j);
            end = cur + j + "?=".length;

            if (encoding.toLowerCase() === "b") {
                text = fromBase64(text, undefined, "byteArray");
            } else if (encoding.toLowerCase() === "q") {
                text = this.parseQEncodedWord(text);
            } else {
                isBetweenWords = false;
                decodedHeaders += header.slice(0, start + 2);
                header = header.slice(start + 2);
            }

            if (start > 0 && (!isBetweenWords || header.slice(0, start).search(/\S/g) > -1)) {
                decodedHeaders += header.slice(0, start);
            }

            decodedHeaders += await this.convertFromCharset(charset, text);

            header = header.slice(end);
            isBetweenWords = true;
        }

        if (header.length > 0) {
            decodedHeaders += header;
        }

        return decodedHeaders;
    }

    /**
     * Converts decoded text for supported charsets.
     * Supports UTF-8, US-ASCII, ISO-8859-*
     *
     * @param encodedWord
     */
    async convertFromCharset(charset, encodedText) {
        charset = charset.toLowerCase();
        const parsedCharset = charset.split("-");
        let page;

        if (parsedCharset.length === 2 && parsedCharset[0] === "utf" && charset === "utf-8") {
            page = 65001;
        } else if (parsedCharset.length === 2 && charset === "us-ascii") {
            page = 20127;
        } else if (parsedCharset.length === 3 && parsedCharset[0] === "iso" && parsedCharset[1] === "8859") {
            const isoCharset = parseInt(parsedCharset[2], 10);
            if (isoCharset >= 1 && isoCharset <= 16) {
                page = 28590 + isoCharset;
            }
        }

        if (page === undefined) throw new OperationError("Unhandled Charset");

        const decoded = this.decodeWithoutCodepage(page, encodedText);
        if (decoded !== null) return decoded;

        // The codepage package is large, so it is only loaded for input that
        // the built-in decoders cannot be relied upon to handle identically.
        const cptable = (await import("codepage")).default;
        return cptable.utils.decode(page, encodedText);
    }

    /**
     * Decodes text without the codepage package where the result is known to be
     * identical to the one it would give.
     *
     * @param {number} page
     * @param {string|byteArray} encodedText
     * @returns {string|null} - null if the codepage package is needed
     */
    decodeWithoutCodepage(page, encodedText) {
        const bytes = typeof encodedText === "string" ?
            encodedText.split("").map(c => c.charCodeAt(0)) :
            encodedText;
        if (bytes.some(b => b > 0xFF)) return null;

        if (page === 20127) {
            return Utils.byteArrayToChars(bytes);
        } else if (page === 65001) {
            try {
                return new TextDecoder("utf-8", {fatal: true}).decode(new Uint8Array(bytes));
            } catch (err) {
                return null;
            }
        }

        // The codepage package treats a null byte as the first half of a
        // two-byte sequence in single-byte code pages
        if (bytes.includes(0)) return null;

        const isoPart = page - 28590;
        if (isoPart === 1) {
            return Utils.byteArrayToChars(bytes);
        } else if (TEXT_DECODER_ISO_8859_PARTS.includes(isoPart)) {
            return new TextDecoder(`iso-8859-${isoPart}`).decode(new Uint8Array(bytes));
        }
        return null;
    }

    /**
     * Parses a Q encoded word
     *
     * @param encodedWord
     */
    parseQEncodedWord(encodedWord) {
        let decodedWord = "";
        for (let i = 0; i < encodedWord.length; i++) {
            if (encodedWord[i] === "_") {
                decodedWord += " ";
            // Parse hex encoding
            } else if (encodedWord[i] === "=") {
                if ((i + 2) >= encodedWord.length) throw new OperationError("Incorrectly Encoded Word");
                const decodedHex = Utils.byteArrayToChars(fromHex(encodedWord.substring(i + 1, i + 3)));
                decodedWord += decodedHex;
                i += 2;
            } else if (
                (encodedWord[i].charCodeAt(0) >= " ".charCodeAt(0) && encodedWord[i].charCodeAt(0) <= "~".charCodeAt(0)) ||
                encodedWord[i] === "\n" ||
                encodedWord[i] === "\r" ||
                encodedWord[i] === "\t") {
                decodedWord += encodedWord[i];
            } else {
                throw new OperationError("Incorrectly Encoded Word");
            }
        }

        return decodedWord;
    }
}

export default MIMEDecoding;
