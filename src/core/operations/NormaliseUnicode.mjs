/**
 * @author Matthieu [m@tthieu.xyz]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import {UNICODE_NORMALISATION_FORMS} from "../lib/ChrEnc.mjs";

/**
 * Normalise Unicode operation
 */
class NormaliseUnicode extends Operation {

    /**
     * NormaliseUnicode constructor
     */
    constructor() {
        super();

        this.name = "Normalise Unicode";
        this.module = "Encodings";
        this.description = "Transform Unicode characters to one of the Normalisation Forms";
        this.infoURL = "https://wikipedia.org/wiki/Unicode_equivalence#Normal_forms";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Normal Form",
                type: "option",
                value: UNICODE_NORMALISATION_FORMS
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [normalForm] = args;

        switch (normalForm) {
            case "NFD":
                return input.normalize("NFD");
            case "NFC":
                return input.normalize("NFC");
            case "NFKD":
                return input.normalize("NFKD");
            case "NFKC":
                return input.normalize("NFKC");
            default:
                throw new OperationError("Unknown Normalisation Form");
        }
    }

}

export default NormaliseUnicode;
