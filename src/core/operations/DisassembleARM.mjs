/**
 * @author MedjedThomasXM
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import { isWorkerEnvironment } from "../Utils.mjs";
import MCapstone from "@alexaltea/capstone-js";

// capstone-js v5 is a WebAssembly build: the package no longer ships the synchronous
// dist/capstone.min.js asm.js bundle, and its entry point is an async factory that
// resolves to the module.
let capstoneModule = null;

/**
 * Loads the Capstone WebAssembly module, reusing the promise across runs since
 * instantiating it is not cheap.
 *
 * @returns {Promise} resolves to the Capstone module
 */
function loadCapstone() {
    if (capstoneModule === null) {
        // Emscripten locates capstone.wasm relative to the script that loaded it, which in
        // the browser is the bundle rather than the file webpack copied into assets/. Node
        // finds it next to capstone.js on its own.
        capstoneModule = MCapstone(isWorkerEnvironment() ?
            {locateFile: (file) => `${self.docURL}/assets/capstone/${file}`} :
            {});
    }
    return capstoneModule;
}

/**
 * Disassemble ARM operation
 */
class DisassembleARM extends Operation {

    /**
     * DisassembleARM constructor
     */
    constructor() {
        super();

        this.name = "Disassemble ARM";
        this.module = "Shellcode";
        this.description = "Disassembles ARM machine code into assembly language.<br><br>Supports ARM (32-bit), Thumb, and ARM64 (AArch64) architectures using the Capstone disassembly framework.<br><br>Input should be in hexadecimal.";
        this.infoURL = "https://wikipedia.org/wiki/ARM_architecture_family";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Architecture",
                "type": "option",
                "value": ["ARM (32-bit)", "ARM64 (AArch64)"]
            },
            {
                "name": "Mode",
                "type": "option",
                "value": ["ARM", "Thumb", "Thumb + Cortex-M", "ARMv8"]
            },
            {
                "name": "Endianness",
                "type": "option",
                "value": ["Little Endian", "Big Endian"]
            },
            {
                "name": "Starting address (hex)",
                "type": "number",
                "value": 0
            },
            {
                "name": "Show instruction hex",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Show instruction position",
                "type": "boolean",
                "value": true
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    async run(input, args) {
        const [
            architecture,
            mode,
            endianness,
            startAddress,
            showHex,
            showPosition
        ] = args;

        // Remove whitespace from input
        const hexInput = input.replace(/\s/g, "");

        // Validate hex input
        if (!/^[0-9a-fA-F]*$/.test(hexInput)) {
            throw new OperationError("Invalid hexadecimal input. Please provide valid hex characters only.");
        }

        if (hexInput.length === 0) {
            return "";
        }

        if (hexInput.length % 2 !== 0) {
            throw new OperationError("Invalid hexadecimal input. Length must be even.");
        }

        const cs = await loadCapstone();

        // Convert hex string to byte array
        const bytes = [];
        for (let i = 0; i < hexInput.length; i += 2) {
            bytes.push(parseInt(hexInput.substr(i, 2), 16));
        }

        // Determine architecture constant
        let arch;
        if (architecture === "ARM64 (AArch64)") {
            arch = cs.ARCH_ARM64;
        } else {
            arch = cs.ARCH_ARM;
        }

        // Determine mode constant
        let modeValue;

        if (architecture === "ARM (32-bit)") {
            switch (mode) {
                case "ARM":
                    modeValue = cs.MODE_ARM;
                    break;
                case "Thumb":
                    modeValue = cs.MODE_THUMB;
                    break;
                case "Thumb + Cortex-M":
                    modeValue = cs.MODE_THUMB | cs.MODE_MCLASS;
                    break;
                case "ARMv8":
                    modeValue = cs.MODE_ARM | cs.MODE_V8;
                    break;
                default:
                    modeValue = cs.MODE_ARM;
            }
        } else {
            // ARM64 only has one mode (ARM mode is default for ARM64)
            modeValue = cs.MODE_ARM;
        }

        // Add endianness
        if (endianness === "Big Endian") {
            modeValue |= cs.MODE_BIG_ENDIAN;
        }

        if (isWorkerEnvironment()) {
            self.sendStatusMessage("Disassembling...");
        }

        let disassembler;
        try {
            disassembler = new cs.Capstone(arch, modeValue);
        } catch (e) {
            throw new OperationError(`Failed to initialise Capstone disassembler: ${e}`);
        }

        let instructions;
        try {
            instructions = disassembler.disasm(bytes, startAddress);
        } catch (e) {
            disassembler.close();
            // Check if it's a "no valid instructions" error (code 0 means OK but nothing decoded)
            if (e && e.includes && e.includes("code 0:")) {
                throw new OperationError(`No valid ${architecture} instructions found in input. The bytes may be for a different architecture or mode.`);
            }
            throw new OperationError(`Disassembly failed: ${e}`);
        }

        // Format output
        const output = [];
        for (const insn of instructions) {
            let line = "";

            if (showPosition) {
                // Format address as hex with 0x prefix
                const addrHex = "0x" + insn.address.toString(16).padStart(8, "0");
                line += addrHex + "  ";
            }

            if (showHex) {
                // Format instruction bytes as hex
                const bytesHex = insn.bytes.map(b => b.toString(16).padStart(2, "0")).join("");
                line += bytesHex.padEnd(16, " ") + "  ";
            }

            line += insn.mnemonic;
            if (insn.op_str) {
                line += " " + insn.op_str;
            }

            output.push(line);
        }

        disassembler.close();

        return output.join("\n");
    }

}

export default DisassembleARM;
