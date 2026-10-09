/**
 * Loads the codepage package on demand. It is large and only needed when a
 * character encoding other than Raw Bytes is selected, so it is kept out of
 * the main bundle and fetched as a separate chunk the first time it is used.
 *
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

let cptablePromise = null;

/**
 * Returns the codepage package, loading it if necessary.
 *
 * @returns {Promise<Object>}
 */
export function loadCodepage() {
    if (cptablePromise === null) {
        cptablePromise = import("codepage")
            .then(module => module.default)
            .catch(err => {
                // Allow a later call to try again
                cptablePromise = null;
                throw err;
            });
    }
    return cptablePromise;
}
