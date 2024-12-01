
export const globalCrypto = (setGlobal: boolean, suppliedCrypto?: Crypto): Crypto => {
    let webcrypto: Crypto
    if (typeof suppliedCrypto !== 'undefined') {
        webcrypto = suppliedCrypto
    } else if (typeof crypto !== 'undefined') {
        webcrypto = crypto
    } else if (typeof global.crypto !== 'undefined') {
        webcrypto = global.crypto
    } else if (typeof global.window?.crypto?.subtle !== 'undefined') {
        webcrypto = global.window.crypto
    } else {
        webcrypto = require('crypto') as Crypto
    }
    if (setGlobal) {
        global.crypto = webcrypto
    }

    return webcrypto
}
