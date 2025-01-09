

import Foundation

extension OpenVPN {

    public enum SetupError: Error {
        case unsupportedConfiguration(option: String)
        case continuationPushReply
        case malformed(option: String)
        case encryptionPassphrase
        case missingConfiguration(option: String)
        case unableToDecrypt(error: Error)
    }

}
