

import Foundation

public enum PersistanceError: Error {
    case userCancelled
    case notFound
    case add
    
}

public class Keychain {
    private let accessGroup: String?

    public init(group: String?) {
        accessGroup = group
    }

    @discardableResult
    public func set(password: String, for username: String, context: String, userDefined: String? = nil, label: String? = nil) throws -> Data {
        do {
            let currentPassword = try self.password(for: username, context: context)
            guard password != currentPassword else {
                return try passwordReference(for: username, context: context)
            }
            removePassword(for: username, context: context)
        } catch let error as TunnelKitManagerError {

            if case .keychain(.userCancelled) = error {
                throw error
            }

        } catch {

            throw error
        }

        var query = [String: Any]()
        setScope(query: &query, context: context, userDefined: userDefined)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrLabel as String] = label
        query[kSecAttrAccount as String] = username
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        query[kSecValueData as String] = password.data(using: .utf8)
        query[kSecReturnPersistentRef as String] = true

        var ref: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &ref)
        guard status == errSecSuccess, let refData = ref as? Data else {
            throw TunnelKitManagerError.keychain(.add)
        }
        return refData
    }

    @discardableResult public func removePassword(for username: String, context: String, userDefined: String? = nil) -> Bool {
        var query = [String: Any]()
        setScope(query: &query, context: context, userDefined: userDefined)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

    public func password(for username: String, context: String, userDefined: String? = nil) throws -> String {
        var query = [String: Any]()
        setScope(query: &query, context: context, userDefined: userDefined)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true

        var result: AnyObject?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            break

        case errSecUserCanceled:
            throw TunnelKitManagerError.keychain(.userCancelled)

        default:
            throw TunnelKitManagerError.keychain(.notFound)
        }
        guard let data = result as? Data else {
            throw TunnelKitManagerError.keychain(.notFound)
        }
        guard let password = String(data: data, encoding: .utf8) else {
            throw TunnelKitManagerError.keychain(.notFound)
        }
        return password
    }


    public func passwordReference(for username: String, context: String, userDefined: String? = nil) throws -> Data {
        var query = [String: Any]()
        setScope(query: &query, context: context, userDefined: userDefined)
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrAccount as String] = username
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnPersistentRef as String] = true

        var result: AnyObject?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            break

        case errSecUserCanceled:
            throw TunnelKitManagerError.keychain(.userCancelled)

        default:
            throw TunnelKitManagerError.keychain(.notFound)
        }
        guard let data = result as? Data else {
            throw TunnelKitManagerError.keychain(.notFound)
        }
        return data
    }

    public static func password(forReference reference: Data) throws -> String {
        var query = [String: Any]()
        query[kSecValuePersistentRef as String] = reference
        query[kSecReturnData as String] = true

        var result: AnyObject?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            break

        case errSecUserCanceled:
            throw TunnelKitManagerError.keychain(.userCancelled)

        default:
            throw TunnelKitManagerError.keychain(.notFound)
        }
        guard let data = result as? Data else {
            throw TunnelKitManagerError.keychain(.notFound)
        }
        guard let password = String(data: data, encoding: .utf8) else {
            throw TunnelKitManagerError.keychain(.notFound)
        }
        return password
    }

    public func add(publicKeyWithIdentifier identifier: String, data: Data) throws -> SecKey {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        query[kSecValueData as String] = data
        query.removeValue(forKey: kSecAttrService as String)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TunnelKitManagerError.keychain(.add)
        }
        return try publicKey(withIdentifier: identifier)
    }

    public func publicKey(withIdentifier identifier: String) throws -> SecKey {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic
        query[kSecReturnRef as String] = true

        query.removeValue(forKey: kSecAttrService as String)

        var result: AnyObject?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            break

        case errSecUserCanceled:
            throw TunnelKitManagerError.keychain(.userCancelled)

        default:
            throw TunnelKitManagerError.keychain(.notFound)
        }
        return result as! SecKey
    }

    @discardableResult public func remove(publicKeyWithIdentifier identifier: String) -> Bool {
        var query = [String: Any]()
        query[kSecClass as String] = kSecClassKey
        query[kSecAttrApplicationTag as String] = identifier
        query[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        query[kSecAttrKeyClass as String] = kSecAttrKeyClassPublic

        // XXX
        query.removeValue(forKey: kSecAttrService as String)

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

        public func setScope(query: inout [String: Any], context: String, userDefined: String?) {
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
            #if os(macOS)
            query[kSecUseDataProtectionKeychain as String] = true
            #endif
        }
        query[kSecAttrService as String] = context
        if let userDefined = userDefined {
            query[kSecAttrGeneric as String] = userDefined
        }
    }
}
