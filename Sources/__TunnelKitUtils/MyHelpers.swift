//Created by Jahanzeb Sohail


import Foundation

public extension DispatchQueue {
    func arrange(after: DispatchTimeInterval, block: @escaping () -> Void) {
        asyncAfter(deadline: .now() + after, execute: block)
    }
}

public extension Encodable {
    func convertToKeyValue() throws -> [String: Any] {
        let data = try JSONEncoder().encode(self)
        guard let dictionary = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as? [String: Any] else {
            fatalError("JSONSerialization failed to encode")
        }
        return dictionary
    }
}

public func fromKeyValue<T: Decodable>(_ type: T.Type, _ dictionary: [String: Any]) throws -> T {
    let data = try JSONSerialization.data(withJSONObject: dictionary, options: .fragmentsAllowed)
    return try JSONDecoder().decode(T.self, from: data)
}

