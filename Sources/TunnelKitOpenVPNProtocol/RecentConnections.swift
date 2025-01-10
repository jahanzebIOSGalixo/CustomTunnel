

import Foundation
import TunnelKitOpenVPNCore

extension OpenVPN {
    struct RecentConnections: CustomStringConvertible {
       
        let more: Configuration
        var description: String {
            let stripped = NSMutableString(string: selected)
            ConfigurationParser.Regex.authToken.replaceMatches(
                in: stripped,
                options: [],
                range: NSRange(location: 0, length: stripped.length),
                withTemplate: "auth-token"
            )
            return stripped as String
        }
        private static let prefix = "PUSH_REPLY,"

        private let selected: String
        init?(message: String) throws {
            guard message.hasPrefix(RecentConnections.prefix) else {
                return nil
            }
            guard let prefixIndex = message.range(of: RecentConnections.prefix)?.lowerBound else {
                return nil
            }
            selected = String(message[prefixIndex...])

            let lines = selected.components(separatedBy: ",")
            more = try ConfigurationParser.parsed(fromLines: lines).configuration
        }        
    }
}
