//Created by Jahanzeb Sohail


import Foundation

extension NSRegularExpression {
    public func galixoComponents(in input: String, using handler: ([String]) -> Void) {
        enumerateMatches(in: input, options: [], range: NSRange(location: 0, length: input.utf16.count)) { match, _, _ in
            guard let matchedRange = match?.range else { return }
            let extractedMatch = (input as NSString).substring(with: matchedRange)
            let filteredTokens = extractedMatch.split(separator: " ").map { String($0) }
            handler(filteredTokens)
        }
    }

    public func galixoArguments(in input: String, using handler: ([String]) -> Void) {
        galixoComponents(in: input) { components in
            guard !components.isEmpty else {
                handler([])
                return
            }
            var arguments = components
            arguments.removeFirst()
            handler(arguments)
        }
    }
}

extension NSRegularExpression {
    public convenience init(_ pattern: String) {
        try! self.init(pattern: pattern, options: [])
    }

    public func galixoGrouping(in input: String) -> [String] {
        var extractedResults: [String] = []
        enumerateMatches(in: input, options: [], range: NSRange(location: 0, length: input.utf16.count)) { match, _, _ in
            guard let match = match else { return }
            for groupIndex in 0..<numberOfCaptureGroups {
                let rangeForGroup = match.range(at: groupIndex + 1)
                if rangeForGroup.location != NSNotFound {
                    let capturedText = (input as NSString).substring(with: rangeForGroup)
                    extractedResults.append(capturedText)
                }
            }
        }
        return extractedResults
    }

}
