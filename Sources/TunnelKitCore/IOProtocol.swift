

import Foundation

public protocol IOProtocol: AnyObject {
    func readingCompletion(task: DispatchQueue, _ handler: @escaping ([Data]?, Error?) -> Void)
    func singleDataWritten(_ packet: Data, completionHandler: ((Error?) -> Void)?)
    func multiplePacketsDataWritten(_ packets: [Data], completionHandler: ((Error?) -> Void)?)
}
