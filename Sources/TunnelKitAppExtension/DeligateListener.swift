
import Foundation
#if os(iOS)
import SystemConfiguration.CaptiveNetwork
import NetworkExtension
#elseif os(macOS)
import CoreWLAN
#endif




/// Observes changes in the current Wi-Fi network.
public class DeligateListener: NSObject {

    /// A change in Wi-Fi state occurred.
    public static let didDetectWifiChange = Notification.Name("InterfaceObserverDidDetectWifiChange")

    private var queue: DispatchQueue?

    private var timer: DispatchSourceTimer?

    private var lastWifiName: String?

   

    private func fireWifiChangeObserver() {
        DeligateListener.getXXID {
            self.fireWifiChange(withSSID: $0)
        }
    }
    
    public func stop() {
        timer?.cancel()
        timer = nil
        queue = nil
    }
    
    public func start(queue: DispatchQueue) {
        self.queue = queue

        let timer = DispatchSource.makeTimerSource(flags: DispatchSource.TimerFlags(rawValue: UInt(0)), queue: queue)
        timer.schedule(deadline: .now(), repeating: .seconds(2))
        timer.setEventHandler {
            self.fireWifiChangeObserver()
        }
        timer.resume()

        self.timer = timer
    }
   

    public static func getXXID(completionHandler: @escaping (String?) -> Void) {
        #if os(iOS)
        NEHotspotNetwork.fetchCurrent {
            completionHandler($0?.ssid)
        }
        #elseif os(macOS)
        let client = CWWiFiClient.shared()
        let ssid = client.interfaces()?.compactMap { $0.ssid() }.first
        completionHandler(ssid)
        #else
        completionHandler(nil)
        #endif
    }
    private func fireWifiChange(withSSID ssid: String?) {
        if ssid != lastWifiName {
            if let current = ssid {

                if let last = lastWifiName, (current != last) {
                    queue?.async {
                        NotificationCenter.default.post(name: DeligateListener.didDetectWifiChange, object: nil)
                    }
                }
            } else {

            }
        }
        lastWifiName = ssid
    }

    
}
