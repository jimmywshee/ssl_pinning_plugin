import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftSslPinningPlugin: NSObject, FlutterPlugin {
    
    let manager = Alamofire.SessionManager.default
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "ssl_pinning_plugin", binaryMessenger: registrar.messenger())
        let instance = SwiftSslPinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        self.flutterResult = result
        switch (call.method) {
        case "check":
            if let _args = call.arguments as? Dictionary<String, AnyObject> {
                self.check(call: call, args: _args)
            } else {
                result(FlutterError(code: "Arguments vide", message: "Veuillez préciser les arguments", details: nil))
            }
            break
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    public func sendResponse(result: AnyObject){
        if let _res = self.flutterResult{
            _res(result)
        }
    }
    
    public func check(call: FlutterMethodCall, args: Dictionary<String, AnyObject>){
        // Récupération des params
        guard let _urlString = args["url"] as? String,
              let _httpMethod = args["httpMethod"] as? String,
              let _headers = args["headers"] as? Dictionary<String, String>,
              let _fingerprints = args["fingerprints"] as? Array<String>,
              let _type = args["type"] as? String
        else {
            self.sendResponse(result: FlutterError(code: "Params incorrect", message: "Les params sont incorrect", details: nil))
            return
        }
        
        self.fingerprints = _fingerprints
        
        // Timeout en millisecond
        var _timeout = 60
        if let _timeoutArg = args["timeout"] as? Int {
            _timeout = _timeoutArg
        }
        
        Alamofire.request(_urlString, method: _httpMethod == "Head" ? .head : .get, parameters: _headers).validate().responseJSON() { response in
            switch response.result {
            case .success:
                break
            case .failure(let error):
                self.sendResponse(result: FlutterError(code: "URL Format", message: error.localizedDescription, details: nil))
                break
            }
        }
        
        manager.session.configuration.timeoutIntervalForRequest = TimeInterval(_timeout)
        
        manager.delegate.sessionDidReceiveChallenge = { session, challenge in
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let serverTrust = challenge.protectionSpace.serverTrust else {
                return (.cancelAuthenticationChallenge, nil)
            }
            
            var secResult = SecTrustResultType.invalid
            let evalStatus = SecTrustEvaluate(serverTrust, &secResult)
            
            guard evalStatus == errSecSuccess else {
                self.sendResponse(result: FlutterError(code: "ERROR CERT", message: "", details: nil))
                return (.cancelAuthenticationChallenge, nil)
            }
            
            var chain: [SecCertificate] = []
            if #available(iOS 15.0, *) {
                if let certs = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
                    chain = certs
                }
            } else {
                let count = SecTrustGetCertificateCount(serverTrust)
                for i in 0..<count {
                    if let c = SecTrustGetCertificateAtIndex(serverTrust, i) {
                        chain.append(c)
                    }
                }
            }
            
            if chain.isEmpty {
                self.sendResponse(result: FlutterError(code: "ERROR CERT", message: "", details: nil))
                return (.cancelAuthenticationChallenge, nil)
            }
            
            let allowedSet: Set<String> = Set((self.fingerprints ?? []).map{
                $0.uppercased().replacingOccurrences(of: "[^A-F0-9]", with: "", options: .regularExpression)
            })
            
            func fingerprintHex(of data: Data, type: String) -> String {
                let normalized = type.uppercased().replacingOccurrences(of: "-", with: "")
                switch normalized {
                case "SHA1":
                    return data.sha1().toHexString().uppercased()
                case "SHA256":
                    return data.sha256().toHexString().uppercased()
                case "SHA384":
                    return data.sha384().toHexString().uppercased()
                case "SHA512":
                    return data.sha512().toHexString().uppercased()
                default:
                    return data.sha256().toHexString().uppercased()
                }
            }
            
            var isSecure = false
            for cert in chain {
                let data = SecCertificateCopyData(cert) as Data
                let hex = fingerprintHex(of: data, type: _type)
                if allowedSet.contains(hex) {
                    isSecure = true
                    break
                }
            }
            
            if isSecure {
                print("yay")
                self.sendResponse(result: "CONNECTION_SECURE" as AnyObject)
            } else {
                print("nah")
                self.sendResponse(result: FlutterError(code: "CONNECTION_NOT_SECURE", message: "Fingerprint doesn't match", details: nil))
            }
            
            return (.cancelAuthenticationChallenge, nil)
        }
    }
}
