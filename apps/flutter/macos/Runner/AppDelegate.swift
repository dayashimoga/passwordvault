import Cocoa
import FlutterMacOS
import LocalAuthentication
import Security

@main
class AppDelegate: FlutterAppDelegate {
  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    guard let controller = mainFlutterWindow?.contentViewController as? FlutterViewController else {
      return
    }

    let biometricChannel = FlutterMethodChannel(
      name: "com.antigravity.pwdvault/biometrics",
      binaryMessenger: controller.engine.binaryMessenger
    )

    biometricChannel.setMethodCallHandler { (call, result) in
      switch call.method {
      case "isBiometricAvailable":
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        result(canEvaluate)

      case "getBiometricType":
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
          result("touchID")
        } else {
          result("none")
        }

      case "authenticate":
        guard let args = call.arguments as? [String: Any],
              let reason = args["reason"] as? String else {
          result(FlutterError(code: "INVALID_ARGS", message: "Missing reason", details: nil))
          return
        }

        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, authError in
          DispatchQueue.main.async {
            if success {
              result(true)
            } else {
              result(false)
            }
          }
        }

      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
