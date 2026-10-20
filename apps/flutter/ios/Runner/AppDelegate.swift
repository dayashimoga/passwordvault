import Flutter
import UIKit
import LocalAuthentication

@main
@objc class AppDelegate: FlutterAppDelegate {
  private var privacyShieldView: UIVisualEffectView?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)

    guard let controller = window?.rootViewController as? FlutterViewController else {
      return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    let biometricChannel = FlutterMethodChannel(
      name: "com.antigravity.pwdvault/biometrics",
      binaryMessenger: controller.binaryMessenger
    )

    biometricChannel.setMethodCallHandler { [weak self] (call, result) in
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
          if #available(iOS 11.0, *) {
            switch context.biometryType {
            case .faceID:
              result("faceID")
            case .touchID:
              result("touchID")
            default:
              result("none")
            }
          } else {
            result("touchID")
          }
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

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  // MARK: - Screen Privacy & Task Switcher Snapshot Protection
  override func applicationWillResignActive(_ application: UIApplication) {
    super.applicationWillResignActive(application)
    guard privacyShieldView == nil, let window = window else { return }

    let blurEffect = UIBlurEffect(style: .dark)
    let shield = UIVisualEffectView(effect: blurEffect)
    shield.frame = window.bounds
    shield.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    shield.tag = 9999

    window.addSubview(shield)
    privacyShieldView = shield
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    super.applicationDidBecomeActive(application)
    guard let shield = privacyShieldView else { return }

    UIView.animate(withDuration: 0.25, animations: {
      shield.alpha = 0
    }) { _ in
      shield.removeFromSuperview()
      self.privacyShieldView = nil
    }
  }
}
