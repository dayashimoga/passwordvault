import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    // Hardware Screen Protection: Prevent screenshots, screen recording, and remote capture
    self.sharingType = .none
    self.minSize = NSSize(width: 800, height: 600)
    self.title = "Antigravity Vault"

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}
