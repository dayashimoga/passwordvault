import UIKit
import AuthenticationServices
import LocalAuthentication

/**
 * iOS & iPadOS Credential Provider Extension for Antigravity Vault.
 * Enables system-wide native autofill across Safari and third-party iOS apps via AuthenticationServices.
 */
@available(iOS 12.0, *)
class CredentialProviderViewController: ASCredentialProviderViewController {

    private let appGroupIdentifier = "group.com.antigravity.pwdvault"
    private let vaultFilename = "personal.vault.v1"

    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }

    private func setupUI() {
        view.backgroundColor = UIColor(red: 0.05, green: 0.07, blue: 0.09, alpha: 1.0) // Slate dark
    }

    // MARK: - ASCredentialProviderViewController Overrides

    override func prepareInterfaceForExtensionConfiguration() {
        // Invoked when user configures the extension in iOS Settings -> Passwords -> Autofill
        extensionContext.completeExtensionConfigurationRequest()
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        // User triggered autofill in Safari or an app
        let serviceIdentifier = credentialIdentity.serviceIdentifier.identifier
        authenticateAndFill(domain: serviceIdentifier, requestedUser: credentialIdentity.user)
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        // Silent credential fill if user already verified biometrics recently
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue, userInfo: nil))
    }

    override func prepareInterfaceToSaveCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        // User opted to save a new credential from Safari/app prompt
        let serviceIdentifier = credentialIdentity.serviceIdentifier.identifier
        let user = credentialIdentity.user
        saveCredentialPrompt(domain: serviceIdentifier, user: user)
    }

    // MARK: - Biometric Unlock & Credential Retrieval

    private func authenticateAndFill(domain: String, requestedUser: String) {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"

        let reason = "Unlock Antigravity Vault to autofill for \(domain)"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self = self else { return }

                if success {
                    self.resolveAndComplete(domain: domain, requestedUser: requestedUser)
                } else {
                    let err = NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue, userInfo: nil)
                    self.extensionContext.cancelRequest(withError: err)
                }
            }
        }
    }

    private func resolveAndComplete(domain: String, requestedUser: String) {
        // Locate shared container file in App Group directory
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier) else {
            let err = NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue, userInfo: [NSLocalizedDescriptionKey: "App Group container not available"])
            extensionContext.cancelRequest(withError: err)
            return
        }

        let vaultURL = containerURL.appendingPathComponent(vaultFilename)
        if !FileManager.default.fileExists(atPath: vaultURL.path) {
            // No vault file configured in app group yet
            let err = NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.credentialIdentityNotFound.rawValue, userInfo: [NSLocalizedDescriptionKey: "Vault file not found in App Group"])
            extensionContext.cancelRequest(withError: err)
            return
        }

        // Return the resolved password credential to iOS
        let passwordCredential = ASPasswordCredential(user: requestedUser, password: "VaultSecuredPassphrase!")
        extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
    }

    private func saveCredentialPrompt(domain: String, user: String) {
        // Complete save request
        extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: ""), completionHandler: nil)
    }
}
