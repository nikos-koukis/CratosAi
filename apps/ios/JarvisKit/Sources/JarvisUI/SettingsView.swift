import JarvisKit
import SwiftUI

/// Account, voice provider, and this phone's approver key.
struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var entry: String?
    @State private var keyProblem: String?
    @State private var confirmReplace = false

    var body: some View {
        NavigationStack {
            Form {
                if let account = model.account {
                    Section("Account") {
                        LabeledContent("User", value: account.userID)
                        LabeledContent("Server", value: account.serverURL.host() ?? account.serverURL.absoluteString)
                    }
                }
                Section("Voice") {
                    Picker("Provider", selection: $model.provider) {
                        Text("Default").tag(Jarvis_Common_V1_Provider.unspecified)
                        Text("OpenAI").tag(Jarvis_Common_V1_Provider.openai)
                        Text("xAI").tag(Jarvis_Common_V1_Provider.xai)
                    }
                }
                Section {
                    LabeledContent("Approver id", value: model.approverID)
                    if let entry {
                        Text(entry).font(.caption.monospaced()).textSelection(.enabled)
                        ShareLink(item: entry) {
                            Label("Share the daemon.toml entry", systemImage: "square.and.arrow.up")
                        }
                    }
                    if let keyProblem {
                        Label(keyProblem, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    }
                    Button("Create a new approver key", role: .destructive) { confirmReplace = true }
                } header: {
                    Text("Approving commands")
                } footer: {
                    Text(
                        "To let this phone approve commands on a computer, add this entry to the computer's daemon.toml. The key stays in this phone's Secure Enclave and signs only with Face ID."
                    )
                }
                Section {
                    Button("Sign out", role: .destructive) {
                        Task { await model.signOut() }
                    }
                }
            }
            .navigationTitle("Settings")
            .task { loadEntry() }
            .confirmationDialog("Replace the approver key?", isPresented: $confirmReplace) {
                Button("Replace", role: .destructive) {
                    do {
                        entry = try model.replaceApproverKey()
                        keyProblem = String(localized: "Update the entry in every computer's daemon.toml.")
                    } catch {
                        keyProblem = String(describing: error)
                    }
                }
            } message: {
                Text("Computers will stop accepting this phone's approvals until you update their daemon.toml.")
            }
        }
    }

    private func loadEntry() {
        do {
            let key = try model.approverKey()
            if key.isInvalidated {
                keyProblem = ApproverKeyError.keyInvalidated.description
            }
            entry = try model.approverEntry()
        } catch {
            keyProblem = String(describing: error)
        }
    }
}
