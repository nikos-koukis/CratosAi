import JarvisKit
import SwiftUI

/// The app: pairing until paired, then the tabs.
public struct RootView: View {
    @Bindable private var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    public var body: some View {
        Group {
            if model.account == nil {
                PairingView(model: model)
            } else {
                TabView(selection: $model.screen) {
                    Tab("Talk", systemImage: "waveform", value: AppModel.Screen.talk) {
                        ConversationView(model: model)
                    }
                    Tab("Tasks", systemImage: "checklist", value: AppModel.Screen.tasks) { TasksView(model: model) }
                    Tab("Approvals", systemImage: "checkmark.shield", value: AppModel.Screen.approvals) {
                        ApprovalsView(model: model)
                    }
                    .badge(model.approvals.count)
                    Tab("Settings", systemImage: "gearshape", value: AppModel.Screen.settings) {
                        SettingsView(model: model)
                    }
                }
                .task { await model.refresh() }
            }
        }
        .onOpenURL { url in
            Task { await model.open(url) }
        }
    }
}

/// Pairs the app with a code from the dashboard.
struct PairingView: View {
    let model: AppModel
    @State private var server = ""
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(
                        "Scan the pairing QR code from the Jarvis dashboard with the Camera app, or type the code here."
                    )
                    .foregroundStyle(.secondary)
                }
                Section("Server") {
                    TextField("https://api.example.com", text: $server)
                        .autocorrectionDisabled()
                        .textContentType(.URL)
                        #if os(iOS)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                        #endif
                }
                Section("Pairing code") {
                    TextField("XXXX-XXXX-XXXX", text: $code)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                        #if os(iOS)
                            .textInputAutocapitalization(.characters)
                        #endif
                }
                if let problem = model.problem {
                    Section { Label(problem, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
                }
                Section {
                    Button {
                        guard let url = URL(string: server.trimmingCharacters(in: .whitespaces)) else { return }
                        Task { await model.pair(server: url, code: code) }
                    } label: {
                        if model.busy { ProgressView() } else { Text("Pair") }
                    }
                    .disabled(model.busy || server.isEmpty || code.count < 12)
                }
            }
            .navigationTitle("Jarvis")
        }
    }
}
