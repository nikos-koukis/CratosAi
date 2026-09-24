import JarvisKit
import SwiftUI

/// Commands on the user's computers that wait for this phone's approval.
struct ApprovalsView: View {
    let model: AppModel

    var body: some View {
        NavigationStack {
            List {
                ForEach(model.approvals) { request in
                    NavigationLink {
                        ApprovalDetailView(model: model, request: request)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(request.commandLine).font(.body.monospaced()).lineLimit(2)
                            Text("on \(request.deviceName)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if model.malformedApprovals > 0 {
                    Label(
                        "\(model.malformedApprovals) request(s) could not be read and cannot be approved.",
                        systemImage: "exclamationmark.octagon"
                    )
                    .foregroundStyle(.red)
                }
            }
            .overlay {
                if model.approvals.isEmpty && model.malformedApprovals == 0 {
                    ContentUnavailableView(
                        "Nothing to approve", systemImage: "checkmark.shield",
                        description: Text("Commands on your computers that need your approval appear here."))
                }
            }
            .refreshable { await model.refresh() }
            .navigationTitle("Approvals")
        }
    }
}

/// Everything the command will do, straight from what the computer sent, and
/// the approve button (Face ID).
struct ApprovalDetailView: View {
    let model: AppModel
    let request: ApprovalRequest
    @State private var result: String?
    @State private var problem: String?
    @State private var signing = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Command") {
                Text(request.commandLine).font(.body.monospaced()).textSelection(.enabled)
            }
            Section("Where") {
                LabeledContent("Computer", value: request.deviceName)
                LabeledContent("Folder") { Text(request.workingDirectory).font(.footnote.monospaced()) }
                LabeledContent(
                    "Time limit",
                    value: Duration.seconds(request.timeout).formatted(.units(allowed: [.minutes, .seconds])))
            }
            Section("Permissions") {
                if request.grants.isEmpty {
                    Label("Read-only, no network", systemImage: "lock")
                } else {
                    ForEach(request.grants, id: \.self) { grant in
                        Label(grant, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    }
                }
            }
            Section("Asked for") {
                Text(request.taskGoal).foregroundStyle(.secondary)
            }
            Section {
                Text("Expires \(request.expires, style: .relative)").foregroundStyle(.secondary)
            }
            if let result {
                Section("Result") { Text(result).font(.footnote.monospaced()) }
            }
            if let problem {
                Section { Label(problem, systemImage: "xmark.octagon").foregroundStyle(.red) }
            }
            if result == nil {
                Section {
                    Button {
                        Task { await approve() }
                    } label: {
                        if signing { ProgressView() } else { Label("Approve with Face ID", systemImage: "faceid") }
                    }
                    .disabled(signing)
                }
            }
        }
        .navigationTitle("Approve command")
    }

    private func approve() async {
        signing = true
        defer { signing = false }
        do {
            result = try await model.approve(request)
            problem = nil
        } catch ApproverKeyError.cancelled {
            // The user closed Face ID: nothing happened.
        } catch let error as ConnectError where error.appReason == .approvalRejected {
            problem = String(
                localized:
                    "The computer does not accept this phone's approvals. Add the entry from Settings to its daemon.toml."
            )
        } catch {
            problem = VoiceController.explain(error)
        }
    }
}
