import JarvisKit
import SwiftUI

/// Background tasks Jarvis works on.
struct TasksView: View {
    let model: AppModel

    var body: some View {
        NavigationStack {
            List(model.tasks, id: \.taskID) { task in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(task.goal).font(.headline).lineLimit(2)
                        Spacer()
                        StateBadge(state: task.state)
                    }
                    if !task.result.isEmpty {
                        Text(task.result).font(.subheadline).foregroundStyle(.secondary).lineLimit(4)
                    }
                    Text(task.updateTime.date, style: .relative).font(.caption).foregroundStyle(.tertiary)
                }
                .swipeActions {
                    if task.isActive {
                        Button("Cancel", role: .destructive) {
                            Task { await model.cancel(task) }
                        }
                    }
                }
            }
            .overlay {
                if model.tasks.isEmpty {
                    ContentUnavailableView(
                        "No tasks yet", systemImage: "checklist",
                        description: Text("Ask Jarvis to do something that takes a while."))
                }
            }
            .refreshable { await model.refresh() }
            .navigationTitle("Tasks")
        }
    }
}

extension JarvisTask {
    var isActive: Bool {
        [.queued, .running, .awaitingConfirmation, .awaitingApproval].contains(state)
    }
}

struct StateBadge: View {
    let state: TaskState

    var body: some View {
        Text(label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.18), in: .capsule)
            .foregroundStyle(color)
    }

    private var label: LocalizedStringKey {
        switch state {
        case .queued: "Queued"
        case .running: "Working"
        case .awaitingConfirmation: "Needs your OK"
        case .awaitingApproval: "Needs approval"
        case .succeeded: "Done"
        case .failed: "Failed"
        case .cancelled: "Cancelled"
        default: "Unknown"
        }
    }

    private var color: Color {
        switch state {
        case .succeeded: .green
        case .failed: .red
        case .cancelled: .gray
        case .awaitingApproval, .awaitingConfirmation: .orange
        default: .blue
        }
    }
}
