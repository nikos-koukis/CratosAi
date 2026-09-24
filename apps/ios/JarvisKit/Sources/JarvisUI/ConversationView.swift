import JarvisKit
import SwiftUI

/// Talking to Jarvis: the live transcript and one big button.
struct ConversationView: View {
    let model: AppModel
    private var voice: VoiceController { model.voice }

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                ScrollViewReader { proxy in
                    List(voice.transcript.lines) { line in
                        TranscriptRow(line: line).id(line.id)
                    }
                    .listStyle(.plain)
                    .onChange(of: voice.transcript.lines.last) {
                        if let last = voice.transcript.lines.last {
                            withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                        }
                    }
                    .overlay {
                        if voice.transcript.lines.isEmpty {
                            ContentUnavailableView(
                                "Talk to Jarvis", systemImage: "waveform",
                                description: Text("Ask anything, or ask Jarvis to do something for you."))
                        }
                    }
                }
                if let problem = voice.problem {
                    Label(problem, systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .padding(.horizontal)
                }
                StatusOrb(phase: voice.phase)
                    .frame(height: 24)
                HStack(spacing: 24) {
                    if voice.phase == .assistantSpeaking {
                        Button {
                            Task { await voice.interrupt() }
                        } label: {
                            Label("Stop answer", systemImage: "hand.raised.fill")
                        }
                        .buttonStyle(.bordered)
                    }
                    Button {
                        Task {
                            if voice.isActive {
                                await voice.stop()
                            } else {
                                await voice.start(provider: model.provider, locale: Locale.current.identifier(.bcp47))
                            }
                        }
                    } label: {
                        Label(voice.isActive ? "End" : "Talk", systemImage: voice.isActive ? "stop.fill" : "mic.fill")
                            .frame(minWidth: 120)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(voice.isActive ? .red : .accentColor)
                    .disabled(voice.phase == .connecting)
                }
                .controlSize(.large)
                .padding(.bottom)
            }
            .navigationTitle("Jarvis")
        }
    }
}

struct TranscriptRow: View {
    let line: TranscriptLine

    var body: some View {
        HStack {
            if line.speaker == .user { Spacer(minLength: 40) }
            Text(line.text)
                .padding(10)
                .background(
                    line.speaker == .user ? Color.accentColor.opacity(0.15) : Color.secondary.opacity(0.12),
                    in: .rect(cornerRadius: 14)
                )
                .opacity(line.final ? 1 : 0.7)
            if line.speaker == .assistant { Spacer(minLength: 40) }
        }
        .listRowSeparator(.hidden)
    }
}

/// Who is talking, at a glance.
struct StatusOrb: View {
    let phase: VoiceController.Phase

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(color)
                .frame(width: 12, height: 12)
                .scaleEffect(phase == .userSpeaking || phase == .assistantSpeaking ? 1.4 : 1)
                .animation(
                    .easeInOut(duration: 0.4).repeatForever(autoreverses: true),
                    value: phase == .userSpeaking || phase == .assistantSpeaking)
            Text(label).font(.footnote).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var color: Color {
        switch phase {
        case .idle: .gray
        case .connecting: .yellow
        case .listening: .green
        case .userSpeaking: .blue
        case .assistantSpeaking: .purple
        }
    }

    private var label: LocalizedStringKey {
        switch phase {
        case .idle: "Not listening"
        case .connecting: "Connecting…"
        case .listening: "Listening"
        case .userSpeaking: "You are speaking"
        case .assistantSpeaking: "Jarvis is speaking"
        }
    }
}
