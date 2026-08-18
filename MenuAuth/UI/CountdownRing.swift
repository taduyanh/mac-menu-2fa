import SwiftUI

/// The depleting ring beside each code, matching the phone app's signal:
/// neutral most of the period, amber under ten seconds, red under five.
struct CountdownRing: View {
    let secondsRemaining: Int
    let period: Int

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return min(max(Double(secondsRemaining) / Double(period), 0), 1)
    }

    private var tint: Color {
        switch secondsRemaining {
        case ...5: .red
        case ...10: .orange
        default: .accentColor
        }
    }

    var body: some View {
        ZStack {
            Circle()
                .stroke(tint.opacity(0.18), lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(secondsRemaining)")
                .font(.system(size: 9, weight: .medium, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(tint)
        }
        // Deliberately not animated. A tweened ring would re-render every frame
        // for every visible row; stepping once per second costs nothing and is
        // just as readable, which is the trade this app is built around.
        .frame(width: 22, height: 22)
        .accessibilityLabel("\(secondsRemaining) seconds remaining")
    }
}
