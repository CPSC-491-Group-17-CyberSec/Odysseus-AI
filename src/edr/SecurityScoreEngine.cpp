// ============================================================================
// SecurityScoreEngine.cpp
// ============================================================================

#include "edr/SecurityScoreEngine.h"

#include <algorithm>

namespace EDR {

QString scoreLabelToText(ScoreLabel l)
{
    switch (l) {
        case ScoreLabel::Secure:   return "Secure";
        case ScoreLabel::Moderate: return "Moderate";
        case ScoreLabel::HighRisk: return "High Risk";
    }
    return "Unknown";
}

const char* scoreLabelHex(ScoreLabel l)
{
    // Strict palette: green / amber / red.
    switch (l) {
        case ScoreLabel::Secure:   return "#10B981";
        case ScoreLabel::Moderate: return "#F59E0B";
        case ScoreLabel::HighRisk: return "#EF4444";
    }
    return "#9CA3AF";
}

namespace {

ScoreLabel labelFor(int score)
{
    if (score >= 80) return ScoreLabel::Secure;
    if (score >= 50) return ScoreLabel::Moderate;
    return ScoreLabel::HighRisk;
}

bool isCrossView(const Alert& a)
{
    return a.category == EDR::Category::CrossView;
}

}  // anonymous

ScoreReport scoreActiveAlerts(const QHash<QString, Alert>& activeAlerts)
{
    using namespace ScoreConstants;

    ScoreReport r;
    r.activeAlerts = activeAlerts.size();

    int critN = 0, highN = 0, medN = 0, lowN = 0;
    int persistentN = 0;

    int crossViewIgnored = 0;

    for (auto it = activeAlerts.constBegin();
              it != activeAlerts.constEnd(); ++it) {
        const Alert& a = it.value();

        // Cross-view: only count if it's persisted across multiple ticks.
        // First-tick cross-view is almost always a ProcessEnumerator race.
        if (isCrossView(a) && a.ticksSeen < kCrossViewMinTicks) {
            ++crossViewIgnored;
            continue;
        }

        // Cross-view always weighted Low regardless of underlying severity
        // (the spec — these are "soft" findings).
        const Severity effective = isCrossView(a)
                                       ? Severity::Low
                                       : a.severity;

        switch (effective) {
            case Severity::Critical: ++critN;  break;
            case Severity::High:     ++highN;  break;
            case Severity::Medium:   ++medN;   break;
            case Severity::Low:      ++lowN;   break;
            case Severity::Info:     ++lowN;   break;   // bucket Info as Low
        }

        if (a.ticksSeen >= kPersistenceMinTicks) ++persistentN;
    }

    r.criticalCount   = critN;
    r.highCount       = highN;
    r.mediumCount     = medN;
    r.lowCount        = lowN;
    r.persistentCount = persistentN;

    // Compute deductions per severity bucket
    const int dCrit = critN * kCriticalPenalty;
    const int dHigh = highN * kHighPenalty;
    const int dMed  = std::min(medN * kMediumPenalty, kMediumCap);
    const int dLow  = std::min(lowN * kLowPenalty,    kLowCap);
    const int dPersist = persistentN * kPersistencePenalty;

    int score = 100 - dCrit - dHigh - dMed - dLow - dPersist;
    if (score < 0)   score = 0;
    if (score > 100) score = 100;
    r.score = score;
    r.label = labelFor(score);

    // Build the breakdown. Skip zero-impact lines so the UI stays clean.
    auto push = [&](int delta, const QString& reason) {
        if (delta == 0) return;
        r.breakdown.append({-delta, reason});   // delta is negative
    };

    push(dCrit,
         critN == 1
             ? QStringLiteral("1 critical alert")
             : QString("%1 critical alerts").arg(critN));
    push(dHigh,
         highN == 1
             ? QStringLiteral("1 high-severity alert")
             : QString("%1 high-severity alerts").arg(highN));
    if (dMed > 0) {
        QString s = (medN == 1
                        ? QStringLiteral("1 medium-severity alert")
                        : QString("%1 medium-severity alerts").arg(medN));
        if (medN * kMediumPenalty > kMediumCap)
            s += QString(" (capped at -%1)").arg(kMediumCap);
        push(dMed, s);
    }
    if (dLow > 0) {
        QString s = (lowN == 1
                        ? QStringLiteral("1 low / info alert")
                        : QString("%1 low / info alerts").arg(lowN));
        if (lowN * kLowPenalty > kLowCap)
            s += QString(" (capped at -%1)").arg(kLowCap);
        push(dLow, s);
    }
    push(dPersist,
         persistentN == 1
             ? QString("1 alert persisting across %1+ ticks")
                   .arg(kPersistenceMinTicks)
             : QString("%1 alerts persisting across %2+ ticks")
                   .arg(persistentN).arg(kPersistenceMinTicks));

    if (r.breakdown.isEmpty() && crossViewIgnored == 0) {
        r.breakdown.append({0, QStringLiteral("No active findings.")});
    } else if (crossViewIgnored > 0 && r.breakdown.isEmpty()) {
        r.breakdown.append({0,
            QString("Ignored %1 first-tick cross-view finding%2 "
                    "(needs persistence to count).")
                .arg(crossViewIgnored)
                .arg(crossViewIgnored == 1 ? "" : "s")});
    }

    return r;
}

}  // namespace EDR
