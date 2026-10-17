/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Tiny in-memory hand-off between screens and the monitor service.
 */
package com.ps01.riskauditor;

import java.util.ArrayList;
import java.util.List;

final class ScanState {
    /** Results of the most recent full scan (used by the PDF export). */
    static volatile List<AppReport> last = new ArrayList<>();
    /** Flagged files from the most recent file scan (used by the PDF export). */
    static volatile List<FileAnalyzer.Result> lastFiles = new ArrayList<>();
    /** Set when something changed (install, uninstall, settings change) so the list rescans on resume. */
    static volatile boolean dirty = false;

    private ScanState() {
    }
}
