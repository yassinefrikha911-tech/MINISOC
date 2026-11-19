# Dashboard mockup (v1)

## Main page
```
+--------------------------------------------------------------+
| MiniSOC (lab use only)                    Timezone: UTC      |
+--------------------------------------------------------------+
| IMPORT                                                       |
| [Choose SSH file] [Choose HTTP file] [Import]                |
| Last import: 120 accepted, 3 rejected (see errors)           |
+--------------------------------------------------------------+
| FILTERS                                                      |
| From [date] To [date]  IP [____]  Source [all/ssh/http]      |
| Priority [all/low/medium/high]   [Apply]  [Export CSV]       |
| Results: 42                                                  |
+--------------------------------------------------------------+
| ALERTS                                                       |
| Rule | Priority | First seen | Last seen | IP | Count | Evidence|
| R1   | medium   | 10:15:32   | 10:15:38  | .5 | 3/3   | [view]  |
+--------------------------------------------------------------+
| EVENTS                                                       |
| Time | Source | IP | Type | Severity | Summary                |
+--------------------------------------------------------------+
```

## Evidence page (after clicking [view])
```
Rule: R1 repeated SSH failures
Threshold: 3 failures in 5 minutes
Window: 10:15:32 to 10:15:38 UTC
Count: 3
Events: (list of the events that triggered it)
```