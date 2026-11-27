import ipaddress
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from minisoc.alerts import detect_and_save, get_evidence
from minisoc.db import connect, init_db
from minisoc.importer import import_file
from minisoc.queries import (ALERT_COLUMNS, ALERT_HEADERS, EVENT_COLUMNS, EVENT_HEADERS,
                             event_date_range, filter_alerts, filter_events, to_csv, totals)

st.set_page_config(page_title="MiniSOC", layout="wide")
init_db()


def import_upload(uploaded, source, year):
    """Save an uploaded file in a temporary folder under its own name, then import it."""
    name = Path(uploaded.name).name
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / name
        path.write_bytes(uploaded.getvalue())
        return import_file(path, source, year=year)


def table(rows, columns, names):
    """Rows (dictionaries) to a display table. Empty values show as a dash."""
    df = pd.DataFrame(rows)[columns]
    if "status_code" in df.columns:
        df["status_code"] = df["status_code"].apply(
            lambda v: "-" if pd.isna(v) else str(int(v)))
    df = df.fillna("-")
    df.columns = names
    return df


st.title("MiniSOC")
st.caption("Lab use only: synthetic data, no automatic response. An alert is a lead "
           "to investigate, not proof of an attack. All times are UTC.")

if "detect" in st.session_state:
    r = st.session_state.pop("detect")
    st.info(f"Rules run on {r['events']} events: {r['found']} alert(s) found, "
            f"{r['new']} new, {r['unchanged']} unchanged, {r['upgraded']} upgraded.")

con = connect()
total = totals(con)
dmin, dmax = event_date_range(con)

# ---------- Filters (sidebar)
st.sidebar.header("Filters")
period = st.sidebar.date_input("Period (UTC)", value=(dmin, dmax))
if not isinstance(period, (tuple, list)) or len(period) != 2:
    st.sidebar.info("Pick an end date to complete the period.")
    st.stop()
start, end = period
if end < start:
    st.sidebar.error("The end date is before the start date.")
    st.stop()

ip_text = st.sidebar.text_input("IP address (exact match)", placeholder="203.0.113.50").strip()
ip = None
if ip_text:
    try:
        ip = str(ipaddress.ip_address(ip_text))
    except ValueError:
        st.sidebar.error("This is not a valid IP address.")
        st.stop()

sources = st.sidebar.multiselect("Source", ["ssh", "http"], default=["ssh", "http"])
priorities = st.sidebar.multiselect("Alert priority", ["low", "medium", "high"],
                                    default=["low", "medium", "high"])
st.sidebar.caption("The filters apply to the tables, the counts and the CSV exports. "
                   "Priority applies to alerts. An IP filter hides R3 alerts, "
                   "which have no IP.")

events = filter_events(con, start, end, ip, sources)
alerts = filter_alerts(con, start, end, ip, sources, priorities)
n_ssh = sum(1 for e in events if e["source"] == "ssh")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events shown", len(events))
c2.metric("SSH events", n_ssh)
c3.metric("HTTP events", len(events) - n_ssh)
c4.metric("Alerts shown", len(alerts))
st.caption(f"Period: {start} to {end} (UTC). In the database: "
           f"{total['events']} events and {total['alerts']} alerts.")

tab_alerts, tab_events, tab_import = st.tabs(["Alerts", "Events", "Import"])

# ---------- Alerts
with tab_alerts:
    st.subheader(f"{len(alerts)} alert(s)")
    if st.button("Run the rules now"):
        st.session_state["detect"] = detect_and_save()
        st.rerun()

    if alerts:
        st.dataframe(table(
            alerts,
            ["id", "rule", "priority", "title", "ip", "source", "event_count",
             "threshold", "window_minutes", "first_seen", "last_seen"],
            ["ID", "Rule", "Priority", "Title", "IP", "Source", "Count", "Threshold",
             "Window (min)", "First seen (UTC)", "Last seen (UTC)"]), hide_index=True)
        st.download_button(
            "Download these alerts (CSV)",
            data=to_csv(alerts, ALERT_COLUMNS, ALERT_HEADERS).encode("utf-8-sig"),
            file_name=f"minisoc_alerts_{start}_{end}.csv", mime="text/csv")

        st.markdown("#### Evidence")
        labels = {a["id"]: f"{a['id']} - {a['rule']} - {a['ip'] or 'all IPs'} - {a['priority']}"
                  for a in alerts}
        chosen = st.selectbox("Open an alert", list(labels), format_func=labels.get)
        a = next(x for x in alerts if x["id"] == chosen)
        st.write(a["details"])
        st.caption(f"Rule {a['rule']}, threshold {a['threshold']}, window "
                   f"{a['window_minutes']} min, {a['event_count']} events, observed "
                   f"{a['first_seen']} to {a['last_seen']} (UTC).")
        st.dataframe(table(
            get_evidence(con, chosen),
            ["timestamp", "source", "ip", "status_code", "summary", "raw"],
            ["Time (UTC)", "Source", "IP", "Status", "Summary", "Raw line"]), hide_index=True)
    else:
        st.info("No alert matches the filters.")

    with st.expander("How the priority is decided"):
        st.write("medium: the threshold of a rule is reached. high: the count is at least "
                 "twice the threshold, or the same IP triggers two different rules. "
                 "Thresholds and windows are pedagogical values (see docs/rules.md).")

# ---------- Events
with tab_events:
    st.subheader(f"{len(events)} event(s), SSH and HTTP together")
    if events:
        st.dataframe(table(
            events, EVENT_COLUMNS,
            ["Time (UTC)", "Source", "IP", "Type", "Severity", "Status", "Summary"]),
            hide_index=True)
        st.download_button(
            "Download these events (CSV)",
            data=to_csv(events, EVENT_COLUMNS, EVENT_HEADERS).encode("utf-8-sig"),
            file_name=f"minisoc_events_{start}_{end}.csv", mime="text/csv")
        st.caption("The export uses the same period and filters as the table.")
    else:
        st.info("No event matches the filters. Use the Import tab to add logs.")

# ---------- Import
with tab_import:
    st.subheader("Import log files")
    st.caption("SSH lines have no year. Give it, or leave 0 and it is guessed. "
               "The year used is saved with the import.")
    year_in = st.number_input("Year of the SSH log (0 = guess it)",
                              min_value=0, max_value=2100, value=0, step=1)
    ssh_file = st.file_uploader("SSH log", type=["log", "txt"], key="ssh_up")
    http_file = st.file_uploader("HTTP log", type=["log", "txt"], key="http_up")
    run_after = st.checkbox("Run the rules after importing", value=True)

    if st.button("Import", type="primary"):
        if ssh_file is None and http_file is None:
            st.warning("Choose at least one file.")
        else:
            year = int(year_in) or None
            reports = []
            for uploaded, source in ((ssh_file, "ssh"), (http_file, "http")):
                if uploaded is not None:
                    try:
                        reports.append(import_upload(uploaded, source, year))
                    except (ValueError, OSError) as error:
                        reports.append({"file": uploaded.name, "source": source,
                                        "status": "error", "accepted": 0, "rejected": 0,
                                        "errors": [], "message": str(error)})
            st.session_state["reports"] = reports
            if run_after:
                st.session_state["detect"] = detect_and_save()
            st.rerun()

    for rep in st.session_state.get("reports", []):
        name = f"{rep['file']} ({rep['source']})"
        if rep["status"] == "duplicate":
            st.warning(f"{name}: identical file already imported "
                       f"(import #{rep['duplicate_of']}). Nothing was changed.")
        elif rep["status"] == "ok":
            st.success(f"{name}: {rep['accepted']} lines accepted, none rejected.")
        elif rep["status"] == "partial":
            st.warning(f"{name}: {rep['accepted']} accepted, {rep['rejected']} rejected.")
        elif rep["status"] == "failed":
            st.error(f"{name}: no line could be imported ({rep['rejected']} rejected).")
        else:
            st.error(f"{name}: {rep.get('message', 'import error')}")
        if rep.get("errors"):
            st.dataframe(pd.DataFrame(rep["errors"],
                                      columns=["Line", "Reason", "Start of the line"]),
                         hide_index=True)

con.close()