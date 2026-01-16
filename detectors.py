import pandas as pd

def _to_dt(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "timestamp" not in df.columns:
        return pd.DataFrame(columns=list(df.columns) + ["timestamp"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.dropna(subset=["timestamp"])

def detect_alerts(df: pd.DataFrame, rules: list[dict]) -> pd.DataFrame:
    df = _to_dt(df)
    alerts = []

    if df.empty:
        return pd.DataFrame(columns=["timestamp", "severity", "rule", "source_ip", "details"])

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rtype = rule.get("type")
        sev = rule.get("severity", "LOW")
        name = rule.get("name", rule.get("id", "rule"))

        if rtype == "failed_login_threshold":
            thr = int(rule["params"]["threshold"])
            win = int(rule["params"]["window_seconds"])

            failed = df[(df.get("event_type") == "login") & (df.get("status") == "fail")].copy()
            if not failed.empty:
                failed = failed.sort_values("timestamp")
                for ip, g in failed.groupby("source_ip"):
                    times = g["timestamp"].tolist()
                    for t in times:
                        window_start = t - pd.Timedelta(seconds=win)
                        count = sum((tt >= window_start and tt <= t) for tt in times)
                        if count > thr:
                            alerts.append({
                                "timestamp": t,
                                "severity": sev,
                                "rule": name,
                                "source_ip": ip,
                                "details": f"Failed logins={count} within {win}s (thr={thr})",
                            })
                            break

        elif rtype == "port_scan_threshold":
            thr = int(rule["params"]["unique_ports_threshold"])
            win = int(rule["params"]["window_seconds"])

            scans = df[df["event_type"].isin(["port_scan", "network"])].copy() if "event_type" in df.columns else df.copy()
            if "dst_port" not in scans.columns:
                continue

            scans = scans.dropna(subset=["dst_port"])
            if not scans.empty:
                scans["dst_port"] = pd.to_numeric(scans["dst_port"], errors="coerce")
                scans = scans.dropna(subset=["dst_port"]).sort_values("timestamp")

                for ip, g in scans.groupby("source_ip"):
                    g = g.sort_values("timestamp")
                    for _, row in g.iterrows():
                        t = row["timestamp"]
                        window_start = t - pd.Timedelta(seconds=win)
                        w = g[(g["timestamp"] >= window_start) & (g["timestamp"] <= t)]
                        unique_ports = w["dst_port"].nunique()
                        if unique_ports >= thr:
                            alerts.append({
                                "timestamp": t,
                                "severity": sev,
                                "rule": name,
                                "source_ip": ip,
                                "details": f"Unique ports={unique_ports} within {win}s (thr={thr})",
                            })
                            break

        elif rtype == "cpu_spike":
            cpu_thr = float(rule["params"]["cpu_threshold"])
            if "cpu_percent" not in df.columns:
                continue
            cpu = pd.to_numeric(df["cpu_percent"], errors="coerce")
            spikes = df[cpu >= cpu_thr]
            for _, r in spikes.iterrows():
                alerts.append({
                    "timestamp": r["timestamp"],
                    "severity": sev,
                    "rule": name,
                    "source_ip": r.get("source_ip", "N/A"),
                    "details": f"CPU={r.get('cpu_percent')}% >= {cpu_thr}%",
                })

        elif rtype == "bytes_in_spike":
            bthr = float(rule["params"]["bytes_in_threshold"])
            if "bytes_in" not in df.columns:
                continue
            b = pd.to_numeric(df["bytes_in"], errors="coerce")
            spikes = df[b >= bthr]
            for _, r in spikes.iterrows():
                alerts.append({
                    "timestamp": r["timestamp"],
                    "severity": sev,
                    "rule": name,
                    "source_ip": r.get("source_ip", "N/A"),
                    "details": f"bytes_in={r.get('bytes_in')} >= {bthr}",
                })

    if not alerts:
        return pd.DataFrame(columns=["timestamp", "severity", "rule", "source_ip", "details"])

    out = pd.DataFrame(alerts).drop_duplicates()
    out = out.sort_values("timestamp", ascending=False).reset_index(drop=True)
    return out
