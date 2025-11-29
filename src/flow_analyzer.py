from nfstream import NFStreamer
import pandas as pd
from collections import defaultdict

class FlowAnalyzer:

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def load_flows(self):
        streamer = NFStreamer(
            source=self.pcap_path,
            statistical_analysis=True
        )
        df = streamer.to_pandas()
        return df

    def summarize_traffic(self, df):
        summary = defaultdict(lambda: {
            "flows": 0,
            "bytes": 0,
            "packets": 0
        })

        for _, row in df.iterrows():
            key = (row["src_ip"], row["dst_ip"])

            summary[key]["flows"] += 1

            summary[key]["bytes"] += row.get("bidirectional_bytes", 0)
            summary[key]["packets"] += row.get("bidirectional_packets", 0)

        return summary

    def top_statistics(self, summary, top_n=10):
        rows = []
        for (src, dst), stats in summary.items():
            rows.append({
                "src": src,
                "dst": dst,
                "flows": stats["flows"],
                "packets": stats["packets"],
                "bytes": stats["bytes"]
            })

        df = pd.DataFrame(rows)

        results = {}
        results["top_flows"] = df.sort_values(by="flows", ascending=False).head(top_n)
        results["top_bytes"] = df.sort_values(by="bytes", ascending=False).head(top_n)
        results["top_packets"] = df.sort_values(by="packets", ascending=False).head(top_n)

        results["unique_hosts_src"] = df["src"].nunique()
        results["unique_hosts_dst"] = df["dst"].nunique()


        results["most_active_src"] = (
            df.groupby("src")["flows"].sum().sort_values(ascending=False).head(5).reset_index()
        )
        results["most_active_dst"] = (
            df.groupby("dst")["flows"].sum().sort_values(ascending=False).head(5).reset_index()
        )

        results["total_flows"] = df["flows"].sum()

        return results
