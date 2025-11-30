from src.flow_analyzer import FlowAnalyzer
from src.report_generator import ReportGenerator


if __name__ == "__main__":
    analyzer = FlowAnalyzer("data/2015-09-08_mixed.pcap")

    # Wczytywanie flow z pliku pcap
    flows = analyzer.load_flows()

    print("\nWyświetlanie pierwszych flow:")
    print(flows.iloc[:, :25].head())

    print("\nInformacje o danych flow:")
    print(flows.info())

    # Podsumowanie ruchu
    summary = analyzer.summarize_traffic(flows)

    # Generowanie statystyk
    stats = analyzer.top_statistics(summary, top_n=10)

    print("\nNajwięcej flow między parami hostów:")
    print(stats["top_flows"].reset_index(drop=True).to_string(index=False))

    print("\nNajwiększy transfer bajtów:")
    print(stats["top_bytes"].reset_index(drop=True).to_string(index=False))

    print("\nNajwięcej pakietów:")
    print(stats["top_packets"].reset_index(drop=True).to_string(index=False))

    print("\nNajbardziej aktywne hosty źródłowe:")
    print(stats["most_active_src"].to_string(index=False))

    print("\nNajbardziej aktywne hosty docelowe:")
    print(stats["most_active_dst"].to_string(index=False))

    print("\nLiczba unikalnych hostów źródłowych:")
    print(stats["unique_hosts_src"])

    print("\nLiczba unikalnych hostów docelowych:")
    print(stats["unique_hosts_dst"])

    print("\nŁączna liczba flow:")
    print(stats["total_flows"])

    # Generowanie raportu PDF
    pcap_name = analyzer.pcap_path.split("/")[-1]

    report = ReportGenerator("report/flow_report.pdf")
    pdf_path = report.generate_pdf(
        stats,
        pcap_name
    )

    print(f"\nRaport PDF został zapisany jako: {pdf_path}")

