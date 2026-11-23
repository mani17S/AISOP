"""The benchmark report printed a benign false-positive rate of 2 of 2 as "1.0%". The rate is a fraction; it must show as 100.0%."""

from app.modules.evaluation.report_generator import BenchmarkReportGenerator


def test_a_fraction_is_shown_as_a_percentage():
    fmt = BenchmarkReportGenerator._format_metric
    assert fmt(1.0, percentage=True) == "100.0%"
    assert fmt(0.5, percentage=True) == "50.0%"
    assert fmt(0.0, percentage=True) == "0.0%"


def test_an_unmeasured_value_is_not_shown_as_a_number():
    assert "N/A" in BenchmarkReportGenerator._format_metric(None, percentage=True)


def test_a_plain_metric_keeps_four_decimals():
    assert BenchmarkReportGenerator._format_metric(0.3148) == "0.3148"
