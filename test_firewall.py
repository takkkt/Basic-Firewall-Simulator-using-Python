from pathlib import Path

from firewall_simulator import check_packet, make_packet, make_rule


test_log = Path(__file__).parent / "test.log"

if test_log.exists():
    test_log.unlink()

rules = []
rules.append(make_rule("BLOCK", "192.168.1.50", "ANY", "ANY", "ANY", "Bad IP"))
rules.append(make_rule("ALLOW", "ANY", 80, "TCP", "WEB", "Allow web"))
rules.append(make_rule("BLOCK", "ANY", 23, "TCP", "ANY", "Block Telnet"))
rules.append(make_rule("BLOCK", "ANY", "ANY", "ICMP", "ANY", "Block ping"))
rules.append(make_rule("BLOCK", "ANY", "ANY", "ANY", "FILE_TRANSFER", "Block files"))


def run_test(name, packet, expected):
    result = check_packet(rules, packet, test_log)
    actual = result[0]

    if actual == expected:
        print("PASS -", name)
    else:
        print("FAIL -", name, "expected", expected, "but got", actual)


packet1 = make_packet("192.168.1.50", 80, "TCP", "WEB")
run_test("block an IP", packet1, "BLOCK")

packet2 = make_packet("10.0.0.5", 80, "TCP", "WEB")
run_test("allow port 80", packet2, "ALLOW")

packet3 = make_packet("10.0.0.5", 23, "TCP", "OTHER")
run_test("block port 23", packet3, "BLOCK")

packet4 = make_packet("10.0.0.5", 8, "ICMP", "PING")
run_test("block ICMP", packet4, "BLOCK")

packet5 = make_packet("10.0.0.5", 21, "TCP", "FILE_TRANSFER")
run_test("block file transfer", packet5, "BLOCK")

packet6 = make_packet("10.0.0.5", 53, "UDP", "OTHER")
run_test("default allow", packet6, "ALLOW")

file = open(test_log, "r")
log_text = file.read()
file.close()

if "ALLOW" in log_text and "BLOCK" in log_text:
    print("PASS - logging")
else:
    print("FAIL - logging")

test_log.unlink()
