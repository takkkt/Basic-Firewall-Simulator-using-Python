import ipaddress
import json
from datetime import datetime
from pathlib import Path


rules = []
folder = Path(__file__).parent
rules_file = folder / "rules.json"
log_file = folder / "firewall.log"


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def make_rule(action, source_ip, port, protocol, traffic_type, description):
    rule = {
        "action": action.upper(),
        "source_ip": source_ip,
        "port": port,
        "protocol": protocol.upper(),
        "traffic_type": traffic_type.upper(),
        "description": description
    }
    return rule


def make_packet(source_ip, port, protocol, traffic_type):
    packet = {
        "source_ip": source_ip,
        "port": port,
        "protocol": protocol.upper(),
        "traffic_type": traffic_type.upper()
    }
    return packet


def rule_matches(rule, packet):
    if rule["source_ip"] != "ANY":
        if rule["source_ip"] != packet["source_ip"]:
            return False

    if rule["port"] != "ANY":
        if rule["port"] != packet["port"]:
            return False

    if rule["protocol"] != "ANY":
        if rule["protocol"] != packet["protocol"]:
            return False

    if rule["traffic_type"] != "ANY":
        if rule["traffic_type"] != packet["traffic_type"]:
            return False

    return True


def write_log(packet, action, reason, filename):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = time
    line = line + " | " + action
    line = line + " | IP: " + packet["source_ip"]
    line = line + " | Port: " + str(packet["port"])
    line = line + " | Protocol: " + packet["protocol"]
    line = line + " | Type: " + packet["traffic_type"]
    line = line + " | " + reason + "\n"

    file = open(filename, "a")
    file.write(line)
    file.close()


def check_packet(current_rules, packet, filename):
    rule_number = 1

    for rule in current_rules:
        if rule_matches(rule, packet):
            action = rule["action"]
            description = rule["description"]

            if description == "":
                description = "No description"

            reason = "Matched rule " + str(rule_number) + ": " + description
            write_log(packet, action, reason, filename)
            return action, reason

        rule_number = rule_number + 1

    action = "ALLOW"
    reason = "No rule matched, so the default action was used"
    write_log(packet, action, reason, filename)
    return action, reason


def save_rules():
    file = open(rules_file, "w")
    json.dump(rules, file, indent=4)
    file.close()


def load_rules():
    if rules_file.exists():
        try:
            file = open(rules_file, "r")
            saved_rules = json.load(file)
            file.close()

            for rule in saved_rules:
                rules.append(rule)

            print("Loaded", len(rules), "saved rules")
        except:
            print("The saved rules could not be loaded")


def get_action():
    while True:
        action = input("Action (ALLOW or BLOCK): ").upper()
        if action == "ALLOW" or action == "BLOCK":
            return action
        print("Please enter ALLOW or BLOCK")


def get_ip(allow_any):
    while True:
        ip = input("Source IP: ")

        if allow_any == True:
            if ip == "" or ip.upper() == "ANY":
                return "ANY"

        if valid_ip(ip):
            return ip

        print("Please enter a valid IP address")


def get_port(allow_any):
    while True:
        port = input("Destination port: ")

        if allow_any == True:
            if port == "" or port.upper() == "ANY":
                return "ANY"

        try:
            port = int(port)
            if port >= 1 and port <= 65535:
                return port
        except ValueError:
            pass

        print("Please enter a port from 1 to 65535")


def get_protocol(allow_any):
    while True:
        protocol = input("Protocol (TCP, UDP or ICMP): ").upper()

        if allow_any == True:
            if protocol == "" or protocol == "ANY":
                return "ANY"

        if protocol == "TCP" or protocol == "UDP" or protocol == "ICMP":
            return protocol

        print("Please enter TCP, UDP or ICMP")


def get_traffic_type(allow_any):
    while True:
        print("Traffic types: WEB, EMAIL, FILE_TRANSFER, PING, OTHER")
        traffic_type = input("Traffic type: ").upper()

        if allow_any == True:
            if traffic_type == "" or traffic_type == "ANY":
                return "ANY"

        if traffic_type == "WEB":
            return traffic_type
        if traffic_type == "EMAIL":
            return traffic_type
        if traffic_type == "FILE_TRANSFER":
            return traffic_type
        if traffic_type == "PING":
            return traffic_type
        if traffic_type == "OTHER":
            return traffic_type

        print("Please enter one of the traffic types shown")


def add_rule():
    print("Enter ANY or leave blank if a field should match everything")
    action = get_action()
    source_ip = get_ip(True)
    port = get_port(True)
    protocol = get_protocol(True)
    traffic_type = get_traffic_type(True)
    description = input("Description: ")

    new_rule = make_rule(
        action,
        source_ip,
        port,
        protocol,
        traffic_type,
        description
    )
    rules.append(new_rule)
    print("Rule added")


def show_rules():
    if len(rules) == 0:
        print("No rules have been added")
        return

    print("Rules are checked from top to bottom")
    number = 1

    for rule in rules:
        print("\nRule", number)
        print("Action:", rule["action"])
        print("Source IP:", rule["source_ip"])
        print("Port:", rule["port"])
        print("Protocol:", rule["protocol"])
        print("Traffic type:", rule["traffic_type"])
        print("Description:", rule["description"])
        number = number + 1


def remove_rule():
    show_rules()

    if len(rules) == 0:
        return

    try:
        number = int(input("Rule number to remove: "))
        if number >= 1 and number <= len(rules):
            rules.pop(number - 1)
            print("Rule removed")
        else:
            print("That rule number does not exist")
    except ValueError:
        print("Please enter a number")


def test_packet():
    source_ip = get_ip(False)
    port = get_port(False)
    protocol = get_protocol(False)
    traffic_type = get_traffic_type(False)

    packet = make_packet(source_ip, port, protocol, traffic_type)
    result = check_packet(rules, packet, log_file)
    action = result[0]
    reason = result[1]

    print("Decision:", action)
    print("Reason:", reason)
    print("The action was added to firewall.log")


def show_log():
    if log_file.exists():
        file = open(log_file, "r")
        text = file.read()
        file.close()
        print(text)
    else:
        print("The log is empty")


def menu():
    load_rules()

    while True:
        print("\nSimple Firewall Simulator")
        print("1. View rules")
        print("2. Add rule")
        print("3. Remove rule")
        print("4. Test a packet")
        print("5. View log")
        print("6. Save rules")
        print("7. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            show_rules()
        elif choice == "2":
            add_rule()
        elif choice == "3":
            remove_rule()
        elif choice == "4":
            test_packet()
        elif choice == "5":
            show_log()
        elif choice == "6":
            save_rules()
            print("Rules saved")
        elif choice == "7":
            save_rules()
            print("Rules saved. Goodbye")
            break
        else:
            print("Please choose a number from 1 to 7")


if __name__ == "__main__":
    menu()
