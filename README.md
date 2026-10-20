# Firewall Simulator

This Python application evaluates simulated network packets against configurable
firewall rules. It does **not** modify the host operating system's firewall or
intercept real network traffic.

## Requirements

- Python 3.9 or newer
- Python standard library only

## How to run it

Run from the project directory:

```powershell
python firewall_simulator.py
```

On Windows, the Python launcher can also be used:

```powershell
py firewall_simulator.py
```

The menu lets you view, add, and remove rules; test packets; view the action log;
and save rules. Saved rules go into `rules.json`, while every packet decision is
appended to `firewall.log`.

## Firewall logic

A packet has four properties:

- **Source IP:** the address the traffic comes from
- **Destination port:** the service it wants to reach (for example, 80 for HTTP)
- **Protocol:** TCP, UDP, or ICMP
- **Traffic type:** WEB, EMAIL, FILE_TRANSFER, PING, or OTHER

Each rule says `ALLOW` or `BLOCK` and can match one or more of those properties.
`ANY` means that property does not matter.

Rules are checked from top to bottom. The **first matching rule wins**. This is
important: a rule blocking an IP at the top can override a later rule that allows
web traffic. If no rule matches, the simulator allows the packet by
default. Real high-security firewalls often use "deny by default" instead.

The logic is:

```text
packet enters
    |
check rule 1 -- matches? --> use its ALLOW/BLOCK action and stop
    |
check rule 2 -- matches? --> use its ALLOW/BLOCK action and stop
    |
continue through rules
    |
no match --> use default ALLOW
    |
write the decision and reason to firewall.log
```

## Example rules to enter in the menu

| Action | Source IP | Port | Protocol | Traffic type | Meaning |
|---|---|---:|---|---|---|
| BLOCK | 192.168.1.50 | ANY | ANY | ANY | Block one suspicious IP |
| ALLOW | ANY | 80 | TCP | WEB | Allow HTTP web traffic |
| BLOCK | ANY | 23 | TCP | ANY | Block insecure Telnet traffic |
| BLOCK | ANY | ANY | ICMP | ANY | Block ICMP packets such as ping |
| BLOCK | ANY | ANY | ANY | FILE_TRANSFER | Block file transfers |

## Example manual test cases

Add the rules above in the same order, then choose **Test a packet**.

| Test | Packet values | Expected result | Why |
|---|---|---|---|
| 1 | `192.168.1.50`, port `80`, TCP, WEB | BLOCK | The blocked-IP rule matches first |
| 2 | `10.0.0.5`, port `80`, TCP, WEB | ALLOW | The web allow rule matches |
| 3 | `10.0.0.5`, port `23`, TCP, OTHER | BLOCK | Telnet port 23 is blocked |
| 4 | `10.0.0.5`, port `8`, ICMP, PING | BLOCK | ICMP is blocked |
| 5 | `10.0.0.5`, port `21`, TCP, FILE_TRANSFER | BLOCK | The traffic type is blocked |
| 6 | `10.0.0.5`, port `53`, UDP, OTHER | ALLOW | No rule matches, so default is ALLOW |

## Run the automated tests

The same examples are included as automated tests:

```powershell
python test_firewall.py
```

You should see seven lines starting with `PASS`.

## Project files

- `firewall_simulator.py` — the program and CLI
- `test_firewall.py` — automated example tests
- `rules.json` — created after saving rules
- `firewall.log` — created after testing a packet

## What this project demonstrates

It covers IP, port, protocol, and traffic-type filtering; ordered rules; input
validation; persistent JSON rules; and an audit log. Changing rule order can
change the resulting decision because evaluation stops at the first match.

The project is a rule-evaluation simulator, not a replacement for Windows
Defender Firewall, Linux `nftables`, or a network firewall.
