# badbot

Public list of bad bots, ASNs, and IPs (v4 and v6) provided by [badbot.icu](https://badbot.icu).

---

## About

**badbot** publishes a continuously updated list of suspicious IP addresses to help you protect your own infrastructure against known attackers. The lists are updated **automatically every day** and are available **free of charge**.

## Lists

| File | Description |
|------|-------------|
| [`lists/ipv4.txt`](lists/ipv4.txt) | Known bad IPv4 addresses and CIDR ranges |
| [`lists/ipv6.txt`](lists/ipv6.txt) | Known bad IPv6 addresses and CIDR ranges |
| [`lists/asn.txt`](lists/asn.txt) | Known bad Autonomous System Numbers (ASNs) |

## Usage

### Download the latest list (raw)

```bash
# IPv4
curl -o badbot-ipv4.txt https://raw.githubusercontent.com/blocksberghexhex/badbot/main/lists/ipv4.txt

# IPv6
curl -o badbot-ipv6.txt https://raw.githubusercontent.com/blocksberghexhex/badbot/main/lists/ipv6.txt
```

### Block with iptables (IPv4)

```bash
while IFS= read -r line; do
  [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
  iptables -I INPUT -s "$line" -j DROP
done < badbot-ipv4.txt
```

### Block with ip6tables (IPv6)

```bash
while IFS= read -r line; do
  [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
  ip6tables -I INPUT -s "$line" -j DROP
done < badbot-ipv6.txt
```

### nginx

```nginx
# Generate deny rules from the list:
# awk '!/^#/ && NF {print "deny "$1";"}' badbot-ipv4.txt > /etc/nginx/conf.d/badbot.conf
# Then reload nginx.
```

## Update Schedule

The lists are refreshed **daily at 02:00 UTC** via GitHub Actions. You can also trigger a manual update from the [Actions tab](../../actions/workflows/update-lists.yml).

## License

The lists are free for personal and commercial use.
