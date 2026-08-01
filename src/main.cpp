// SPDX-License-Identifier: MIT
// cpp-dns-probe — DNS resolver & packet analyzer in C++23
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o dnsprobe
// Usage: ./dnsprobe <domain> [--type A|AAAA|MX|NS|CNAME|SOA|PTR|TXT]
//                     [--server IP] [--port N] [--timeout S] [--retries N]
//        ./dnsprobe -x <ipv4>         reverse lookup (PTR)
//        ./dnsprobe --parse <hex>     offline decode of a DNS response
//        ./dnsprobe --selftest        encode/decode self-tests
//        ./dnsprobe --help

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace dns {

// ── DNS constants ──────────────────────────────────────────────────────────
constexpr uint16_t TYPE_A     = 1;
constexpr uint16_t TYPE_NS    = 2;
constexpr uint16_t TYPE_CNAME = 5;
constexpr uint16_t TYPE_SOA   = 6;
constexpr uint16_t TYPE_PTR   = 12;
constexpr uint16_t TYPE_MX    = 15;
constexpr uint16_t TYPE_TXT   = 16;
constexpr uint16_t TYPE_AAAA  = 28;
constexpr uint16_t CLASS_IN   = 1;

// Real response captured from 8.8.8.8 for example.com (A, 2 records) — used
// by --selftest to verify the parser against real-world wire data.
constexpr std::string_view k_captured_example_com =
    "d71781800001000200000000076578616d706c6503636f6d0000010001"
    "c00c000100010000012c0004ac4293f3"
    "c00c000100010000012c00046814179a";

// ── Small helpers ──────────────────────────────────────────────────────────
std::string type_name(uint16_t t) {
  switch (t) {
    case TYPE_A:     return "A";
    case TYPE_NS:    return "NS";
    case TYPE_CNAME: return "CNAME";
    case TYPE_SOA:   return "SOA";
    case TYPE_PTR:   return "PTR";
    case TYPE_MX:    return "MX";
    case TYPE_TXT:   return "TXT";
    case TYPE_AAAA:  return "AAAA";
    default:         return "TYPE" + std::to_string(t);
  }
}

std::string rcode_str(uint8_t rc) {
  switch (rc) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 4: return "NOTIMP";
    case 5: return "REFUSED";
    default: return "RCODE" + std::to_string(rc);
  }
}

std::optional<uint16_t> parse_qtype(std::string_view s) {
  std::string up(s);
  std::transform(up.begin(), up.end(), up.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  if (up == "A")     return TYPE_A;
  if (up == "AAAA")  return TYPE_AAAA;
  if (up == "MX")    return TYPE_MX;
  if (up == "NS")    return TYPE_NS;
  if (up == "CNAME") return TYPE_CNAME;
  if (up == "SOA")   return TYPE_SOA;
  if (up == "PTR")   return TYPE_PTR;
  if (up == "TXT")   return TYPE_TXT;
  return std::nullopt;
}

std::string reverse_name(const std::string& ip) {
  std::vector<std::string> parts;
  std::string cur;
  for (char c : ip) {
    if (c == '.') { parts.push_back(cur); cur.clear(); }
    else cur += c;
  }
  parts.push_back(cur);
  if (parts.size() != 4) return {};
  std::string rev;
  for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
    if (!rev.empty()) rev += ".";
    rev += *it;
  }
  rev += ".in-addr.arpa";
  return rev;
}

bool valid_domain(std::string_view d) {
  if (d.empty() || d.size() > 253) return false;
  for (char c : d) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_'))
      return false;
  }
  return true;
}

// ── Name encoding / decoding (RFC 1035 §4.1.2, with compression) ──────────
bool encode_name(const std::string& name_in, std::vector<uint8_t>& out) {
  std::string name = name_in;
  if (name.empty()) return false;
  if (name.back() == '.') name.pop_back();
  if (name.empty()) { out.push_back(0); return true; }
  size_t start = 0;
  while (true) {
    size_t dot = name.find('.', start);
    size_t end = (dot == std::string::npos) ? name.size() : dot;
    size_t len = end - start;
    if (len == 0 || len > 63) return false;
    out.push_back(static_cast<uint8_t>(len));
    out.insert(out.end(), name.begin() + static_cast<ptrdiff_t>(start),
               name.begin() + static_cast<ptrdiff_t>(end));
    if (dot == std::string::npos) break;
    start = end + 1;
  }
  out.push_back(0);
  return true;
}

// Decode a possibly-compressed name starting at `pos` (updated past the name).
std::optional<std::string> decode_name(const std::vector<uint8_t>& pkt, size_t& pos) {
  std::string name;
  size_t p = pos;
  std::vector<size_t> seen;
  bool jumped = false;
  size_t jumps = 0;
  while (true) {
    if (p >= pkt.size()) return std::nullopt;
    const uint8_t len = pkt[p];
    if ((len & 0xC0) == 0xC0) {  // compression pointer
      if (p + 1 >= pkt.size()) return std::nullopt;
      const size_t off = (static_cast<size_t>(len & 0x3F) << 8) | pkt[p + 1];
      if (off >= pkt.size()) return std::nullopt;
      if (std::find(seen.begin(), seen.end(), off) != seen.end()) return std::nullopt;  // loop
      seen.push_back(off);
      if (!jumped) { pos = p + 2; jumped = true; }
      p = off;
      if (++jumps > 16) return std::nullopt;
      continue;
    }
    if (len == 0) {  // root terminator
      if (!jumped) pos = p + 1;
      break;
    }
    if (len > 63 || p + 1 + len > pkt.size()) return std::nullopt;
    if (!name.empty()) name += '.';
    name.append(reinterpret_cast<const char*>(&pkt[p + 1]), len);
    p += 1 + len;
  }
  return name;
}

// ── Bounds-checked big-endian reader ───────────────────────────────────────
struct Reader {
  const std::vector<uint8_t>& pkt;
  size_t pos = 0;
  bool ok = true;

  bool read16(uint16_t& v) {
    if (pos + 2 > pkt.size()) { ok = false; return false; }
    v = static_cast<uint16_t>((static_cast<uint16_t>(pkt[pos]) << 8) | pkt[pos + 1]);
    pos += 2;
    return true;
  }
  bool read32(uint32_t& v) {
    if (pos + 4 > pkt.size()) { ok = false; return false; }
    v = (static_cast<uint32_t>(pkt[pos]) << 24) |
        (static_cast<uint32_t>(pkt[pos + 1]) << 16) |
        (static_cast<uint32_t>(pkt[pos + 2]) << 8) |
        static_cast<uint32_t>(pkt[pos + 3]);
    pos += 4;
    return true;
  }
  bool skip(size_t n) {
    if (pos + n > pkt.size()) { ok = false; return false; }
    pos += n;
    return true;
  }
};

// ── Query builder ──────────────────────────────────────────────────────────
std::vector<uint8_t> build_query(uint16_t id, const std::string& name, uint16_t qtype) {
  std::vector<uint8_t> pkt;
  auto push16 = [&](uint16_t v) {
    pkt.push_back(static_cast<uint8_t>(v >> 8));
    pkt.push_back(static_cast<uint8_t>(v & 0xFF));
  };
  push16(id);
  push16(0x0100);  // flags: RD
  push16(1); push16(0); push16(0); push16(0);  // qd=1, an=0, ns=0, ar=0
  if (!encode_name(name, pkt)) return {};
  push16(qtype);
  push16(CLASS_IN);
  return pkt;
}

// ── Response parsing ───────────────────────────────────────────────────────
struct Record {
  std::string name;
  uint16_t type = 0;
  uint16_t klass = 0;
  uint32_t ttl = 0;
  std::string rdata;  // human-readable
};

struct Response {
  bool ok = false;
  std::string error;
  size_t size = 0;
  uint16_t id = 0;
  uint8_t rcode = 0;
  bool qr = false, aa = false, tc = false, rd = false, ra = false;
  std::string qname;
  uint16_t qtype = 0;
  std::vector<Record> answers, authorities, additionals;
};

std::string format_rdata(const std::vector<uint8_t>& pkt, uint16_t type,
                         size_t rdata_pos, size_t rdlen) {
  std::string s;
  switch (type) {
    case TYPE_A: {
      if (rdlen == 4) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt[rdata_pos], buf, sizeof(buf));
        s = buf;
      } else s = "(bad A rdata)";
      break;
    }
    case TYPE_AAAA: {
      if (rdlen == 16) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt[rdata_pos], buf, sizeof(buf));
        s = buf;
      } else s = "(bad AAAA rdata)";
      break;
    }
    case TYPE_CNAME:
    case TYPE_NS:
    case TYPE_PTR: {
      size_t p = rdata_pos;
      auto nm = decode_name(pkt, p);
      s = nm.value_or("(bad name)");
      break;
    }
    case TYPE_MX: {
      if (rdlen >= 3) {
        uint16_t pref = static_cast<uint16_t>((static_cast<uint16_t>(pkt[rdata_pos]) << 8) |
                                              pkt[rdata_pos + 1]);
        size_t p = rdata_pos + 2;
        auto nm = decode_name(pkt, p);
        s = std::to_string(pref) + " " + nm.value_or("(bad name)");
      } else s = "(bad MX rdata)";
      break;
    }
    case TYPE_TXT: {
      size_t p = rdata_pos;
      const size_t end = rdata_pos + rdlen;
      std::vector<std::string> parts;
      while (p < end) {
        const uint8_t len = pkt[p++];
        if (p + len > end) { parts.emplace_back("(bad txt)"); break; }
        parts.emplace_back(reinterpret_cast<const char*>(&pkt[p]), len);
        p += len;
      }
      for (size_t i = 0; i < parts.size(); ++i) {
        if (i) s += " ";
        s += '"' + parts[i] + '"';
      }
      break;
    }
    case TYPE_SOA: {
      size_t p = rdata_pos;
      auto mname = decode_name(pkt, p);
      auto rname = decode_name(pkt, p);
      auto rd32 = [&](uint32_t& v) -> bool {
        if (p + 4 > rdata_pos + rdlen) return false;
        v = (static_cast<uint32_t>(pkt[p]) << 24) |
            (static_cast<uint32_t>(pkt[p + 1]) << 16) |
            (static_cast<uint32_t>(pkt[p + 2]) << 8) |
            static_cast<uint32_t>(pkt[p + 3]);
        p += 4;
        return true;
      };
      uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
      if (mname && rname && rd32(serial) && rd32(refresh) && rd32(retry) &&
          rd32(expire) && rd32(minimum)) {
        s = mname.value() + " " + rname.value() + " " + std::to_string(serial) + " " +
            std::to_string(refresh) + " " + std::to_string(retry) + " " +
            std::to_string(expire) + " " + std::to_string(minimum);
      } else s = "(bad SOA rdata)";
      break;
    }
    default: {
      for (size_t i = 0; i < rdlen && i < 32; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", pkt[rdata_pos + i]);
        s += buf;
      }
      if (rdlen > 32) s += "...";
    }
  }
  return s;
}

Response parse_response(const std::vector<uint8_t>& pkt) {
  Response r;
  r.size = pkt.size();
  Reader rd{pkt};
  uint16_t flags = 0, qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
  if (!rd.read16(r.id) || !rd.read16(flags) || !rd.read16(qdcount) ||
      !rd.read16(ancount) || !rd.read16(nscount) || !rd.read16(arcount)) {
    r.error = "packet too short for header (need >= 12 bytes)";
    return r;
  }
  r.qr = flags & 0x8000;
  r.aa = flags & 0x0400;
  r.tc = flags & 0x0200;
  r.rd = flags & 0x0100;
  r.ra = flags & 0x0080;
  r.rcode = static_cast<uint8_t>(flags & 0x000F);

  for (uint16_t i = 0; i < qdcount; ++i) {
    auto nm = decode_name(pkt, rd.pos);
    uint16_t qt = 0, qc = 0;
    if (!nm || !rd.read16(qt) || !rd.read16(qc)) {
      r.error = "malformed question section";
      return r;
    }
    if (i == 0) { r.qname = *nm; r.qtype = qt; }
  }

  auto parse_section = [&](uint16_t count, std::vector<Record>& out) -> bool {
    for (uint16_t i = 0; i < count; ++i) {
      Record rec;
      auto nm = decode_name(pkt, rd.pos);
      uint16_t rdlen = 0;
      if (!nm || !rd.read16(rec.type) || !rd.read16(rec.klass) ||
          !rd.read32(rec.ttl) || !rd.read16(rdlen)) {
        r.error = "malformed resource record header";
        return false;
      }
      rec.name = *nm;
      const size_t rdata_pos = rd.pos;
      if (!rd.skip(rdlen)) { r.error = "rdata out of bounds"; return false; }
      rec.rdata = format_rdata(pkt, rec.type, rdata_pos, rdlen);
      out.push_back(std::move(rec));
    }
    return true;
  };

  if (!parse_section(ancount, r.answers)) return r;
  if (!parse_section(nscount, r.authorities)) return r;
  if (!parse_section(arcount, r.additionals)) return r;
  r.ok = true;
  return r;
}

// ── UDP transport ──────────────────────────────────────────────────────────
struct QueryResult {
  std::optional<std::vector<uint8_t>> pkt;
  double rtt_ms = 0.0;
  std::string error;
};

QueryResult send_query(const std::string& server, uint16_t port,
                       const std::vector<uint8_t>& query, int timeout_s, int retries) {
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return {std::nullopt, 0.0, "socket(): " + std::string(std::strerror(errno))};

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, server.c_str(), &addr.sin_addr) != 1) {
    close(fd);
    return {std::nullopt, 0.0, "invalid resolver address: " + server};
  }

  timeval tv{};
  tv.tv_sec = timeout_s;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  const auto t0 = std::chrono::steady_clock::now();
  std::string last_err;
  for (int attempt = 0; attempt <= retries; ++attempt) {
    if (sendto(fd, query.data(), query.size(), 0,
               reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
      last_err = "sendto(): " + std::string(std::strerror(errno));
      continue;
    }
    std::vector<uint8_t> buf(65536);
    const ssize_t n = recvfrom(fd, buf.data(), buf.size(), 0, nullptr, nullptr);
    if (n > 0) {
      buf.resize(static_cast<size_t>(n));
      const auto t1 = std::chrono::steady_clock::now();
      const double rtt = std::chrono::duration<double, std::milli>(t1 - t0).count();
      close(fd);
      return {std::move(buf), rtt, ""};
    }
    last_err = (errno == EAGAIN || errno == EWOULDBLOCK)
                 ? "timeout (" + std::to_string(timeout_s) + "s)"
                 : "recvfrom(): " + std::string(std::strerror(errno));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  close(fd);
  return {std::nullopt, 0.0, last_err};
}

std::string default_server() {
  std::ifstream f("/etc/resolv.conf");
  std::string line;
  while (std::getline(f, line)) {
    std::istringstream iss{line};  // brace init (avoid most vexing parse)
    std::string kw, val;
    if (iss >> kw >> val && kw == "nameserver" && !val.empty()) return val;
  }
  return "8.8.8.8";
}

uint16_t next_id() {
  static uint16_t c = static_cast<uint16_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  ++c;
  if (c == 0) ++c;
  return c;
}

// ── Hex utilities ──────────────────────────────────────────────────────────
std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
  std::vector<uint8_t> out;
  std::string clean;
  bool in_comment = false;
  for (const char c : hex) {
    if (c == '#') { in_comment = true; continue; }
    if (in_comment) {
      if (c == '\n') in_comment = false;
      continue;
    }
    if (c == ' ' || c == '\n' || c == '\t' || c == '\r') continue;
    clean += c;
  }
  if (clean.size() % 2 != 0) return std::nullopt;
  const auto hexval = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < clean.size(); i += 2) {
    const int hi = hexval(clean[i]);
    const int lo = hexval(clean[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

// ── Output ─────────────────────────────────────────────────────────────────
struct Palette {
  std::string reset, dim, cyan, green, yellow, red, blue;
};

Palette make_palette(bool color) {
  if (!color) return {"", "", "", "", "", "", ""};
  return {"\033[0m", "\033[2m", "\033[36m", "\033[32m",
          "\033[33m", "\033[31m", "\033[34m"};
}

void print_section(const std::string& title, const std::vector<Record>& recs,
                   const Palette& P, std::string_view indent) {
  if (recs.empty()) return;
  std::println(std::cout, "{}{} {} ({}){}",
               indent, "──", title, recs.size(), P.reset);
  for (const auto& rec : recs) {
    std::print(std::cout, "{}  {}{}{}  {}  IN  {}{}{}  ",
               indent, P.dim, rec.name, P.reset, rec.ttl,
               P.blue, type_name(rec.type), P.reset);
    std::println(std::cout, "{}{}{}", P.green, rec.rdata, P.reset);
  }
}

std::string flags_str(const Response& r) {
  std::string fl;
  if (r.qr) fl += "QR ";
  if (r.aa) fl += "AA ";
  if (r.tc) fl += "TC ";
  if (r.rd) fl += "RD ";
  if (r.ra) fl += "RA ";
  if (fl.empty()) fl = "-";
  return fl;
}

void print_response_summary(const Response& r) {
  std::println(std::cout, "  id=0x{:04X}  flags: {}  rcode: {}", r.id,
               flags_str(r), rcode_str(r.rcode));
  std::println(std::cout, "  question:  {}  IN  {}", r.qname, type_name(r.qtype));
  std::println(std::cout, "  answer: {}  authority: {}  additional: {}  · {} bytes",
               r.answers.size(), r.authorities.size(), r.additionals.size(), r.size);
}

// ── Modes ──────────────────────────────────────────────────────────────────
struct Options {
  std::vector<std::string> domains;
  uint16_t qtype = TYPE_A;
  std::string server = "8.8.8.8";
  uint16_t port = 53;
  int timeout_s = 3;
  int retries = 2;
  bool color = true;
  bool help = false;
  bool selftest = false;
  bool parse_hex = false;
  std::string hex_input;
};

void print_help() {
  std::println(std::cout, "Usage: dnsprobe <domain> [<domain> ...] [options]");
  std::println(std::cout, "       dnsprobe -x <ipv4>");
  std::println(std::cout, "       dnsprobe --parse <hex>");
  std::println(std::cout, "       dnsprobe --selftest");
  std::println(std::cout, "");
  std::println(std::cout, "Options:");
  std::println(std::cout, "  --type <T>     record type: A, AAAA, MX, NS, CNAME, SOA, PTR, TXT");
  std::println(std::cout, "  --server <ip>  resolver IP (default: first nameserver in");
  std::println(std::cout, "                 /etc/resolv.conf, fallback 8.8.8.8)");
  std::println(std::cout, "  --port <n>     resolver port (default 53)");
  std::println(std::cout, "  --timeout <s>  per-attempt timeout in seconds (default 3)");
  std::println(std::cout, "  --retries <n>  retries after timeout (default 2)");
  std::println(std::cout, "  -x <ipv4>      reverse lookup (PTR)");
  std::println(std::cout, "  --parse <hex>  offline decode of a hex DNS response");
  std::println(std::cout, "  --selftest     run encode/decode self-tests");
  std::println(std::cout, "  --no-color     disable ANSI colors");
  std::println(std::cout, "  -h, --help     show this help");
  std::println(std::cout, "");
  std::println(std::cout, "Exit codes: 0 = answers found · 1 = NXDOMAIN / no records · 2 = error");
}

Options parse_args(int argc, char** argv) {
  Options opt;
  opt.server = default_server();
  opt.color = isatty(STDOUT_FILENO) != 0;

  for (int i = 1; i < argc; ++i) {
    const std::string_view a{argv[i]};
    auto next = [&](const char* flag) -> std::string {
      if (i + 1 >= argc) {
        std::println(std::cerr, "dnsprobe: missing value for {}", flag);
        std::exit(2);
      }
      return std::string(argv[++i]);
    };

    if (a == "--type") {
      auto t = parse_qtype(next("--type"));
      if (!t) {
        std::println(std::cerr, "dnsprobe: unknown type '{}'", argv[i]);
        std::exit(2);
      }
      opt.qtype = *t;
    } else if (a == "--server") {
      opt.server = next("--server");
    } else if (a == "--port") {
      const auto v = next("--port");
      unsigned n = 0;
      if (std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc{} || n == 0 || n > 65535) {
        std::println(std::cerr, "dnsprobe: invalid port '{}'", v);
        std::exit(2);
      }
      opt.port = static_cast<uint16_t>(n);
    } else if (a == "--timeout") {
      const auto v = next("--timeout");
      int n = 0;
      if (std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc{} || n < 1 || n > 60) {
        std::println(std::cerr, "dnsprobe: invalid timeout '{}'", v);
        std::exit(2);
      }
      opt.timeout_s = n;
    } else if (a == "--retries") {
      const auto v = next("--retries");
      int n = 0;
      if (std::from_chars(v.data(), v.data() + v.size(), n).ec != std::errc{} || n < 0 || n > 10) {
        std::println(std::cerr, "dnsprobe: invalid retries '{}'", v);
        std::exit(2);
      }
      opt.retries = n;
    } else if (a == "-x") {
      const auto ip = next("-x");
      const auto rev = reverse_name(ip);
      if (rev.empty()) {
        std::println(std::cerr, "dnsprobe: '{}' is not a valid IPv4 address", ip);
        std::exit(2);
      }
      opt.qtype = TYPE_PTR;
      opt.domains.push_back(rev);
    } else if (a == "--parse") {
      opt.parse_hex = true;
      opt.hex_input = next("--parse");
    } else if (a == "--selftest") {
      opt.selftest = true;
    } else if (a == "--no-color") {
      opt.color = false;
    } else if (a == "--help" || a == "-h") {
      opt.help = true;
    } else if (a.starts_with("-")) {
      std::println(std::cerr, "dnsprobe: unknown option '{}'", a);
      std::exit(2);
    } else {
      opt.domains.emplace_back(a);
    }
  }
  return opt;
}

int run_query(const Options& opt, const Palette& P) {
  int code = 0;
  for (const auto& domain : opt.domains) {
    if (!valid_domain(domain)) {
      std::println(std::cout, "  {}✗ '{}' is not a valid domain name{}",
                   P.red, domain, P.reset);
      code = std::max(code, 2);
      continue;
    }
    const uint16_t id = next_id();
    auto query = build_query(id, domain, opt.qtype);
    if (query.empty()) {
      std::println(std::cout, "  {}✗ could not encode '{}'{}", P.red, domain, P.reset);
      code = std::max(code, 2);
      continue;
    }
    const std::string target = "→ " + opt.server + ":" + std::to_string(opt.port) +
                               "  [timeout " + std::to_string(opt.timeout_s) + "s ×" +
                               std::to_string(opt.retries + 1) + "]";
    std::println(std::cout, "  {}▸ {}{}  ({})  {}",
                 P.cyan, domain, P.reset, type_name(opt.qtype), P.dim + target + P.reset);

    auto res = send_query(opt.server, opt.port, query, opt.timeout_s, opt.retries);
    if (!res.pkt) {
      std::println(std::cout, "      {}✗ {}{}", P.red, res.error, P.reset);
      code = std::max(code, 2);
      continue;
    }
    auto resp = parse_response(*res.pkt);
    if (!resp.ok) {
      std::println(std::cout, "      {}✗ malformed response: {}{}",
                   P.red, resp.error, P.reset);
      code = std::max(code, 2);
      continue;
    }

    print_response_summary(resp);
    print_section("ANSWER", resp.answers, P, "      ");
    print_section("AUTHORITY", resp.authorities, P, "      ");
    print_section("ADDITIONAL", resp.additionals, P, "      ");

    if (resp.rcode == 3) {
      std::println(std::cout, "      {}✗ NXDOMAIN — {} does not exist{}",
                   P.red, domain, P.reset);
      code = std::max(code, 1);
    } else if (resp.answers.empty()) {
      std::println(std::cout, "      {}✗ no {} record(s) found{}",
                   P.yellow, type_name(opt.qtype), P.reset);
      code = std::max(code, 1);
    } else {
      std::println(std::cout, "      {}✓ {}{} answer(s) in {:.1f} ms",
                   P.green, P.reset, resp.answers.size(), res.rtt_ms);
      code = std::max(code, 0);
    }
    std::println(std::cout, "");
  }
  return code;
}

int run_parse(const Options& opt, const Palette& P) {
  auto bytes = hex_to_bytes(opt.hex_input);
  if (!bytes) {
    std::println(std::cerr, "dnsprobe: invalid hex input for --parse");
    return 2;
  }
  std::println(std::cout, "  offline decode of {} byte(s)", bytes->size());
  auto resp = parse_response(*bytes);
  if (!resp.ok) {
    std::println(std::cout, "  {}✗ {}{}", P.red, resp.error, P.reset);
    return 2;
  }
  print_response_summary(resp);
  print_section("ANSWER", resp.answers, P, "  ");
  print_section("AUTHORITY", resp.authorities, P, "  ");
  print_section("ADDITIONAL", resp.additionals, P, "  ");
  return 0;
}

int run_selftest(const Palette& P) {
  std::println(std::cout, "  self-tests (encode / decode / parse)");
  int pass = 0;
  int fail = 0;
  const auto check = [&](bool ok, std::string_view name) {
    if (ok) {
      ++pass;
      std::println(std::cout, "    {}PASS{}  {}", P.green, P.reset, name);
    } else {
      ++fail;
      std::println(std::cout, "    {}FAIL{}  {}", P.red, P.reset, name);
    }
  };

  {
    std::vector<uint8_t> out;
    const bool ok = encode_name("example.com", out);
    const std::vector<uint8_t> expect{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                      3, 'c', 'o', 'm', 0};
    check(ok && out == expect, "encode example.com");
  }
  {
    std::vector<uint8_t> out;
    const bool ok = encode_name("example.com.", out);
    const std::vector<uint8_t> expect{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                      3, 'c', 'o', 'm', 0};
    check(ok && out == expect, "encode example.com. (trailing dot)");
  }
  {
    std::vector<uint8_t> out;
    const bool ok = encode_name(".", out);
    check(ok && out == std::vector<uint8_t>{0}, "encode root (.)");
  }
  {
    const auto q = build_query(0x1234, "www.example.com", TYPE_A);
    Reader rd{q};
    uint16_t id = 0, flags = 0, qd = 0, an = 0, ns = 0, ar = 0;
    const bool header_ok = rd.read16(id) && rd.read16(flags) && rd.read16(qd) &&
                           rd.read16(an) && rd.read16(ns) && rd.read16(ar);
    auto nm = decode_name(q, rd.pos);
    uint16_t qt = 0, qc = 0;
    check(header_ok && id == 0x1234 && qd == 1 && nm && *nm == "www.example.com" &&
              rd.read16(qt) && qt == TYPE_A && rd.read16(qc) && qc == CLASS_IN,
          "query header + question roundtrip");
  }
  {
    // Synthetic response using a compression pointer (0xC00C → offset 12).
    std::vector<uint8_t> pkt;
    const auto push16 = [&](uint16_t v) {
      pkt.push_back(static_cast<uint8_t>(v >> 8));
      pkt.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    push16(0x0102); push16(0x8180); push16(1); push16(1); push16(0); push16(0);
    encode_name("example.com", pkt);
    push16(TYPE_A); push16(CLASS_IN);
    pkt.push_back(0xC0); pkt.push_back(0x0C);
    push16(TYPE_A); push16(CLASS_IN);
    push16(0); push16(300);  // ttl = 0x0000012C (32-bit)
    push16(4);               // rdlen = 4
    pkt.push_back(93); pkt.push_back(184); pkt.push_back(215); pkt.push_back(14);
    const auto resp = parse_response(pkt);
    check(resp.ok && resp.answers.size() == 1 && resp.answers[0].name == "example.com" &&
              resp.answers[0].rdata == "93.184.215.14",
          "parse compression pointer + A record");
  }
  {
    const auto bytes = hex_to_bytes(k_captured_example_com);
    const auto resp = parse_response(*bytes);
    check(resp.ok && resp.qname == "example.com" && resp.answers.size() == 2 &&
              resp.answers[0].type == TYPE_A && resp.answers[0].rdata == "172.66.147.243" &&
              resp.answers[1].rdata == "104.20.23.154" && resp.rcode == 0,
          "parse real 8.8.8.8 response (example.com A ×2)");
  }
  {
    const std::vector<uint8_t> bad{0x12, 0x34, 0x01};
    const auto resp = parse_response(bad);
    check(!resp.ok && !resp.error.empty(), "reject truncated packet");
  }
  {
    check(type_name(TYPE_A) == "A" && type_name(TYPE_MX) == "MX" &&
              type_name(12345) == "TYPE12345",
          "type_name mapping");
  }
  {
    check(reverse_name("8.8.8.8") == "8.8.8.8.in-addr.arpa",
          "reverse_name (ipv4)");
  }
  {
    const auto b = hex_to_bytes("# comment line\n 0a 0B cC # trailing comment\n");
    check(b && b->size() == 3 && (*b)[0] == 10 && (*b)[1] == 11 && (*b)[2] == 204,
          "hex_to_bytes (skips # comments)");
  }

  std::println(std::cout, "  {}{}/{} selftests passed{}",
               fail == 0 ? P.green : P.red, pass, pass + fail, P.reset);
  return fail == 0 ? 0 : 1;
}

}  // namespace dns

int main(int argc, char** argv) {
  using namespace dns;
  const Options opt = parse_args(argc, argv);
  const Palette P = make_palette(opt.color);

  std::println(std::cout, "{}{}{}", P.cyan,
               "dnsprobe — DNS resolver & packet analyzer (C++23)", P.reset);
  std::println(std::cout, "");

  if (opt.help) { print_help(); return 0; }
  if (opt.selftest) return run_selftest(P);
  if (opt.parse_hex) return run_parse(opt, P);
  if (opt.domains.empty()) {
    std::println(std::cerr, "dnsprobe: no domain given (see --help)");
    return 2;
  }
  return run_query(opt, P);
}
