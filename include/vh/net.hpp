#pragma once

/**
 * vh/net.hpp  —  VanHooks Network Layer
 *
 * Live capture, offline pcap/pcapng read/write, BPF filtering, and full
 * protocol-layer parsing — all compiled directly into libvanhooks.
 *
 * No external libraries or runtime dependencies.  The network stack lives
 * in src/net/ and include/vanhooks/net/ (see /NOTICE) and is compiled
 * directly into the same static archive as the hooking engine.
 *
 * API lives in the vh::net namespace to match the rest of VanHooks.
 *
 * Quick start
 * ───────────
 *   #include <vh/vh.hpp>   // pulls net.hpp in automatically
 *
 *   // Hook something
 *   auto hook = vh::hook(&target, &detour);
 *
 *   // Capture packets on the same host
 *   auto cap = vh::net::Capture::open("eth0");
 *   cap->filter("tcp port 443");
 *   cap->start([](vh::net::Packet pkt) {
 *       auto parsed = pkt.parse();
 *       // use parsed layers …
 *   });
 */

#ifndef VH_NET_ENABLED
#  error "vh/net.hpp included but VH_ENABLE_NET=OFF — re-run CMake with -DVH_ENABLE_NET=ON"
#endif

// ── Internal network stack headers ───────────────────────────────────────────
#include <vanhooks/net/Devices.h>
#include <vanhooks/net/PacketCore.h>
#include <vanhooks/net/L3Layers.h>
#include <vanhooks/net/L4Layers.h>
#include <vanhooks/net/L2Layers.h>

// ── Standard ─────────────────────────────────────────────────────────────────
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <cstdint>

#include "result.hpp"   // vh::Result / vh::Status

namespace vh::net {

// ─────────────────────────────────────────────────────────────────────────────
//  Packet  — non-owning view over a raw captured packet.
//  Valid only inside the PacketCallback invocation; copy raw_data() to keep.
// ─────────────────────────────────────────────────────────────────────────────

class Packet {
public:
    explicit Packet(vanhooks::net::RawPacket* raw) noexcept : raw_(raw) {}

    [[nodiscard]] const uint8_t*               raw_data() const noexcept;
    [[nodiscard]] std::size_t                  raw_len()  const noexcept;
    [[nodiscard]] std::unique_ptr<vanhooks::net::Packet> parse()   const;

    [[nodiscard]] vanhooks::net::RawPacket* raw() const noexcept { return raw_; }

private:
    vanhooks::net::RawPacket* raw_ = nullptr;
};

// ─────────────────────────────────────────────────────────────────────────────
//  DeviceInfo  — lightweight descriptor returned by vh::net::devices()
// ─────────────────────────────────────────────────────────────────────────────

struct DeviceInfo {
    std::string name;        ///< e.g. "eth0", "en0", "\\Device\\NPF_{…}"
    std::string description; ///< human-readable label (may be empty on Linux)
    std::string ip4;         ///< primary IPv4 address as dotted-decimal, or ""
    bool        loopback = false;
};

/// List all interfaces capable of live capture on this machine.
[[nodiscard]] std::vector<DeviceInfo> devices();

// ─────────────────────────────────────────────────────────────────────────────
//  Filter  — BPF expression builder
// ─────────────────────────────────────────────────────────────────────────────

class Filter {
public:
    Filter() = default;
    explicit Filter(std::string_view bpf) : expr_(bpf) {}

    Filter& expr(std::string_view e) { expr_ = e; return *this; }
    [[nodiscard]] std::string_view expr() const noexcept { return expr_; }

private:
    std::string expr_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Capture  — RAII live-interface capture
//
//  auto cap = vh::net::Capture::open("eth0");
//  cap->filter("udp port 53");
//  cap->start([](vh::net::Packet p) { … });
//  cap->stop();   // or let it destruct
// ─────────────────────────────────────────────────────────────────────────────

class Capture {
public:
    using PacketCallback = std::function<void(Packet)>;

    Capture(Capture&&) noexcept;
    Capture& operator=(Capture&&) noexcept;
    Capture(const Capture&)            = delete;
    Capture& operator=(const Capture&) = delete;
    ~Capture();

    // ── Factory ───────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<Capture> open(std::string_view device_name);
    [[nodiscard]] static Result<Capture> open_by_ip(std::string_view ipv4);

    // ── Configuration (before start()) ───────────────────────────────────────
    Capture& filter(std::string_view bpf_expr);
    Capture& filter(const Filter& f)    { return filter(f.expr()); }
    Capture& snap_len(int bytes) noexcept { snap_len_ = bytes; return *this; }
    Capture& promiscuous(bool on) noexcept { promisc_ = on; return *this; }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    Status start(PacketCallback cb);
    void   stop();
    [[nodiscard]] bool running() const noexcept { return running_; }

    // ── Stats ─────────────────────────────────────────────────────────────────
    struct Stats {
        uint32_t received   = 0;
        uint32_t dropped    = 0;
        uint32_t if_dropped = 0;
    };
    [[nodiscard]] std::optional<Stats> stats() const;

    // ── Escape hatch ──────────────────────────────────────────────────────────
    [[nodiscard]] vanhooks::net::PcapLiveDevice* device() const noexcept { return dev_; }

private:
    explicit Capture(vanhooks::net::PcapLiveDevice* dev) noexcept : dev_(dev) {}

    struct CallbackCtx { PacketCallback cb; };
    static void on_packet(vanhooks::net::RawPacket*, vanhooks::net::PcapLiveDevice*, void*) noexcept;

    vanhooks::net::PcapLiveDevice*        dev_      = nullptr;
    bool                         running_  = false;
    bool                         promisc_  = true;
    int                          snap_len_ = 65535;
    std::unique_ptr<CallbackCtx> ctx_;
};

// ─────────────────────────────────────────────────────────────────────────────
//  PcapReader  — offline .pcap / .pcapng reader
//
//  auto r = vh::net::PcapReader::open("dump.pcap");
//  while (auto pkt = r->next()) { … }
// ─────────────────────────────────────────────────────────────────────────────

class PcapReader {
public:
    PcapReader(PcapReader&&) noexcept;
    PcapReader& operator=(PcapReader&&) noexcept;
    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;
    ~PcapReader();

    [[nodiscard]] static Result<PcapReader> open(std::string_view path);

    [[nodiscard]] std::optional<vanhooks::net::RawPacket> next();
    PcapReader& filter(std::string_view bpf_expr);
    [[nodiscard]] uint64_t packets_read() const noexcept { return count_; }

private:
    explicit PcapReader(vanhooks::net::IFileReaderDevice* dev) noexcept : dev_(dev) {}
    vanhooks::net::IFileReaderDevice* dev_   = nullptr;
    uint64_t                 count_ = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  PcapWriter  — write raw/parsed packets to a .pcap file
//
//  auto w = vh::net::PcapWriter::open("out.pcap");
//  w->write(pkt);
// ─────────────────────────────────────────────────────────────────────────────

class PcapWriter {
public:
    PcapWriter(PcapWriter&&) noexcept;
    PcapWriter& operator=(PcapWriter&&) noexcept;
    PcapWriter(const PcapWriter&)            = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;
    ~PcapWriter();

    [[nodiscard]] static Result<PcapWriter> open(std::string_view path);

    Status write(const vanhooks::net::RawPacket& pkt);
    Status write(const vanhooks::net::Packet& pkt);
    void   close();
    [[nodiscard]] uint64_t packets_written() const noexcept { return count_; }

private:
    explicit PcapWriter(vanhooks::net::PcapFileWriterDevice* dev) noexcept : dev_(dev) {}
    vanhooks::net::PcapFileWriterDevice* dev_   = nullptr;
    uint64_t                    count_ = 0;
};

} // namespace vh::net
