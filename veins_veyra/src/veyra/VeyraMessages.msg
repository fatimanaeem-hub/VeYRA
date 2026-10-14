//
// VEYRA - over-the-air messages (802.11p, Veins).
//
// In Phase 3a the cryptography runs in gateway_service.py, so these packets
// carry plain fields plus a byte length padded to the real post-quantum size
// (PROTOCOL.md, "Packet sizes"). The radio therefore sees exactly as many
// bytes as the real protocol would send.
//
// All frames are MAC broadcasts (as in WAVE/WSMP); the RSU each frame is meant
// for is in dstRsu. That keeps the 802.11p behaviour realistic (no MAC
// retries, frames can be lost) and lets the attacker node overhear traffic.
//
// 'mode' and 'truth' are evaluation labels, never used to decide anything
// (see PROTOCOL.md, "mode and truth").
//

import veins.modules.messages.BaseFrame1609_4;

namespace veyra;

// RSU -> everyone, every second: "I am here" (like a WAVE service advertisement).
packet VeyraBeacon extends veins::BaseFrame1609_4
{
    int rsuIndex;
    double rsuX;
    double rsuY;
}

// Vehicle -> RSU: Alg. 2 request, C1 || C2 (~1125 bytes).
packet VeyraHandshakeReq extends veins::BaseFrame1609_4
{
    string vehicle;
    int dstRsu;
    string mode = "normal";
    simtime_t sentAt;
    int attempt;
}

// RSU -> vehicle: Alg. 2 reply, C3 (120 bytes). Only sent when accepted.
packet VeyraHandshakeResp extends veins::BaseFrame1609_4
{
    string vehicle;
    int srcRsu;
    simtime_t reqSentAt;
}

// Vehicle -> RSU: one sensor reading, C_ij || tso || PD_ij (~150 bytes).
packet VeyraReading extends veins::BaseFrame1609_4
{
    string vehicle;
    int dstRsu;
    string mode = "normal";
    string truth = "honest";
    double speedKmh;      // what the vehicle reports
    double trueSpeedKmh;  // what SUMO says (ground truth, for the dataset)
    double x;
    double y;
    double accel;         // m/s^2, from consecutive SUMO speeds
    double heading;       // degrees
    simtime_t sentAt;
    long seq;
}
