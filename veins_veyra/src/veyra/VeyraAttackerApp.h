//
// VEYRA - roadside attacker ("eve").
//
// A parked radio next to one RSU. It overhears the readings sent to that RSU
// and, at scripted times, transmits attack frames over the same 802.11p
// channel. Its frames compete for the air like any other, and can be lost.
//
//   intruderAt     handshake + reading from an identity never registered
//   tamperAt       a copy of a victim's reading with one bit flipped
//   replayFreshAt  a captured reading re-sent while still inside the window
//   replayOldAt    a reading captured long ago re-sent (outside the window)
//
// The fifth attack, a compromised vehicle sending false values, is in
// VeyraVehicleApp (compromisedIndex).
//

#pragma once

#include <string>

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veyra/VeyraMessages_m.h"

namespace veyra {

class VeyraAttackerApp : public veins::DemoBaseApplLayer {
public:
    ~VeyraAttackerApp() override;
    void initialize(int stage) override;
    void finish() override;

protected:
    void onWSM(veins::BaseFrame1609_4* wsm) override;
    void handleSelfMsg(omnetpp::cMessage* msg) override;
    bool attack(int kind);
    void sendCopy(const VeyraReading* src, const char* mode, const char* name);

    int targetRsu = 0;
    std::string intruder;
    int handshakeBytes = 0;
    int readingBytes = 0;
    omnetpp::simtime_t retryInterval;
    omnetpp::simtime_t minOldAge;

    VeyraReading* oldest = nullptr; // first reading overheard
    VeyraReading* latest = nullptr; // most recent reading overheard
    long overheard = 0;
    long attacksSent = 0;
};

} // namespace veyra
