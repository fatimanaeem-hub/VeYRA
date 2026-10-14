//
// VEYRA - vehicle (sensor node) application.
//
// Listens for RSU beacons, picks the nearest RSU it can hear, runs the
// Alg. 2 handshake with it over 802.11p (again on every handover), then
// sends one sensor reading per second to the RSU it has a session with.
// One vehicle (compromisedIndex) starts reporting false speeds after
// attackStart: registered, valid keys, false data.
//

#pragma once

#include <map>
#include <string>
#include <vector>

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veyra/VeyraMessages_m.h"

namespace veyra {

class VeyraVehicleApp : public veins::DemoBaseApplLayer {
public:
    ~VeyraVehicleApp() override;
    void initialize(int stage) override;
    void finish() override;

protected:
    void onWSM(veins::BaseFrame1609_4* wsm) override;
    void handleSelfMsg(omnetpp::cMessage* msg) override;

    void onBeacon(VeyraBeacon* b);
    void onHandshakeResp(VeyraHandshakeResp* r);
    void chooseRsu();
    void sendHandshake();
    void sendReading();
    bool heardRecently(int rsu) const;

    struct RsuSeen {
        omnetpp::simtime_t lastHeard;
        double x = 0;
        double y = 0;
        double rssi = -200; // dBm of the last beacon heard
    };
    struct Attempt { // one handshake request, for handshakes.csv
        omnetpp::simtime_t sentAt;
        int rsu;
        int attempt;
        double rssi;
        double distance;
        bool ok;
    };
    double distanceTo(int rsu) const;

    // parameters
    bool active = false;
    int handshakeBytes = 0;
    int readingBytes = 0;
    omnetpp::simtime_t readingInterval;
    omnetpp::simtime_t handshakeTimeout;
    omnetpp::simtime_t beaconTimeout;
    double handoverMargin = 0;
    bool rssiPolicy = true;
    double minRssi = 0;
    double hysteresis = 0;
    bool compromised = false;
    double fakeSpeedKmh = 0;
    omnetpp::simtime_t attackStart;

    // state
    std::string name;
    omnetpp::simtime_t createdAt;
    std::map<int, RsuSeen> rsus;
    int targetRsu = -1; // RSU we want a session with
    int sessionRsu = -1; // RSU we have a session with
    int lastSessionRsu = -1; // for counting handovers
    bool handshakePending = false;
    omnetpp::simtime_t handshakeSentAt;
    omnetpp::simtime_t handshakeFirstSentAt; // first attempt for the current RSU
    int handshakeAttempt = 0;
    long seq = 0;
    double lastSpeed = -1;
    omnetpp::simtime_t lastSpeedAt;

    omnetpp::cMessage* readingTimer = nullptr;
    omnetpp::cMessage* handshakeTimer = nullptr;

    // statistics
    long readingsSent = 0;
    long readingsNoSession = 0; // not sent: no RSU in range / no session yet
    long readingsDuringHandshake = 0; // not sent: switching RSU
    long handshakesSent = 0;
    long handshakeRetries = 0;
    long sessions = 0;
    long handovers = 0;
    long falseReadingsSent = 0;
    std::vector<Attempt> attempts;
    double handshakeLatencySum = 0;
    double handshakeLatencyMax = 0;
    double timeToSessionSum = 0;
    double timeToSessionMax = 0;
    omnetpp::simsignal_t handshakeLatencySignal;
    omnetpp::simsignal_t timeToSessionSignal;
    omnetpp::simsignal_t readingSentSignal;
};

} // namespace veyra
