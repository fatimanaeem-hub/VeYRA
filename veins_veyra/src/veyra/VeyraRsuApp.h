//
// VEYRA - RSU application: the bridge between the 802.11p radio inside
// OMNeT++ and the gateway service (gateway_service.py) outside it.
//
//   vehicle --802.11p--> rsu[j] --local TCP--> GW-j in gateway_service.py
//
// * Beacons every second so vehicles know it is there.
// * Handshake request arrives over the air -> HANDSHAKE to the gateway ->
//   if accepted, C3 goes back over the air after the gateway's real
//   processing time (proc_ms).
// * Reading arrives over the air -> READING to the gateway (Alg. 3).
// * Every second: TICK (aggregate, seal, publish, finalise).
//
// The gateway is one CPU: with modelGatewayCpu, work that arrives while it
// is still busy waits its turn (queue_ms), so post-quantum processing cost
// turns into simulated delay.
//

#pragma once

#include <string>

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veyra/GatewayLink.h"
#include "veyra/VeyraMessages_m.h"

namespace veyra {

class VeyraRsuApp : public veins::DemoBaseApplLayer {
public:
    // Folder of the current run (VEYRA/results/omnet-run-<time>), "" before
    // the first RSU initialises. Vehicles write vehicles.csv there.
    static const std::string& resultsRunDir()
    {
        return runDir;
    }

    ~VeyraRsuApp() override;
    void initialize(int stage) override;
    void finish() override;

protected:
    void onWSM(veins::BaseFrame1609_4* wsm) override;
    void handleSelfMsg(omnetpp::cMessage* msg) override;

    void onHandshakeReq(VeyraHandshakeReq* req);
    void onReading(VeyraReading* r);
    void doTick();
    void sendBeacon();

    std::string rpc(const std::string& json);
    omnetpp::simtime_t gatewayStart(); // when the gateway CPU can start new work
    void gatewayBusy(omnetpp::simtime_t start, double procMs);

    // CSV with one row per message the RSU handled (shared by all RSUs).
    void openCsv(const std::string& resultsDir);
    void csvRow(const std::string& type, const std::string& vehicle, const std::string& mode, const std::string& truth, omnetpp::simtime_t sentAt, omnetpp::simtime_t arrivedAt, double queueMs, double procMs, double vehicleMs, const std::string& reply, const std::string& stage, long bytes, const VeyraReading* r, const std::string& extra);

    // parameters
    int rsuIndex = 0;
    std::string host;
    int port = 0;
    int beaconBytes = 0;
    int handshakeRespBytes = 0;
    omnetpp::simtime_t rsuBeaconInterval;
    omnetpp::simtime_t tickInterval;
    bool modelGatewayCpu = true;

    // state
    GatewayLink link;
    std::string gatewayName;
    long requestId = 0;
    omnetpp::simtime_t busyUntil;
    omnetpp::cMessage* beaconTimer = nullptr;
    omnetpp::cMessage* tickTimer = nullptr;
    double x = 0;
    double y = 0;

    // statistics
    long handshakesOk = 0;
    long handshakesRejected = 0;
    long readingsAccepted = 0;
    long readingsRejected = 0;
    long txPublished = 0;
    long txFinalised = 0;
    long maliciousFinalised = 0;
    long ticksDeferred = 0;
    omnetpp::simsignal_t airDelaySignal;
    omnetpp::simsignal_t queueDelaySignal;
    omnetpp::simsignal_t e2eDelaySignal;
    omnetpp::simsignal_t handshakeProcSignal;
    omnetpp::simsignal_t tickProcSignal;

    // shared across all RSUs of a run
    static std::FILE* csv;
    static std::string runDir;
    static int openRsus;
};

} // namespace veyra
