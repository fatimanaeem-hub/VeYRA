//
// VEYRA - RSU application. See VeyraRsuApp.h and PROTOCOL.md.
//

#include "veyra/VeyraRsuApp.h"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <sstream>
#include <stdexcept>

#include "veins/base/modules/BaseMobility.h"
#include "veins/base/utils/FindModule.h"

#ifdef _WIN32
#include <direct.h>
#define VEYRA_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define VEYRA_MKDIR(p) mkdir(p, 0755)
#endif

using namespace omnetpp;
using veins::BaseFrame1609_4;

namespace veyra {

Define_Module(VeyraRsuApp);

std::FILE* VeyraRsuApp::csv = nullptr;
std::string VeyraRsuApp::runDir;
int VeyraRsuApp::openRsus = 0;

enum RsuTimerKind {
    BEACON_TIMER = 200,
    TICK_TIMER = 201
};

static std::string num(double v, int prec = 3)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.*f", prec, v);
    return buf;
}

static std::string csvField(const std::string& s)
{
    if (s.find_first_of(",\"\n") == std::string::npos) return s;
    std::string o = "\"";
    for (char c : s) {
        if (c == '"') o += '"';
        o += c;
    }
    return o + "\"";
}

VeyraRsuApp::~VeyraRsuApp()
{
    cancelAndDelete(beaconTimer);
    cancelAndDelete(tickTimer);
    if (csv) { // the run ended in an error, so finish() was not called
        std::fclose(csv);
        csv = nullptr;
    }
}

void VeyraRsuApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        rsuIndex = getParentModule()->getIndex();
        if (rsuIndex == 0) {
            // New run in the same process (e.g. Qtenv "rebuild network" after
            // an error): start from a clean slate.
            if (csv) std::fclose(csv);
            csv = nullptr;
            runDir.clear();
            openRsus = 0;
        }
        host = par("gatewayHost").stdstringValue();
        port = par("gatewayPort");
        if (port <= 0) port = par("firstGatewayPort").intValue() + rsuIndex;
        beaconBytes = par("beaconBytes");
        handshakeRespBytes = par("handshakeRespBytes");
        rsuBeaconInterval = par("rsuBeaconInterval");
        tickInterval = par("tickInterval");
        modelGatewayCpu = par("modelGatewayCpu");

        airDelaySignal = registerSignal("airDelay");
        queueDelaySignal = registerSignal("gatewayQueueDelay");
        e2eDelaySignal = registerSignal("readingEndToEnd");
        handshakeProcSignal = registerSignal("handshakeProc");
        tickProcSignal = registerSignal("tickProc");

        beaconTimer = new cMessage("rsuBeacon", BEACON_TIMER);
        tickTimer = new cMessage("tick", TICK_TIMER);
        busyUntil = SIMTIME_ZERO;
    }
    else if (stage == 1) {
        auto* mob = veins::FindModule<veins::BaseMobility*>::findSubModule(getParentModule());
        if (mob) {
            veins::Coord p = mob->getPositionAt(simTime());
            x = p.x;
            y = p.y;
        }

        std::string err = link.connectTo(host, port);
        if (!err.empty()) {
            throw cRuntimeError("%s cannot reach the gateway service at %s:%d (%s). "
                                "Start it first, in the VEYRA folder: python gateway_service.py --vehicles 20",
                                getParentModule()->getFullName(), host.c_str(), port, err.c_str());
        }
        std::ostringstream hello;
        hello << "{\"type\":\"HELLO\",\"rsu\":\"" << getParentModule()->getFullName()
              << "\",\"sim_time\":" << num(simTime().dbl(), 6) << ",\"protocol_version\":1}";
        std::string reply = rpc(hello.str());
        gatewayName = jsonString(reply, "gateway", "?");
        EV_INFO << getParentModule()->getFullName() << " connected to " << gatewayName << " on port " << port
                << " (FT " << jsonNumber(reply, "FT", -1) << ", crypto " << jsonString(reply, "crypto_backend") << ")" << endl;
        std::printf("[veyra] %s at (%.0f, %.0f) -> %s on %s:%d\n", getParentModule()->getFullName(), x, y,
                    gatewayName.c_str(), host.c_str(), port);
        std::fflush(stdout);

        if (!csv) openCsv(par("resultsDir").stdstringValue());
        openRsus++;
        getParentModule()->getDisplayString().setTagArg("t", 0, gatewayName.c_str());

        scheduleAt(simTime() + uniform(0, rsuBeaconInterval.dbl()), beaconTimer);
        // All RSUs tick at the same whole seconds, like fake_omnet.py.
        scheduleAt(simTime() + tickInterval, tickTimer);
    }
}

void VeyraRsuApp::openCsv(const std::string& resultsDir)
{
    std::time_t now = std::time(nullptr);
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", std::localtime(&now));
    VEYRA_MKDIR(resultsDir.c_str());
    runDir = resultsDir + "/omnet-run-" + stamp;
    VEYRA_MKDIR(runDir.c_str());
    std::string path = runDir + "/messages.csv";
    csv = std::fopen(path.c_str(), "w");
    if (!csv) throw cRuntimeError("cannot write %s", path.c_str());
    std::fprintf(csv,
            "sim_s,rsu,gateway,type,vehicle,mode,truth,sent_s,arrived_s,air_ms,queue_ms,proc_ms,"
            "vehicle_ms,end_to_end_ms,reply,stage,bytes,true_speed_kmh,reported_speed_kmh,x,y,"
            "accel_ms2,heading_deg,seq,detail\n");

    std::FILE* v = std::fopen((runDir + "/vehicles.csv").c_str(), "w");
    if (v) {
        std::fputs("vehicle,node,entered_s,left_s,readings_sent,not_sent_no_session,not_sent_during_handshake,"
                   "handshakes_sent,handshake_retries,sessions,handovers,false_readings_sent,"
                   "handshake_latency_mean_ms,handshake_latency_max_ms,time_to_session_mean_ms,time_to_session_max_ms\n", v);
        std::fclose(v);
    }

    std::FILE* hs = std::fopen((runDir + "/handshakes.csv").c_str(), "w");
    if (hs) {
        std::fputs("vehicle,sent_s,rsu,attempt,bytes,beacon_rssi_dbm,distance_m,answered\n", hs);
        std::fclose(hs);
    }

    // Which configuration produced this folder.
    cConfigurationEx* cfg = getEnvir()->getConfigEx();
    cModule* net = getSimulation()->getSystemModule();
    std::FILE* info = std::fopen((runDir + "/run_info.json").c_str(), "w");
    if (info) {
        std::fprintf(info,
                "{\n  \"config\": \"%s\",\n  \"run\": %d,\n  \"network\": \"%s\",\n  \"rsus\": %d,\n"
                "  \"sim_time_limit\": \"%s\",\n  \"model_gateway_cpu\": %s,\n  \"started\": \"%s\"\n}\n",
                cfg->getActiveConfigName(), cfg->getActiveRunNumber(), net->getNedTypeName(),
                net->hasPar("numRsus") ? (int) net->par("numRsus").intValue() : -1,
                cfg->getConfigValue("sim-time-limit") ? cfg->getConfigValue("sim-time-limit") : "",
                modelGatewayCpu ? "true" : "false", stamp);
        std::fclose(info);
    }
    std::printf("[veyra] OMNeT++ results -> %s\n", runDir.c_str());
    std::fflush(stdout);
}

void VeyraRsuApp::csvRow(const std::string& type, const std::string& vehicle, const std::string& mode, const std::string& truth, simtime_t sentAt, simtime_t arrivedAt, double queueMs, double procMs, double vehicleMs, const std::string& reply, const std::string& stage, long bytes, const VeyraReading* r, const std::string& extra)
{
    if (!csv) return;
    bool timed = sentAt >= SIMTIME_ZERO;
    double airMs = timed ? (arrivedAt - sentAt).dbl() * 1000.0 : 0.0;
    double e2e = timed ? vehicleMs + airMs + queueMs + procMs : 0.0;
    std::string row = num(simTime().dbl(), 6) + "," + getParentModule()->getFullName() + "," + gatewayName + "," + type + "," + csvField(vehicle) + "," + mode + "," + truth + "," + (timed ? num(sentAt.dbl(), 6) : "") + "," + num(arrivedAt.dbl(), 6) + "," + (timed ? num(airMs) : "") + "," + num(queueMs) + "," + num(procMs) + "," + num(vehicleMs) + "," + (timed ? num(e2e) : "") + "," + reply + "," + csvField(stage) + "," + std::to_string(bytes) + ",";
    if (r) {
        row += num(r->getTrueSpeedKmh(), 2) + "," + num(r->getSpeedKmh(), 2) + "," + num(r->getX(), 2) + "," + num(r->getY(), 2) + "," + num(r->getAccel(), 3) + "," + num(r->getHeading(), 1) + "," + std::to_string(r->getSeq());
    }
    else {
        row += ",,,,,,";
    }
    row += "," + csvField(extra) + "\n";
    std::fputs(row.c_str(), csv);
}

std::string VeyraRsuApp::rpc(const std::string& json)
{
    try {
        return link.request(json);
    }
    catch (const std::exception& e) {
        throw cRuntimeError("%s lost the gateway service on port %d: %s. Is gateway_service.py still running?",
                getParentModule()->getFullName(), port, e.what());
    }
}

simtime_t VeyraRsuApp::gatewayStart()
{
    if (!modelGatewayCpu) return simTime();
    return std::max(simTime(), busyUntil);
}

void VeyraRsuApp::gatewayBusy(simtime_t start, double procMs)
{
    if (modelGatewayCpu) busyUntil = start + SimTime(procMs / 1000.0);
}

void VeyraRsuApp::finish()
{
    DemoBaseApplLayer::finish();
    recordScalar("handshakesOk", handshakesOk);
    recordScalar("handshakesRejected", handshakesRejected);
    recordScalar("readingsAccepted", readingsAccepted);
    recordScalar("readingsRejected", readingsRejected);
    recordScalar("txPublished", txPublished);
    recordScalar("txFinalisedSeenHere", txFinalised);
    recordScalar("ticksDeferredGatewayBusy", ticksDeferred);

    if (!link.isOpen()) return;
    openRsus--;
    bool last = openRsus <= 0;
    try {
        if (last) {
            // Keep the service's own summary next to the OMNeT++ results.
            std::string stats = rpc("{\"type\":\"STATS\",\"sim_time\":" + num(simTime().dbl(), 6) + "}");
            if (!runDir.empty()) {
                std::FILE* f = std::fopen((runDir + "/gateway_summary.json").c_str(), "w");
                if (f) {
                    std::fputs(stats.c_str(), f);
                    std::fclose(f);
                }
            }
            if (par("shutdownService").boolValue()) rpc("{\"type\":\"SHUTDOWN\",\"sim_time\":" + num(simTime().dbl(), 6) + "}");
            else rpc("{\"type\":\"BYE\",\"sim_time\":" + num(simTime().dbl(), 6) + "}");
        }
        else {
            rpc("{\"type\":\"BYE\",\"sim_time\":" + num(simTime().dbl(), 6) + "}");
        }
    }
    catch (const cRuntimeError&) {
        // the service may already be gone; results are still on disk
    }
    link.close();
    if (last && csv) {
        std::fclose(csv);
        csv = nullptr;
        std::printf("[veyra] OMNeT++ results written to %s\n", runDir.c_str());
        std::fflush(stdout);
    }
}

void VeyraRsuApp::handleSelfMsg(cMessage* msg)
{
    if (msg == beaconTimer) {
        sendBeacon();
        scheduleAt(simTime() + rsuBeaconInterval, beaconTimer);
    }
    else if (msg == tickTimer) {
        doTick();
        // Ticks stay on the whole-second grid; if the gateway is busy, this
        // tick's work queues behind it (see doTick).
        scheduleAt(simTime() + tickInterval, tickTimer);
    }
    else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void VeyraRsuApp::sendBeacon()
{
    auto* b = new VeyraBeacon("RsuBeacon");
    populateWSM(b);
    b->setByteLength(beaconBytes);
    b->setRsuIndex(rsuIndex);
    b->setRsuX(x);
    b->setRsuY(y);
    sendDown(b);
}

void VeyraRsuApp::onWSM(BaseFrame1609_4* wsm)
{
    if (auto* req = dynamic_cast<VeyraHandshakeReq*>(wsm)) {
        if (req->getDstRsu() == rsuIndex) onHandshakeReq(req);
    }
    else if (auto* r = dynamic_cast<VeyraReading*>(wsm)) {
        if (r->getDstRsu() == rsuIndex) onReading(r);
    }
}

void VeyraRsuApp::onHandshakeReq(VeyraHandshakeReq* req)
{
    simtime_t arrived = simTime();
    simtime_t start = gatewayStart();
    double queueMs = (start - arrived).dbl() * 1000.0;
    emit(airDelaySignal, arrived - req->getSentAt());

    std::ostringstream js;
    js << "{\"type\":\"HANDSHAKE\",\"id\":" << ++requestId << ",\"vehicle\":\"" << jsonEscape(req->getVehicle())
       << "\",\"sim_time\":" << num(start.dbl(), 6) << ",\"mode\":\"" << jsonEscape(req->getMode()) << "\"}";
    std::string reply = rpc(js.str());
    std::string type = jsonString(reply, "type");
    double procMs = jsonNumber(reply, "proc_ms");
    gatewayBusy(start, procMs);
    emit(handshakeProcSignal, procMs / 1000.0);

    if (type == "HANDSHAKE_OK") {
        handshakesOk++;
        // C3 goes back over the air once the gateway has finished (Alg. 2).
        auto* resp = new VeyraHandshakeResp("HandshakeResp");
        populateWSM(resp);
        long down = static_cast<long>(jsonNumber(reply, "bytes_down", handshakeRespBytes));
        resp->setByteLength(down > 0 ? down : handshakeRespBytes);
        resp->setVehicle(req->getVehicle());
        resp->setSrcRsu(rsuIndex);
        resp->setReqSentAt(req->getSentAt());
        simtime_t delay = (modelGatewayCpu ? busyUntil : simTime() + SimTime(procMs / 1000.0)) - simTime();
        sendDelayedDown(resp, delay);
        csvRow("HANDSHAKE", req->getVehicle(), req->getMode(), "", req->getSentAt(), arrived, queueMs, procMs, 0.0,
                "ok", jsonBool(reply, "handover") ? "handover" : "", static_cast<long>(jsonNumber(reply, "bytes_up", req->getByteLength())), nullptr,
                "attempt " + std::to_string(req->getAttempt()));
    }
    else {
        handshakesRejected++;
        std::string stage = jsonString(reply, "stage", jsonString(reply, "reason"));
        EV_WARN << getParentModule()->getFullName() << ": handshake from " << req->getVehicle() << " ["
                << req->getMode() << "] REJECTED at " << stage << endl;
        csvRow("HANDSHAKE", req->getVehicle(), req->getMode(), "", req->getSentAt(), arrived, queueMs, procMs, 0.0,
                "reject", stage, req->getByteLength(), nullptr, jsonString(reply, "reason"));
    }
}

void VeyraRsuApp::onReading(VeyraReading* r)
{
    simtime_t arrived = simTime();
    simtime_t start = gatewayStart();
    double queueMs = (start - arrived).dbl() * 1000.0;
    emit(airDelaySignal, arrived - r->getSentAt());

    std::ostringstream js;
    js << "{\"type\":\"READING\",\"id\":" << ++requestId << ",\"vehicle\":\"" << jsonEscape(r->getVehicle())
       << "\",\"sim_time\":" << num(start.dbl(), 6) << ",\"speed\":" << num(r->getSpeedKmh(), 2) << ",\"x\":"
       << num(r->getX(), 2) << ",\"y\":" << num(r->getY(), 2) << ",\"mode\":\"" << jsonEscape(r->getMode())
       << "\",\"truth\":\"" << jsonEscape(r->getTruth()) << "\"}";
    std::string reply = rpc(js.str());
    std::string type = jsonString(reply, "type");
    double procMs = jsonNumber(reply, "proc_ms");
    double vehicleMs = jsonNumber(reply, "vehicle_ms");
    gatewayBusy(start, procMs);

    if (type == "ACK") {
        readingsAccepted++;
        emit(queueDelaySignal, SimTime(queueMs / 1000.0));
        double e2e = vehicleMs + (arrived - r->getSentAt()).dbl() * 1000.0 + queueMs + procMs;
        emit(e2eDelaySignal, e2e / 1000.0);
        csvRow("READING", r->getVehicle(), r->getMode(), r->getTruth(), r->getSentAt(), arrived, queueMs, procMs,
                vehicleMs, "ack", "buffered", static_cast<long>(jsonNumber(reply, "bytes_up", r->getByteLength())), r, "");
    }
    else {
        readingsRejected++;
        std::string stage = jsonString(reply, "stage", jsonString(reply, "reason"));
        EV_WARN << getParentModule()->getFullName() << ": reading from " << r->getVehicle() << " [" << r->getMode()
                << "] REJECTED at " << stage << endl;
        csvRow("READING", r->getVehicle(), r->getMode(), r->getTruth(), r->getSentAt(), arrived, queueMs, procMs,
                vehicleMs, "reject", stage, r->getByteLength(), r, jsonString(reply, "reason"));
    }
}

void VeyraRsuApp::doTick()
{
    // First come, first served: if the gateway is still busy, the tick starts
    // when it is free, and anything arriving later queues behind the tick.
    simtime_t start = gatewayStart();
    if (start > simTime()) ticksDeferred++;
    std::string reply = rpc("{\"type\":\"TICK\",\"id\":" + std::to_string(++requestId) + ",\"sim_time\":" + num(start.dbl(), 6) + "}");
    double procMs = jsonNumber(reply, "proc_ms");
    gatewayBusy(start, procMs);
    emit(tickProcSignal, procMs / 1000.0);

    std::string published;
    jsonRaw(reply, "published", published);
    int readings = 0;
    if (!published.empty() && published != "null") {
        txPublished++;
        readings = static_cast<int>(jsonNumber(reply, "readings", 0));
    }
    int fin = jsonCount(reply, "latency_s");
    int bad = static_cast<int>(jsonSum(reply, "malicious_readings"));
    txFinalised += fin;
    maliciousFinalised += bad;
    if (readings > 0 || fin > 0) {
        csvRow("TICK", "", "", "", -1, simTime(), (start - simTime()).dbl() * 1000.0, procMs, 0.0, "ok", "", static_cast<long>(jsonNumber(reply, "c_j_bytes", 0)), nullptr,
                std::to_string(readings) + " readings published; " + std::to_string(fin) + " tx finalised (" + std::to_string(bad) + " malicious readings)");
    }
}

} // namespace veyra
