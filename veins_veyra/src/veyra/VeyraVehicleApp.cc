//
// VEYRA - vehicle (sensor node) application. See VeyraVehicleApp.h.
//

#include "veyra/VeyraVehicleApp.h"

#include <cmath>

#include "veins/base/phyLayer/PhyToMacControlInfo.h"
#include "veins/modules/mobility/traci/TraCIMobility.h"
#include "veins/modules/phy/DeciderResult80211.h"
#include "veyra/VeyraRsuApp.h"

#include <cstdio>

using namespace omnetpp;
using veins::BaseFrame1609_4;

namespace veyra {

Define_Module(VeyraVehicleApp);

static const double kPi = 3.14159265358979323846;

enum VehicleTimerKind {
    READING_TIMER = 100,
    HANDSHAKE_TIMER = 101
};

void VeyraVehicleApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        int index = getParentModule()->getIndex();
        int maxVehicles = par("maxVehicles");
        active = maxVehicles < 0 || index < maxVehicles;

        handshakeBytes = par("handshakeBytes");
        readingBytes = par("readingBytes");
        readingInterval = par("readingInterval");
        handshakeTimeout = par("handshakeTimeout");
        beaconTimeout = par("beaconTimeout");
        handoverMargin = par("handoverMargin");
        std::string policy = par("handoverPolicy").stdstringValue();
        if (policy != "rssi" && policy != "distance") throw cRuntimeError("handoverPolicy must be \"rssi\" or \"distance\"");
        rssiPolicy = policy == "rssi";
        minRssi = par("minRssi");
        hysteresis = par("handoverHysteresis");
        compromised = (index == par("compromisedIndex").intValue());
        fakeSpeedKmh = par("fakeSpeedKmh");
        attackStart = par("attackStart");

        handshakeLatencySignal = registerSignal("handshakeLatency");
        timeToSessionSignal = registerSignal("timeToSession");
        readingSentSignal = registerSignal("readingSent");

        readingTimer = new cMessage("reading", READING_TIMER);
        handshakeTimer = new cMessage("handshakeTimeout", HANDSHAKE_TIMER);
        createdAt = simTime();
    }
    else if (stage == 1) {
        name = mobility ? mobility->getExternalId() : getParentModule()->getFullName();
        if (!active) return;
        // Readings start somewhere in the first interval so the cars do not
        // all transmit in the same instant.
        scheduleAt(simTime() + uniform(0, readingInterval.dbl()), readingTimer);
        if (compromised) {
            getParentModule()->getDisplayString().setTagArg("i", 1, "red");
            EV_WARN << name << " is the compromised vehicle: false speeds from "
                    << (createdAt + attackStart) << " s" << endl;
        }
    }
}

VeyraVehicleApp::~VeyraVehicleApp()
{
    cancelAndDelete(readingTimer);
    cancelAndDelete(handshakeTimer);
}

void VeyraVehicleApp::finish()
{
    DemoBaseApplLayer::finish();
    if (!active) return;
    recordScalar("readingsSent", readingsSent);
    recordScalar("readingsNotSentNoSession", readingsNoSession);
    recordScalar("readingsNotSentDuringHandshake", readingsDuringHandshake);
    recordScalar("handshakesSent", handshakesSent);
    recordScalar("handshakeRetries", handshakeRetries);
    recordScalar("sessionsEstablished", sessions);
    recordScalar("handovers", handovers);
    recordScalar("falseReadingsSent", falseReadingsSent);

    // One row per car in VEYRA/results/omnet-run-<time>/vehicles.csv
    const std::string& dir = VeyraRsuApp::resultsRunDir();
    if (dir.empty()) return;
    std::FILE* f = std::fopen((dir + "/vehicles.csv").c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s,%s,%.3f,%.3f,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.3f,%.3f,%.3f,%.3f\n", name.c_str(),
            getParentModule()->getFullName(), createdAt.dbl(), simTime().dbl(), readingsSent, readingsNoSession,
            readingsDuringHandshake, handshakesSent, handshakeRetries, sessions, handovers, falseReadingsSent,
            sessions > 0 ? handshakeLatencySum / sessions * 1000.0 : 0.0, handshakeLatencyMax * 1000.0,
            sessions > 0 ? timeToSessionSum / sessions * 1000.0 : 0.0, timeToSessionMax * 1000.0);
    std::fclose(f);

    // One row per handshake request in handshakes.csv
    std::FILE* h = std::fopen((dir + "/handshakes.csv").c_str(), "a");
    if (!h) return;
    for (auto& a : attempts) {
        std::fprintf(h, "%s,%.6f,rsu[%d],%d,%d,%.2f,%.1f,%d\n", name.c_str(), a.sentAt.dbl(), a.rsu, a.attempt,
                handshakeBytes, a.rssi, a.distance, a.ok ? 1 : 0);
    }
    std::fclose(h);
}

bool VeyraVehicleApp::heardRecently(int rsu) const
{
    auto it = rsus.find(rsu);
    return it != rsus.end() && simTime() - it->second.lastHeard <= beaconTimeout;
}

void VeyraVehicleApp::onWSM(BaseFrame1609_4* wsm)
{
    if (!active) return;
    if (auto* b = dynamic_cast<VeyraBeacon*>(wsm)) {
        onBeacon(b);
    }
    else if (auto* r = dynamic_cast<VeyraHandshakeResp*>(wsm)) {
        onHandshakeResp(r);
    }
    // Readings and handshake requests from other cars are ignored.
}

void VeyraVehicleApp::onBeacon(VeyraBeacon* b)
{
    RsuSeen& s = rsus[b->getRsuIndex()];
    s.lastHeard = simTime();
    s.x = b->getRsuX();
    s.y = b->getRsuY();
    auto* res = dynamic_cast<veins::DeciderResult80211*>(veins::PhyToMacControlInfo::getDeciderResult(b));
    if (res) s.rssi = res->getRecvPower_dBm();
    chooseRsu();
}

double VeyraVehicleApp::distanceTo(int rsu) const
{
    auto it = rsus.find(rsu);
    if (it == rsus.end()) return -1;
    double dx = it->second.x - curPosition.x;
    double dy = it->second.y - curPosition.y;
    return std::sqrt(dx * dx + dy * dy);
}

// Which RSU to have a session with.
//
// "rssi" (default): the strongest beacon heard in the last beaconTimeout, but
// only if it is at least minRssi (weaker RSUs can be heard but handshakes
// with them often fail). Switch only when the new RSU is handoverHysteresis dB stronger, or
// the current one is lost or too weak.
//
// "distance": the nearest RSU heard; switch when it is handoverMargin metres
// closer than the current one.
void VeyraVehicleApp::chooseRsu()
{
    if (rssiPolicy) {
        int best = -1;
        double bestRssi = -1e9;
        for (auto& kv : rsus) {
            if (!heardRecently(kv.first)) continue;
            if (kv.second.rssi > bestRssi) {
                bestRssi = kv.second.rssi;
                best = kv.first;
            }
        }
        bool currentOk = targetRsu >= 0 && heardRecently(targetRsu) && rsus[targetRsu].rssi >= minRssi;
        if (best < 0 || bestRssi < minRssi) { // nothing usable in range
            if (!currentOk) targetRsu = -1;
            return;
        }
        if (currentOk && (best == targetRsu || bestRssi < rsus[targetRsu].rssi + hysteresis)) return;
        targetRsu = best;
        if (sessionRsu != targetRsu) {
            handshakeAttempt = 0;
            sendHandshake();
        }
        return;
    }

    int best = -1;
    double bestDist = 1e18;
    double targetDist = 1e18;
    for (auto& kv : rsus) {
        if (!heardRecently(kv.first)) continue;
        double dx = kv.second.x - curPosition.x;
        double dy = kv.second.y - curPosition.y;
        double d = std::sqrt(dx * dx + dy * dy);
        if (kv.first == targetRsu) targetDist = d;
        if (d < bestDist) {
            bestDist = d;
            best = kv.first;
        }
    }

    if (best < 0) { // nothing in range
        targetRsu = -1;
        return;
    }
    bool keep = targetRsu >= 0 && heardRecently(targetRsu) && bestDist > targetDist - handoverMargin;
    if (keep) return;
    if (best == targetRsu) return;

    targetRsu = best;
    if (sessionRsu != targetRsu) {
        handshakeAttempt = 0;
        sendHandshake();
    }
}

void VeyraVehicleApp::sendHandshake()
{
    if (targetRsu < 0) return;
    // Once this request reaches the gateway side, the old session key is
    // replaced, so the old session must not be used any more.
    if (sessionRsu >= 0 && sessionRsu != targetRsu) sessionRsu = -1;
    auto* req = new VeyraHandshakeReq("HandshakeReq");
    populateWSM(req);
    req->setByteLength(handshakeBytes);
    req->setVehicle(name.c_str());
    req->setDstRsu(targetRsu);
    req->setMode("normal");
    req->setSentAt(simTime());
    req->setAttempt(++handshakeAttempt);
    if (handshakeAttempt == 1) handshakeFirstSentAt = simTime();
    attempts.push_back({simTime(), targetRsu, handshakeAttempt, rsus[targetRsu].rssi, distanceTo(targetRsu), false});
    sendDown(req);

    handshakesSent++;
    if (handshakeAttempt > 1) handshakeRetries++;
    handshakePending = true;
    handshakeSentAt = simTime();
    cancelEvent(handshakeTimer);
    scheduleAt(simTime() + handshakeTimeout, handshakeTimer);
}

void VeyraVehicleApp::onHandshakeResp(VeyraHandshakeResp* r)
{
    if (name != r->getVehicle()) return; // someone else's
    if (!handshakePending || r->getSrcRsu() != targetRsu) return; // stale reply
    for (auto& a : attempts)
        if (a.sentAt == r->getReqSentAt() && a.rsu == r->getSrcRsu()) a.ok = true;
    handshakePending = false;
    cancelEvent(handshakeTimer);
    if (lastSessionRsu >= 0 && lastSessionRsu != r->getSrcRsu()) handovers++;
    sessionRsu = r->getSrcRsu();
    lastSessionRsu = sessionRsu;
    sessions++;
    emit(handshakeLatencySignal, simTime() - r->getReqSentAt());
    double lat = (simTime() - r->getReqSentAt()).dbl();
    handshakeLatencySum += lat;
    if (lat > handshakeLatencyMax) handshakeLatencyMax = lat;
    double tts = (simTime() - handshakeFirstSentAt).dbl(); // including retries
    emit(timeToSessionSignal, simTime() - handshakeFirstSentAt);
    timeToSessionSum += tts;
    if (tts > timeToSessionMax) timeToSessionMax = tts;
    EV_INFO << name << ": session with rsu[" << sessionRsu << "] after "
            << (simTime() - r->getReqSentAt()) * 1000 << " ms (attempt " << handshakeAttempt << ")" << endl;
}

void VeyraVehicleApp::handleSelfMsg(cMessage* msg)
{
    if (msg == readingTimer) {
        sendReading();
        scheduleAt(simTime() + readingInterval, readingTimer);
    }
    else if (msg == handshakeTimer) {
        // No reply: the request or the reply was lost on the air, or the
        // gateway refused us. Try again while the RSU is still in range.
        if (handshakePending && targetRsu >= 0 && heardRecently(targetRsu)) {
            sendHandshake();
        }
        else {
            handshakePending = false;
            chooseRsu();
        }
    }
    else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void VeyraVehicleApp::sendReading()
{
    // Re-evaluate coverage once a second even if no beacon arrived.
    if (targetRsu >= 0 && !heardRecently(targetRsu)) chooseRsu();

    // While a handshake is in flight the gateway side may already hold the
    // new session key, so a reading sealed now could fail at the old RSU.
    // Hold readings until the new session is confirmed (break-before-make;
    // sendHandshake() also drops the old session).
    if (handshakePending) {
        readingsDuringHandshake++;
        return;
    }
    if (sessionRsu < 0 || !heardRecently(sessionRsu)) {
        readingsNoSession++;
        return;
    }

    double trueKmh = mobility ? mobility->getSpeed() * 3.6 : 0.0;
    double accel = 0;
    if (lastSpeed >= 0 && simTime() > lastSpeedAt) accel = (trueKmh - lastSpeed) / 3.6 / (simTime() - lastSpeedAt).dbl();
    lastSpeed = trueKmh;
    lastSpeedAt = simTime();

    bool lying = compromised && simTime() >= createdAt + attackStart;
    double reported = lying ? fakeSpeedKmh + uniform(0, 20) : trueKmh;

    auto* m = new VeyraReading("Reading");
    populateWSM(m);
    m->setByteLength(readingBytes);
    m->setVehicle(name.c_str());
    m->setDstRsu(sessionRsu);
    m->setMode(lying ? "compromised" : "normal");
    m->setTruth(lying ? "malicious" : "honest");
    m->setSpeedKmh(reported);
    m->setTrueSpeedKmh(trueKmh);
    m->setX(curPosition.x);
    m->setY(curPosition.y);
    m->setAccel(accel);
    m->setHeading(mobility ? mobility->getHeading().getRad() * 180.0 / kPi : 0.0);
    m->setSentAt(simTime());
    m->setSeq(++seq);
    sendDown(m);

    readingsSent++;
    if (lying) falseReadingsSent++;
    emit(readingSentSignal, 1L);
}

} // namespace veyra
