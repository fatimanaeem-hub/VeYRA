//
// VEYRA - roadside attacker ("eve"). See VeyraAttackerApp.h.
//

#include "veyra/VeyraAttackerApp.h"

#include <cstdio>

using namespace omnetpp;
using veins::BaseFrame1609_4;

namespace veyra {

Define_Module(VeyraAttackerApp);

enum AttackKind {
    ATTACK_INTRUDER_HANDSHAKE = 300,
    ATTACK_INTRUDER_READING,
    ATTACK_TAMPER,
    ATTACK_REPLAY_FRESH,
    ATTACK_REPLAY_OLD
};

static const char* attackName(int kind)
{
    switch (kind) {
    case ATTACK_INTRUDER_HANDSHAKE: return "unregistered handshake";
    case ATTACK_INTRUDER_READING: return "unregistered reading";
    case ATTACK_TAMPER: return "tamper";
    case ATTACK_REPLAY_FRESH: return "replay_fresh";
    case ATTACK_REPLAY_OLD: return "replay_old";
    }
    return "?";
}

VeyraAttackerApp::~VeyraAttackerApp()
{
    delete oldest;
    delete latest;
}

void VeyraAttackerApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        targetRsu = par("targetRsu");
        intruder = par("intruderName").stdstringValue();
        handshakeBytes = par("handshakeBytes");
        readingBytes = par("readingBytes");
        retryInterval = par("retryInterval");
        minOldAge = par("minOldAge");

        struct {
            const char* param;
            int kind;
        } plan[] = {
                {"intruderAt", ATTACK_INTRUDER_HANDSHAKE},
                {"tamperAt", ATTACK_TAMPER},
                {"replayFreshAt", ATTACK_REPLAY_FRESH},
                {"replayOldAt", ATTACK_REPLAY_OLD},
        };
        for (auto& p : plan) {
            double t = par(p.param).doubleValue();
            if (t >= 0) scheduleAt(SimTime(t), new cMessage(attackName(p.kind), p.kind));
        }
    }
}

void VeyraAttackerApp::finish()
{
    DemoBaseApplLayer::finish();
    recordScalar("readingsOverheard", overheard);
    recordScalar("attackFramesSent", attacksSent);
}

void VeyraAttackerApp::onWSM(BaseFrame1609_4* wsm)
{
    auto* r = dynamic_cast<VeyraReading*>(wsm);
    if (!r || r->getDstRsu() != targetRsu) return;
    if (std::string(r->getMode()) != "normal") return; // only genuine traffic
    overheard++;
    if (!oldest) oldest = r->dup();
    delete latest;
    latest = r->dup();
}

void VeyraAttackerApp::handleSelfMsg(cMessage* msg)
{
    int kind = msg->getKind();
    if (kind < ATTACK_INTRUDER_HANDSHAKE || kind > ATTACK_REPLAY_OLD) {
        DemoBaseApplLayer::handleSelfMsg(msg);
        return;
    }
    if (attack(kind)) {
        attacksSent++;
        if (kind == ATTACK_INTRUDER_HANDSHAKE) {
            // Then try to send data without a session.
            msg->setKind(ATTACK_INTRUDER_READING);
            msg->setName(attackName(ATTACK_INTRUDER_READING));
            scheduleAt(simTime() + 1, msg);
            return;
        }
        delete msg;
    }
    else {
        // Nothing suitable captured yet: try again shortly.
        scheduleAt(simTime() + retryInterval, msg);
    }
}

bool VeyraAttackerApp::attack(int kind)
{
    switch (kind) {
    case ATTACK_INTRUDER_HANDSHAKE: {
        auto* req = new VeyraHandshakeReq("HandshakeReq");
        populateWSM(req);
        req->setByteLength(handshakeBytes);
        req->setVehicle(intruder.c_str());
        req->setDstRsu(targetRsu);
        req->setMode("unregistered");
        req->setSentAt(simTime());
        req->setAttempt(1);
        sendDown(req);
        break;
    }
    case ATTACK_INTRUDER_READING: {
        auto* m = new VeyraReading("Reading");
        populateWSM(m);
        m->setByteLength(readingBytes);
        m->setVehicle(intruder.c_str());
        m->setDstRsu(targetRsu);
        m->setMode("normal");
        m->setTruth("malicious");
        m->setSpeedKmh(60);
        m->setTrueSpeedKmh(0);
        m->setX(curPosition.x);
        m->setY(curPosition.y);
        m->setSentAt(simTime());
        sendDown(m);
        break;
    }
    case ATTACK_TAMPER:
        if (!latest) return false;
        sendCopy(latest, "tamper", "Reading(tampered)");
        break;
    case ATTACK_REPLAY_FRESH:
        if (!latest) return false;
        sendCopy(latest, "replay_fresh", "Reading(replayed)");
        break;
    case ATTACK_REPLAY_OLD:
        if (!oldest || simTime() - oldest->getSentAt() < minOldAge) return false;
        sendCopy(oldest, "replay_old", "Reading(old replay)");
        break;
    }
    std::printf("[veyra] t=%.1fs eve: %s -> rsu[%d]\n", simTime().dbl(), attackName(kind), targetRsu);
    std::fflush(stdout);
    return true;
}

void VeyraAttackerApp::sendCopy(const VeyraReading* src, const char* mode, const char* name)
{
    VeyraReading* m = src->dup();
    m->setName(name);
    m->setMode(mode);
    m->setTruth("malicious");
    // Same bytes as the captured frame; a fresh transmission on the air.
    populateWSM(m);
    m->setByteLength(readingBytes);
    m->setSentAt(simTime());
    sendDown(m);
}

} // namespace veyra
